use core::str;
use std::str::FromStr;

use crate::{
    bitwarden::{
        config::{bw_get_config, ConfigResponseModel},
        constants::get_bw_http_client,
        crypto::bw_decrypt_encstr,
        sync::{bw_sync, CipherDetailsResponseModel, CipherType},
    },
    database::{AuthDto, Database, IdentityDto},
    keychain::Keychain,
};

const BW_EXPOSE_FIELD: &str = "desu.tei.bw-ssh-agent:expose";

fn extract_key_from_cipher<'a>(
    cipher: &'a CipherDetailsResponseModel,
    symmetric_key: &[u8],
) -> color_eyre::Result<Option<(String, String, &'a String)>> {
    let Some(ref fields) = cipher.fields else {
        return Ok(None);
    };

    let cipher_key = if let Some(ref encrypted) = cipher.key {
        bw_decrypt_encstr(symmetric_key, encrypted)?
    } else {
        symmetric_key.to_vec()
    };

    let mut expose = false;
    for field in fields {
        if let Some(field_name) = &field.name {
            if bw_decrypt_encstr(&cipher_key, &field_name)? != BW_EXPOSE_FIELD.as_bytes() {
                continue;
            }
        } else {
            continue;
        }

        let value = if let Some(value) = &field.value {
            bw_decrypt_encstr(&cipher_key, value)?
        } else {
            continue;
        };

        if value == b"1" || value == b"true" {
            expose = true;
        }
    }

    if !expose {
        return Ok(None);
    }

    let Some(ref encrypted_private_key) = cipher.notes else {
        return Ok(None);
    };

    let private_key = String::from_utf8(bw_decrypt_encstr(&cipher_key, encrypted_private_key)?)?;
    let name = String::from_utf8(bw_decrypt_encstr(
        &cipher_key,
        &cipher.name.as_ref().unwrap(),
    )?)?;

    Ok(Some((name, private_key, encrypted_private_key)))
}

pub async fn sync_keys(
    database: &Database,
    client: &reqwest::Client,
    config: &ConfigResponseModel,
    symmetric_key: &[u8],
    auth: &AuthDto,
) -> color_eyre::Result<()> {
    println!("Fetching from {}", config.environment.vault);
    let sync_result = bw_sync(client, config, &auth.access_token).await?;

    let secure_notes = sync_result
        .ciphers
        .iter()
        .filter(|c| {
            c.type_field == CipherType::SecureNote
                && c.secure_note.is_some()
                && c.deleted_date.is_none()
        })
        .collect::<Vec<_>>();

    let mut found = 0;
    let mut changed = 0;
    let identities = database.get_identities()?;
    let mut new_identities = vec![];

    for cipher in secure_notes {
        let (name, private_key, encrypted_private_key) = {
            match extract_key_from_cipher(&cipher, symmetric_key) {
                Ok(Some(keys)) => keys,
                Ok(None) => continue,
                Err(e) => {
                    println!("Error extracting key from cipher id {}: {:?}", cipher.id, e);
                    continue;
                }
            }
        };

        let ssh_key = match ssh_key::PrivateKey::from_str(&private_key) {
            Ok(key) => key,
            Err(e) => {
                println!("Error parsing SSH key from the note named \"{}\": {}", name, e);
                continue;
            }
        };
        let pub_key = ssh_key.public_key().to_bytes()?;

        found += 1;

        let old = identities.iter().find(|i| i.id == cipher.id);
        let mut should_update = false;

        if let Some(old) = old {
            if old.name != name || old.public_key != pub_key {
                should_update = true;
            }
        } else {
            should_update = true;
        }

        if should_update {
            println!("Updating {}", name);

            database.add_identity(&IdentityDto {
                id: cipher.id.clone(),
                name,
                public_key: pub_key.clone(),
                private_key: encrypted_private_key.clone(),
                intermediate_key: cipher.key.clone(),
            })?;
            changed += 1;
        }

        new_identities.push(pub_key);
    }

    // delete any identities that are no longer in bitwarden
    for old in identities {
        if !new_identities.contains(&old.public_key) {
            println!("Deleting {}", old.name);
            database.delete_identity(&old.id)?;
            changed += 1;
        }
    }

    if found == 0 {
        println!(
            "No keys to sync. Make sure to put \"{}\" = 1 in a Secure Note.",
            BW_EXPOSE_FIELD
        );
        return Ok(());
    }

    println!("Updated {} keys", changed);

    Ok(())
}

pub async fn cmd_sync(database: Database) -> color_eyre::Result<()> {
    let Some(auth) = database.get_auth()? else {
        println!("Not logged in. Please run `bw-ssh-agent login` first.");
        return Ok(());
    };

    let client = get_bw_http_client();
    let config = bw_get_config(&client, &auth.vault_url).await?;

    // todo: refresh token if expired

    let mut keychain = Keychain::start();
    keychain.ensure_keypair().await?;
    let symmetric_key = keychain.decrypt_data(auth.symmetric_key.to_vec()).await?;

    sync_keys(&database, &client, &config, &symmetric_key, &auth).await?;

    Ok(())
}
