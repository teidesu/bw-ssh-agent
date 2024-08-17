use std::{str::FromStr, sync::Arc};

use tokio::sync::Mutex;

use crate::{
    bitwarden::{
        config::{bw_get_config, BwConfig},
        crypto::decrypt_with_master_key,
        sync::{bw_sync, CipherType},
    },
    database::{AuthDto, Database, IdentityDto},
    keychain::Keychain,
};

const BW_EXPOSE_FIELD: &str = "desu.tei.bw-ssh-agent:expose";

pub async fn do_sync(
    database: Arc<Mutex<Database>>,
    client: &reqwest::Client,
    config: &BwConfig,
    symmetric_key: &[u8],
    auth: &AuthDto,
) -> color_eyre::Result<()> {
    let database = database.lock().await;

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
        let Some(ref fields) = cipher.fields else {
            continue;
        };

        let mut expose = false;
        for field in fields {
            let name = String::from_utf8(decrypt_with_master_key(&symmetric_key, &field.name)?)?;
            if name != BW_EXPOSE_FIELD {
                continue;
            }

            let value = String::from_utf8(decrypt_with_master_key(&symmetric_key, &field.value)?)?;

            if value == "1" || value == "true" {
                expose = true;
            }
        }

        if !expose {
            continue;
        }

        let name = String::from_utf8(decrypt_with_master_key(&symmetric_key, &cipher.name)?)?;
        let Some(ref encrypted_private_key) = cipher.notes else {
            continue;
        };
        let private_key = String::from_utf8(decrypt_with_master_key(
            &symmetric_key,
            &encrypted_private_key,
        )?)?;

        let ssh_key = ssh_key::PrivateKey::from_str(&private_key)?;
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

pub async fn cmd_sync(database: Arc<Mutex<Database>>) -> color_eyre::Result<()> {
    let auth = {
        let database = database.lock().await;
        let Some(auth) = database.get_auth()? else {
            println!("Not logged in. Please run `bw-ssh-agent login` first.");
            return Ok(());
        };
        auth
    };

    let client = reqwest::Client::new();
    let config = bw_get_config(&client, &auth.vault_url).await?;

    // todo: refresh token if expired

    let mut keychain = Keychain::start();
    keychain.ensure_keypair().await?;
    let symmetric_key = keychain.decrypt_data(auth.symmetric_key.to_vec()).await?;

    do_sync(database, &client, &config, &symmetric_key, &auth).await?;

    Ok(())
}
