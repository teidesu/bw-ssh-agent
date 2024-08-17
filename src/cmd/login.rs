use color_eyre::eyre::eyre;
use rustyline::DefaultEditor;

use crate::{
    bitwarden::{
        auth::{bw_login, bw_prelogin},
        config::bw_get_config,
        constants::{get_bw_http_client, BW_DEFAULT_VAULT_URL},
        crypto::{decrypt_with_master_key, hkdf_expand_key, make_master_key, make_master_key_hash},
    },
    cmd::sync::sync_keys,
    database::{AuthDto, Database},
    keychain::Keychain,
    utils::get_current_unix_timestamp,
    Commands,
};

pub async fn cmd_login(database: Database, command: Commands) -> color_eyre::Result<()> {
    let Commands::Login {
        email,
        password,
        vault_url,
    } = command
    else {
        unreachable!()
    };

    let mut rl = DefaultEditor::new()?;

    let email = email
        .unwrap_or_else(|| rl.readline("Email » ").unwrap())
        .trim()
        .to_ascii_lowercase();

    let password = password.unwrap_or_else(|| rl.readline("Password » ").unwrap());

    let vault_url = vault_url.unwrap_or(String::from(BW_DEFAULT_VAULT_URL));
    let client = get_bw_http_client();

    let config = bw_get_config(&client, &vault_url).await?;
    if let Some(ref server) = config.server {
        println!(
            "Server is {} v{}",
            server.name.clone(),
            server.version.clone().unwrap_or(config.version.clone())
        );
    }

    let prelogin_result = bw_prelogin(&client, &config, &email).await?;

    if prelogin_result.kdf != 0 {
        return Err(eyre!("KDF method {} is not supported", prelogin_result.kdf));
    }

    println!("Hashing password...");
    let mut master_key = make_master_key(&password, &email, prelogin_result.kdf_iterations)?;
    let master_key_hash = make_master_key_hash(&master_key, &password)?;

    println!("Logging in...");
    let login_result = bw_login(&client, &config, &email, &master_key_hash).await?;

    if master_key.len() == 32 {
        master_key = hkdf_expand_key(&master_key)?.to_vec();
    }

    let master_key: [u8; 64] = master_key
        .try_into()
        .map_err(|_| eyre!("Invalid master key length"))?;

    let symmetric_key = decrypt_with_master_key(&master_key, &login_result.key)?;

    let mut keychain = Keychain::start();
    keychain.ensure_keypair().await?;

    let encrypted_master_key = keychain.encrypt_data(master_key.to_vec()).await?;
    let encrypted_symmetric_key = keychain.encrypt_data(symmetric_key.to_vec()).await?;

    let auth = AuthDto {
        vault_url: config.environment.vault.clone(),
        access_token: login_result.access_token,
        refresh_token: login_result.refresh_token,
        expires_at: get_current_unix_timestamp() + login_result.expires_in,
        master_key: encrypted_master_key,
        symmetric_key: encrypted_symmetric_key,
    };

    database.set_auth(&auth)?;

    println!("Logged in successfully!");

    println!("Syncing keys...");
    sync_keys(&database, &client, &config, &symmetric_key, &auth).await?;

    Ok(())
}
