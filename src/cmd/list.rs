use std::sync::Arc;

use tokio::sync::Mutex;

use crate::database::Database;

pub async fn cmd_list(database: Arc<Mutex<Database>>) -> color_eyre::Result<()> {
    let database = database.lock().await;

    let identities = database.get_identities()?;

    println!("{} identities:", identities.len());
    for identity in identities {
        let pub_key = ssh_key::PublicKey::from_bytes(&identity.public_key)?;
        println!("{}: {}", identity.name, pub_key.to_openssh()?);
    }

    Ok(())
}
