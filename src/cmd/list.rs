use crate::database::Database;

pub fn cmd_list(database: Database) -> color_eyre::Result<()> {
    let identities = database.get_identities()?;

    println!("{} identities:", identities.len());
    for identity in identities {
        let pub_key = ssh_key::PublicKey::from_bytes(&identity.public_key)?;
        println!("{}: {}", identity.name, pub_key.to_openssh()?);
    }

    Ok(())
}
