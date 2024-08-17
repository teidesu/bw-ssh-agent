use std::sync::Arc;

use tokio::{fs, net::UnixListener};

use crate::{
    agent::agent::Agent,
    cmd::utils::check_running,
    constants::{PID_PATH, SOCKET_PATH},
    database::Database,
    handler,
    keychain::Keychain,
};

pub async fn cmd_daemon(database: Database) -> color_eyre::Result<()> {
    let pipe = &*SOCKET_PATH;
    let pid_file = &*PID_PATH;

    if check_running().await? {
        println!("bw-ssh-agent is already running!");
        return Ok(());
    }

    if fs::metadata(&pipe).await.is_ok() {
        fs::remove_file(&pipe)
            .await
            .expect("error cleaning up socket");
    }

    fs::write(&pid_file, format!("{}", std::process::id())).await?;

    println!(
        "bw-ssh-agent daemon started on {}",
        pipe.clone().to_string_lossy()
    );

    let listener = UnixListener::bind(pipe)?;
    let mut keychain = Keychain::start();

    keychain.ensure_keypair().await?;

    Agent::new(listener)
        .run(Arc::new(handler::Handler::new(database, keychain)))
        .await?;

    Ok(())
}
