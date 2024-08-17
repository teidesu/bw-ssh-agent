use std::sync::Arc;

use tokio::{fs, net::UnixListener, sync::Mutex};

use crate::{
    agent::agent::Agent,
    cmd::utils::check_running,
    constants::{get_pid_path, get_socket_path},
    database::Database,
    handler,
    keychain::Keychain,
};

pub async fn cmd_daemon(database: Arc<Mutex<Database>>) -> color_eyre::Result<()> {
    let pipe = get_socket_path()?;
    let pid_file = get_pid_path()?;

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
        .run(Box::new(handler::Handler::new(database, keychain)))
        .await?;

    Ok(())
}
