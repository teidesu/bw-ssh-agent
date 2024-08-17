use std::fs;

use clap::{command, Parser, Subcommand};
use cmd::{daemon::cmd_daemon, list::cmd_list, login::cmd_login, sync::cmd_sync};
use constants::DATA_DIR;
use database::Database;

pub mod agent;
pub mod bitwarden;
pub mod cmd;
pub mod constants;
pub mod database;
pub mod handler;
pub mod keychain;
pub mod utils;

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Launches the daemon
    Daemon,
    /// Logs into the account
    Login {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        vault_url: Option<String>,
    },
    /// Syncs the private keys from the vault into the agent
    Sync,
    /// Lists the identities in the agent database
    List,
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    fs::create_dir_all(&*DATA_DIR)?;

    let database = Database::open()?;

    match cli.command {
        Commands::Daemon => {
            cmd_daemon(database).await?;
        }
        Commands::Login { .. } => {
            cmd_login(database, cli.command).await?;
        }
        Commands::Sync => {
            cmd_sync(database).await?;
        }
        Commands::List => {
            cmd_list(database)?;
        }
    };

    Ok(())
}
