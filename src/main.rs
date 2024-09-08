use std::fs;

use clap::{command, Parser, Subcommand};
use cmd::{
    daemon_register::cmd_daemon_register, daemon_run::cmd_daemon_run, list::cmd_list,
    login::cmd_login, sync::cmd_sync,
};
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

#[derive(Clone, Debug, Subcommand)]
pub enum DaemonCommands {
    /// Runs the daemon in this session
    Run,
    /// Registers the daemon as a MacOS service
    Register,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Daemon controls
    Daemon {
        #[command(subcommand)]
        subcommand: DaemonCommands,
    },
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
        Commands::Daemon { subcommand } => match subcommand {
            DaemonCommands::Run => cmd_daemon_run(database).await?,
            DaemonCommands::Register => unsafe {
                cmd_daemon_register()?;
            },
        },
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
