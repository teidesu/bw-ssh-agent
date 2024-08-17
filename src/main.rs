// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{fs, sync::Arc};

use clap::{command, Parser, Subcommand};
use cmd::{daemon::cmd_daemon, list::cmd_list, login::cmd_login, sync::cmd_sync};
use constants::get_data_dir;
use database::Database;
use tokio::sync::Mutex;

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

    let data_dir = get_data_dir()?;
    fs::create_dir_all(&data_dir)?;

    let database = Arc::new(Mutex::new(Database::open()?));

    match cli.command {
        Commands::Daemon => {
            cmd_daemon(database.clone()).await?;
        }
        Commands::Login { .. } => {
            cmd_login(database.clone(), cli.command).await?;
        }
        Commands::Sync => {
            cmd_sync(database.clone()).await?;
        }
        Commands::List => {
            cmd_list(database.clone()).await?;
        }
    };

    Ok(())
}
