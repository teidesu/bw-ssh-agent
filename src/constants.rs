use std::path::PathBuf;

use color_eyre::eyre::eyre;

pub fn get_data_dir() -> color_eyre::Result<PathBuf> {
    let dirs = directories::BaseDirs::new().ok_or(eyre!("Could not get base directories"))?;

    Ok(dirs.config_dir().join("bw-ssh-agent"))
}

pub fn get_socket_path() -> color_eyre::Result<PathBuf> {
    get_data_dir().map(|d| d.join("agent.sock"))
}

pub fn get_pid_path() -> color_eyre::Result<PathBuf> {
    get_data_dir().map(|d| d.join("agent.pid"))
}

pub fn get_database_path() -> color_eyre::Result<PathBuf> {
    get_data_dir().map(|d| d.join("data.sqlite"))
}
