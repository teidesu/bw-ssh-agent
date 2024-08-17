use std::{path::PathBuf, sync::LazyLock};

pub static DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let dirs = directories::BaseDirs::new().expect("Could not get base directories");
    dirs.config_dir().join("bw-ssh-agent")
});

pub static SOCKET_PATH: LazyLock<PathBuf> = LazyLock::new(|| DATA_DIR.join("agent.sock"));

pub static PID_PATH: LazyLock<PathBuf> = LazyLock::new(|| DATA_DIR.join("agent.pid"));

pub static DATABASE_PATH: LazyLock<PathBuf> = LazyLock::new(|| DATA_DIR.join("data.sqlite"));
