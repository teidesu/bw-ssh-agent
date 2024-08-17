use sysinfo::{Pid, ProcessStatus};
use tokio::fs;

use crate::constants::get_pid_path;

pub async fn check_running() -> color_eyre::Result<bool> {
    let pid_file = get_pid_path()?;

    if fs::metadata(&pid_file).await.is_ok() {
        // check if process is running
        let pid = fs::read_to_string(&pid_file).await?;
        let pid: usize = pid.trim().parse()?;

        let mut system = sysinfo::System::new();
        system.refresh_all();

        if let Some(process) = system.process(Pid::from(pid)) {
            return Ok(process.status() == ProcessStatus::Run);
        }
    }

    Ok(false)
}
