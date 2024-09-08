use color_eyre::eyre::eyre;
use objc2_foundation::ns_string;
use objc2_service_management::SMAppService;

use crate::constants::SOCKET_PATH;

pub unsafe fn cmd_daemon_register() -> color_eyre::Result<()> {
    let name = ns_string!("launchd.plist");
    let service = SMAppService::agentServiceWithPlistName(name);

    let _ = service.unregisterAndReturnError();
    match service.registerAndReturnError() {
        Ok(_) => {
            println!("Service registered successfully");
            println!("To get started, add the following to your ~/.ssh/config file:");
            println!(
                "Host *\n  IdentityAgent \"{}\"",
                &*SOCKET_PATH.clone().to_string_lossy()
            );
            Ok(())
        }
        Err(e) => Err(eyre!(e.localizedDescription().to_string())),
    }
}
