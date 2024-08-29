use color_eyre::eyre::eyre;
use objc2_foundation::ns_string;
use objc2_service_management::SMAppService;

pub unsafe fn cmd_daemon_register() -> color_eyre::Result<()> {
    let name = ns_string!("launchd.plist");
    let service = SMAppService::agentServiceWithPlistName(name);
    
    let _ = service.unregisterAndReturnError();
    match service.registerAndReturnError() {
        Ok(_) => Ok(println!("Service registered successfully")),
        Err(e) => Err(eyre!(e.localizedDescription().to_string())),
    }
}
