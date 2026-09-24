//! Running as a Windows service.
//!
//! `opcua-audit-gateway --config <dir>\config.toml service install`
//! registers an auto-start service that runs
//! `… --config <absolute path> --log-dir <config dir>\logs service run`
//! under its own virtual account (`NT SERVICE\OpcUaAuditGateway`), and
//! restricts the config, data, certificate and log directories to that
//! account, SYSTEM and administrators.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::Context;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const NAME: &str = "OpcUaAuditGateway";
/// The virtual account the service runs as; Windows creates it with the
/// service.
const ACCOUNT: &str = "NT SERVICE\\OpcUaAuditGateway";
const DISPLAY_NAME: &str = "OPC UA Audit Gateway";

static CONFIG: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Hands the process to the Windows service control manager. Returns when
/// the service stops.
pub fn dispatch(config: PathBuf) -> anyhow::Result<()> {
    let _ = CONFIG.set(config);
    service_dispatcher::start(NAME, ffi_service_main)
        .context("not started by the service manager (use `service install`)")?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service failed: {e:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = Mutex::new(Some(stop_tx));
    let status = service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = stop_tx.lock().ok().and_then(|mut t| t.take()) {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let set = |state: ServiceState, accept: ServiceControlAccept, code: u32| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(15),
            process_id: None,
        })
    };
    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    )?;
    let config = CONFIG.get().cloned().unwrap_or_default();
    let result = tokio::runtime::Runtime::new()?.block_on(crate::run(&config, async move {
        let _ = stop_rx.await;
    }));
    if let Err(e) = &result {
        tracing::error!("gateway stopped with an error: {e:#}");
    }
    set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        u32::from(result.is_err()),
    )?;
    result.map(|_| ())
}

/// Registers the service and locks down `dirs` (config, data, certificates,
/// logs) so only the service, SYSTEM and administrators can use them.
pub fn install(config: &Path, log_dir: &Path, dirs: &[PathBuf]) -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening the service manager (run as administrator)")?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![
            "--config".into(),
            config.into(),
            "--log-dir".into(),
            log_dir.into(),
            "service".into(),
            "run".into(),
        ],
        dependencies: Vec::new(),
        account_name: Some(ACCOUNT.into()),
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::DELETE)
        .context("creating the service")?;
    service.set_description("Transparent OPC UA gateway with an audit trail of every write")?;
    for dir in dirs {
        if let Err(e) = restrict(dir) {
            let _ = service.delete();
            return Err(e.context("the service was not installed"));
        }
    }
    Ok(())
}

/// Replaces the permissions of `dir` and everything in it: full control for
/// SYSTEM and administrators (who also own it), modify for the service, and
/// nothing for other users. Without this, the default permissions of a
/// directory such as `C:\gateway` let any local user change the config, the
/// users or the executable, or read the private key.
fn restrict(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    // SIDs, so this works whatever the language of Windows.
    const SYSTEM: &str = "*S-1-5-18";
    const ADMINISTRATORS: &str = "*S-1-5-32-544";
    let service = format!("{ACCOUNT}:(OI)(CI)M");
    let system = format!("{SYSTEM}:(OI)(CI)F");
    let administrators = format!("{ADMINISTRATORS}:(OI)(CI)F");
    let children = dir.join("*");
    let steps: [&[&std::ffi::OsStr]; 3] = [
        &[
            dir.as_os_str(),
            "/setowner".as_ref(),
            ADMINISTRATORS.as_ref(),
            "/T".as_ref(),
            "/L".as_ref(),
            "/Q".as_ref(),
        ],
        &[
            dir.as_os_str(),
            "/inheritance:r".as_ref(),
            "/grant:r".as_ref(),
            system.as_ref(),
            administrators.as_ref(),
            service.as_ref(),
            "/Q".as_ref(),
        ],
        // Drop anything set explicitly on the contents; they inherit the
        // permissions above.
        &[
            children.as_os_str(),
            "/reset".as_ref(),
            "/T".as_ref(),
            "/L".as_ref(),
            "/Q".as_ref(),
        ],
    ];
    for (i, args) in steps.iter().enumerate() {
        let output = std::process::Command::new("icacls")
            .args(*args)
            .output()
            .context("running icacls")?;
        // An empty directory has no contents to reset.
        let empty = i == 2
            && std::fs::read_dir(dir)
                .map(|mut d| d.next().is_none())
                .unwrap_or(false);
        if !output.status.success() && !empty {
            anyhow::bail!(
                "setting the permissions of {}: {}{}",
                dir.display(),
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run as administrator)")?;
    let service = manager
        .open_service(
            NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("opening the service")?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
    }
    service.delete().context("deleting the service")?;
    Ok(())
}
