//! Service creation, configuration, and control operations.

use std::mem;
use std::path::PathBuf;

use windows::Win32::Foundation::ERROR_SERVICE_EXISTS;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CreateServiceW, OpenServiceW,
    SC_ACTION, SC_ACTION_RESTART,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_DESCRIPTION_W,
    SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_FAILURE_ACTIONSW,
    SERVICE_CONFIG_SERVICE_SID_INFO,
    SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
    SERVICE_FAILURE_ACTIONSW, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_WIN32_OWN_PROCESS,
    StartServiceW,
};
use windows::core::{PCWSTR, PWSTR};

use super::{InstallerBuilder, InstallerError};
use super::handles::{ScManagerHandle, ServiceHandle};
use super::utils::{str_to_wide, MAX_PATH, MAX_SERVICE_NAME, MAX_DESCRIPTION, MAX_DEPENDENCIES};

/// Create the Windows service with comprehensive configuration
pub(super) fn create_service(
    sc_manager: &ScManagerHandle,
    builder: &InstallerBuilder,
) -> Result<ServiceHandle, InstallerError> {
    // Prepare wide string buffers
    let mut service_name_buf: [u16; MAX_SERVICE_NAME] = [0; MAX_SERVICE_NAME];
    let mut display_name_buf: [u16; MAX_SERVICE_NAME] = [0; MAX_SERVICE_NAME];
    let mut binary_path_buf: [u16; MAX_PATH] = [0; MAX_PATH];
    let mut dependencies_buf: [u16; MAX_DEPENDENCIES] = [0; MAX_DEPENDENCIES];

    // Convert strings to wide
    str_to_wide(&builder.label, &mut service_name_buf)?;
    str_to_wide(&builder.description, &mut display_name_buf)?;

    // Build binary path with arguments
    let binary_path = if builder.args.is_empty() {
        builder.program.to_string_lossy().to_string()
    } else {
        format!(
            "\"{}\" {}",
            builder.program.display(),
            builder.args.join(" ")
        )
    };
    str_to_wide(&binary_path, &mut binary_path_buf)?;

    // Build dependencies string
    if builder.wants_network {
        str_to_wide("Tcpip\0Afd\0", &mut dependencies_buf)?;
    }

    // Determine start type based on auto_start preference
    let start_type = if builder.auto_start {
        SERVICE_AUTO_START
    } else {
        SERVICE_DEMAND_START
    };

    // Create the service
    let service_handle = unsafe {
        CreateServiceW(
            sc_manager.handle(),
            PCWSTR::from_raw(service_name_buf.as_ptr()),
            PCWSTR::from_raw(display_name_buf.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            start_type,
            SERVICE_ERROR_IGNORE,
            PCWSTR::from_raw(binary_path_buf.as_ptr()),
            PCWSTR::null(),
            None,
            if builder.wants_network {
                PCWSTR::from_raw(dependencies_buf.as_ptr())
            } else {
                PCWSTR::null()
            },
            PCWSTR::null(),
            PCWSTR::null(),
        )
    };

    if service_handle.is_invalid() {
        let error = unsafe { windows::Win32::Foundation::GetLastError() };
        if error == ERROR_SERVICE_EXISTS {
            return Err(InstallerError::System(format!(
                "Service '{}' already exists",
                builder.label
            )));
        } else {
            return Err(InstallerError::System(format!(
                "Failed to create service: {}",
                error.0
            )));
        }
    }

    Ok(ServiceHandle(service_handle))
}

/// Configure service description
pub(super) fn configure_service_description(
    service: &ServiceHandle,
    description: &str,
) -> Result<(), InstallerError> {
    let mut desc_buf: [u16; MAX_DESCRIPTION] = [0; MAX_DESCRIPTION];
    str_to_wide(description, &mut desc_buf)?;

    let service_desc = SERVICE_CONFIG_DESCRIPTION_W {
        lpDescription: PWSTR::from_raw(desc_buf.as_mut_ptr()),
    };

    unsafe {
        ChangeServiceConfig2W(
            service.handle(),
            SERVICE_CONFIG_DESCRIPTION,
            Some(&service_desc as *const _ as *const std::ffi::c_void),
        )
        .map_err(|e| {
            InstallerError::System(format!("Failed to set service description: {}", e))
        })?;
    }

    Ok(())
}

/// Configure failure actions for automatic restart
pub(super) fn configure_failure_actions(
    service: &ServiceHandle,
    auto_restart: bool,
) -> Result<(), InstallerError> {
    if !auto_restart {
        return Ok(());
    }

    // Define restart actions: restart after 5s, 10s, 30s
    let actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5000, // 5 seconds
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 10000, // 10 seconds
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 30000, // 30 seconds
        },
    ];

    let failure_actions = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86400, // Reset failure count after 24 hours
        lpRebootMsg: PWSTR::null(),
        lpCommand: PWSTR::null(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_ptr() as *mut SC_ACTION,
    };

    unsafe {
        ChangeServiceConfig2W(
            service.handle(),
            SERVICE_CONFIG_FAILURE_ACTIONS,
            Some(&failure_actions as *const _ as *const std::ffi::c_void),
        )
        .map_err(|e| InstallerError::System(format!("Failed to set failure actions: {}", e)))?;
    }

    Ok(())
}

/// Configure delayed auto-start for performance
pub(super) fn configure_delayed_start(service: &ServiceHandle) -> Result<(), InstallerError> {
    let delayed_start = SERVICE_DELAYED_AUTO_START_INFO {
        fDelayedAutostart: true.into(),
    };

    unsafe {
        ChangeServiceConfig2W(
            service.handle(),
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            Some(&delayed_start as *const _ as *const std::ffi::c_void),
        )
        .map_err(|e| InstallerError::System(format!("Failed to set delayed start: {}", e)))?;
    }

    Ok(())
}

/// Configure service SID for security isolation
pub(super) fn configure_service_sid(service: &ServiceHandle) -> Result<(), InstallerError> {
    let service_sid_info = windows::Win32::System::Services::SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };

    unsafe {
        ChangeServiceConfig2W(
            service.handle(),
            SERVICE_CONFIG_SERVICE_SID_INFO,
            Some(&service_sid_info as *const _ as *const std::ffi::c_void),
        )
        .map_err(|e| InstallerError::System(format!("Failed to set service SID: {}", e)))?;
    }

    Ok(())
}

/// Start the service
pub(super) fn start_service(service: &ServiceHandle) -> Result<(), InstallerError> {
    unsafe {
        StartServiceW(service.handle(), &[])
            .map_err(|e| InstallerError::System(format!("Failed to start service: {}", e)))?;
    }
    Ok(())
}

/// Stop the service
pub(super) fn stop_service(service: &ServiceHandle) -> Result<(), InstallerError> {
    let mut service_status: windows::Win32::System::Services::SERVICE_STATUS =
        unsafe { mem::zeroed() };

    unsafe {
        windows::Win32::System::Services::ControlService(
            service.handle(),
            windows::Win32::System::Services::SERVICE_CONTROL_STOP,
            &mut service_status,
        )
        .map_err(|e| InstallerError::System(format!("Failed to stop service: {}", e)))?;
    }

    Ok(())
}

/// Open an existing service by name
pub(super) fn open_service(
    sc_manager: &ScManagerHandle,
    label: &str,
) -> Result<ServiceHandle, InstallerError> {
    let mut service_name_buf: [u16; MAX_SERVICE_NAME] = [0; MAX_SERVICE_NAME];
    str_to_wide(label, &mut service_name_buf)?;

    let service_handle = unsafe {
        OpenServiceW(
            sc_manager.handle(),
            PCWSTR::from_raw(service_name_buf.as_ptr()),
            SERVICE_ALL_ACCESS,
        )
    };

    if service_handle.is_invalid() {
        return Err(InstallerError::System(format!(
            "Failed to open service for deletion: {}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        )));
    }

    Ok(ServiceHandle(service_handle))
}

/// Install service definitions in registry
pub(super) fn install_services(
    services: &[crate::config::ServiceDefinition],
) -> Result<(), InstallerError> {
    for service in services {
        let service_toml = toml::to_string_pretty(service).map_err(|e| {
            InstallerError::System(format!("Failed to serialize service: {}", e))
        })?;

        // Create services directory
        let services_dir = PathBuf::from(r"C:\ProgramData\kodegen\services");
        std::fs::create_dir_all(&services_dir).map_err(|e| {
            InstallerError::System(format!("Failed to create services directory: {}", e))
        })?;

        // Write service file
        let service_file = services_dir.join(format!("{}.toml", service.name));
        std::fs::write(&service_file, service_toml).map_err(|e| {
            InstallerError::System(format!("Failed to write service file: {}", e))
        })?;
    }
    Ok(())
}
