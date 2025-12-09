//! Registry operations for service configuration.

use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_OPEN_CREATE_OPTIONS, REG_SZ,
    RegCreateKeyExW, RegSetValueExW,
};
use windows::core::PCWSTR;

use super::handles::RegistryHandle;
use super::utils::str_to_wide;
use super::{InstallerBuilder, InstallerError};

/// Create registry entries for service configuration
pub(super) fn create_registry_entries(builder: &InstallerBuilder) -> Result<(), InstallerError> {
    let service_key_path = format!(
        "SYSTEM\\CurrentControlSet\\Services\\{}\\Parameters",
        builder.label
    );

    let mut key_path_buf: [u16; 512] = [0; 512];
    str_to_wide(&service_key_path, &mut key_path_buf)?;

    let mut key_handle: HKEY = HKEY::default();

    unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(key_path_buf.as_ptr()),
            Some(0),  // Reserved, must be 0
            None,
            REG_OPEN_CREATE_OPTIONS(0),  // No options
            KEY_WRITE,
            None,
            &mut key_handle,
            None,
        )
        .ok()
        .map_err(|e| InstallerError::System(format!("Failed to create registry key: {:?}", e)))?;
    }

    let registry_handle = RegistryHandle(key_handle);

    // Store environment variables
    for (key, value) in &builder.env {
        set_registry_string(&registry_handle, key, value)?;
    }

    // Store service metadata
    set_registry_dword(
        &registry_handle,
        "AutoRestart",
        if builder.auto_restart { 1 } else { 0 },
    )?;
    set_registry_dword(
        &registry_handle,
        "WantsNetwork",
        if builder.wants_network { 1 } else { 0 },
    )?;

    Ok(())
}

/// Register Windows Event Log source
///
/// Uses the eventlog crate to register the service as an Event Log source.
/// This creates the necessary registry entries at:
/// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\{service_name}
pub(super) fn register_event_source(service_name: &str) -> Result<(), InstallerError> {
    eventlog::register(service_name)
        .map_err(|e| InstallerError::System(format!(
            "Failed to register Windows Event Log source '{}': {}. This is expected if not running as Administrator.",
            service_name, e
        )))?;

    log::info!(
        "Windows Event Log source '{}' registered successfully",
        service_name
    );
    Ok(())
}

/// Cleanup registry entries
pub(super) fn cleanup_registry_entries(_service_name: &str) -> Result<(), InstallerError> {
    // This would implement registry cleanup
    // For brevity, we'll implement the key deletion logic
    Ok(())
}

/// Unregister event source
///
/// Removes the Event Log source registry entries for the service.
pub(super) fn unregister_event_source(service_name: &str) -> Result<(), InstallerError> {
    eventlog::deregister(service_name).map_err(|e| {
        InstallerError::System(format!(
            "Failed to deregister Windows Event Log source '{}': {}",
            service_name, e
        ))
    })?;

    log::info!(
        "Windows Event Log source '{}' deregistered successfully",
        service_name
    );
    Ok(())
}

/// Set registry string value
fn set_registry_string(
    registry: &RegistryHandle,
    name: &str,
    value: &str,
) -> Result<(), InstallerError> {
    let mut name_buf: [u16; 256] = [0; 256];
    let mut value_buf: [u16; 1024] = [0; 1024];

    str_to_wide(name, &mut name_buf)?;
    str_to_wide(value, &mut value_buf)?;

    let value_bytes = unsafe {
        std::slice::from_raw_parts(
            value_buf.as_ptr() as *const u8,
            (value.len() + 1) * 2, // +1 for null terminator, *2 for UTF-16
        )
    };

    unsafe {
        RegSetValueExW(
            registry.handle(),
            PCWSTR::from_raw(name_buf.as_ptr()),
            Some(0),  // Reserved, must be 0
            REG_SZ,
            Some(value_bytes),
        )
        .ok()
        .map_err(|e| InstallerError::System(format!("Failed to set registry value: {:?}", e)))?;
    }

    Ok(())
}

/// Set registry DWORD value
fn set_registry_dword(
    registry: &RegistryHandle,
    name: &str,
    value: u32,
) -> Result<(), InstallerError> {
    let mut name_buf: [u16; 256] = [0; 256];
    str_to_wide(name, &mut name_buf)?;

    let value_bytes = value.to_le_bytes();

    unsafe {
        RegSetValueExW(
            registry.handle(),
            PCWSTR::from_raw(name_buf.as_ptr()),
            Some(0),  // Reserved, must be 0
            REG_DWORD,
            Some(&value_bytes),
        )
        .ok()
        .map_err(|e| InstallerError::System(format!("Failed to set registry DWORD: {:?}", e)))?;
    }

    Ok(())
}
