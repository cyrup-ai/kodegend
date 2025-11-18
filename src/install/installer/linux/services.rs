//! Service definition installation.
//!
//! This module handles installation of service definition files in the
//! configuration directory with proper permissions.

use std::fs;
use std::path::PathBuf;

use super::InstallerError;
use super::file_ops::write_file_atomic;

/// Install service definitions in configuration directory
pub(super) fn install_services(
    services: &[crate::config::ServiceDefinition],
) -> Result<(), InstallerError> {
    for service in services {
        let service_toml = toml::to_string_pretty(service).map_err(|e| {
            InstallerError::System(format!("Failed to serialize service: {}", e))
        })?;

        // Create services directory
        let services_dir = PathBuf::from("/etc/kodegen/services");
        fs::create_dir_all(&services_dir).map_err(|e| {
            InstallerError::System(format!("Failed to create services directory: {}", e))
        })?;

        // Write service file
        let service_file = services_dir.join(format!("{}.toml", service.name));
        write_file_atomic(&service_file, &service_toml)?;

        // Set appropriate permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&service_file)
                .map_err(|e| {
                    InstallerError::System(format!(
                        "Failed to get service file metadata: {}",
                        e
                    ))
                })?
                .permissions();
            perms.set_mode(0o644);
            fs::set_permissions(&service_file, perms).map_err(|e| {
                InstallerError::System(format!("Failed to set service file permissions: {}", e))
            })?;
        }
    }
    Ok(())
}
