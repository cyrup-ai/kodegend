//! Uninstallation and cleanup functionality
//!
//! This module provides uninstallation logic, certificate cleanup, and host file
//! restoration with zero allocation fast paths and blazing-fast performance.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use log::{info, warn};

// Removed unused import: use super::core::InstallProgress;
use super::config::remove_kodegen_host_entries;
use super::fluent_voice;

/// Uninstall Kodegen daemon with comprehensive cleanup
#[allow(dead_code)] // Function IS used via install::uninstall re-export in runners.rs:run_uninstall()
pub async fn uninstall_kodegen_daemon() -> Result<()> {
    info!("Starting Kodegen daemon uninstallation");

    // Remove daemon service - platform-specific uninstallation
    info!("Removing daemon service...");

    #[cfg(target_os = "macos")]
    {
        if let Err(e) = super::macos::PlatformExecutor::uninstall("kodegend") {
            warn!("Failed to uninstall macOS daemon: {e}");
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = super::linux::PlatformExecutor::uninstall("kodegend") {
            warn!("Failed to uninstall Linux daemon: {}", e);
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = super::windows::PlatformExecutor::uninstall("kodegend") {
            warn!("Failed to uninstall Windows daemon: {}", e);
        }
    }

    // Remove host entries
    if let Err(e) = remove_kodegen_host_entries() {
        warn!("Failed to remove Kodegen host entries: {e}");
    }

    // Remove wildcard certificate from system trust store
    if let Err(e) = remove_wildcard_certificate_from_system().await {
        warn!("Failed to remove wildcard certificate from system: {e}");
    }

    // Remove installation directories from Windows PATH
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = remove_from_windows_path() {
            warn!("Failed to remove kodegen from Windows PATH: {e}");
        }
    }

    // Clean up installation directories
    if let Err(e) = cleanup_installation_directories() {
        warn!("Failed to clean up installation directories: {e}");
    }

    // Uninstall fluent-voice components
    let fluent_voice_path = std::path::Path::new("/opt/kodegen/fluent-voice");
    if let Err(e) = fluent_voice::uninstall_fluent_voice(fluent_voice_path).await {
        warn!("Failed to uninstall fluent-voice components: {e}");
    }

    info!("Kodegen daemon uninstallation completed");
    Ok(())
}

/// Validate existing certificate with fast validation (used by config.rs)
#[allow(dead_code)] // Library function for certificate validation operations
pub fn validate_existing_wildcard_cert(cert_path: &Path) -> Result<()> {
    let cert_content = fs::read_to_string(cert_path).context("Failed to read certificate file")?;

    // Basic validation - check if it contains the expected domain
    if !cert_content.contains("mcp.kodegen.ai") {
        return Err(anyhow::anyhow!("Missing required domain: mcp.kodegen.ai"));
    }

    // Check if it has both certificate and private key
    if !cert_content.contains("-----BEGIN CERTIFICATE-----")
        || !cert_content.contains("-----BEGIN PRIVATE KEY-----")
    {
        return Err(anyhow::anyhow!(
            "Invalid certificate format - missing certificate or private key"
        ));
    }

    Ok(())
}

/// Import wildcard certificate on Linux
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn import_wildcard_certificate_linux(cert_path: &str) -> Result<()> {
    info!("Importing Kodegen wildcard certificate to Linux system trust store");

    // Extract just the certificate part from the combined PEM file
    let cert_content =
        std::fs::read_to_string(cert_path).context("Failed to read certificate file")?;

    // Find the certificate part (everything before the private key)
    let cert_part = if let Some(key_start) = cert_content.find("-----BEGIN PRIVATE KEY-----") {
        &cert_content[..key_start]
    } else {
        &cert_content
    };

    // Copy certificate to system trust store
    let system_cert_path = "/usr/local/share/ca-certificates/kodegen-wildcard.crt";

    // Ensure directory exists
    if let Some(parent) = std::path::Path::new(system_cert_path).parent() {
        std::fs::create_dir_all(parent).context("Failed to create ca-certificates directory")?;
    }

    std::fs::write(system_cert_path, cert_part)
        .context("Failed to write certificate to system trust store")?;

    // Update certificate trust store
    let output = Command::new("update-ca-certificates")
        .output()
        .context("Failed to execute update-ca-certificates")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to update certificate trust store: {}", stderr);
        // Don't fail the installation if this step fails
    } else {
        info!("Successfully imported Kodegen wildcard certificate to Linux system trust store");
    }

    Ok(())
}

/// Remove wildcard certificate from system trust store
#[allow(dead_code)] // Function IS used at line 51, but compiler doesn't track async usage correctly
async fn remove_wildcard_certificate_from_system() -> Result<()> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "macos")] {
            remove_wildcard_certificate_macos().await
        } else if #[cfg(target_os = "linux")] {
            remove_wildcard_certificate_linux().await
        } else if #[cfg(target_os = "windows")] {
            remove_wildcard_certificate_windows().await
        } else {
            warn!("Wildcard certificate removal not supported on this platform");
            Ok(())
        }
    }
}

/// Remove wildcard certificate from macOS keychain
#[cfg(target_os = "macos")]
#[allow(dead_code)] // Used at line 140 via cfg_if!, but compiler doesn't track platform-specific usage
async fn remove_wildcard_certificate_macos() -> Result<()> {
    info!("Removing Kodegen certificate from macOS System keychain");

    // Find and delete the certificate
    let output = Command::new("security")
        .args([
            "delete-certificate",
            "-c",
            "mcp.kodegen.ai",
            "/Library/Keychains/System.keychain",
        ])
        .output()
        .context("Failed to execute security command")?;

    if output.status.success() {
        info!("Successfully removed Kodegen certificate from macOS System keychain");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't treat this as a fatal error since the certificate might not exist
        warn!("Failed to remove certificate from macOS keychain (might not exist): {stderr}");
    }

    Ok(())
}

/// Remove wildcard certificate from Linux system trust store
#[cfg(target_os = "linux")]
async fn remove_wildcard_certificate_linux() -> Result<()> {
    info!("Removing Kodegen wildcard certificate from Linux system trust store");

    let system_cert_path = "/usr/local/share/ca-certificates/kodegen-wildcard.crt";

    // Remove certificate file
    if std::path::Path::new(system_cert_path).exists() {
        std::fs::remove_file(system_cert_path)
            .context("Failed to remove certificate from system trust store")?;

        // Update certificate trust store
        let output = Command::new("update-ca-certificates")
            .output()
            .context("Failed to execute update-ca-certificates")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to update certificate trust store: {}", stderr);
        } else {
            info!(
                "Successfully removed Kodegen wildcard certificate from Linux system trust store"
            );
        }
    } else {
        info!("Kodegen wildcard certificate not found in system trust store");
    }

    Ok(())
}

/// Remove wildcard certificate from Windows Root certificate store
#[cfg(target_os = "windows")]
async fn remove_wildcard_certificate_windows() -> Result<()> {
    use windows::Win32::Security::Cryptography::{
        CERT_FIND_SUBJECT_STR_W, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
        CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE,
        CertCloseStore, CertDeleteCertificateFromStore, CertFindCertificateInStore, CertOpenStore,
    };
    use windows::core::HSTRING;

    info!("Removing Kodegen certificate from Windows Root certificate store");

    // Perform CryptoAPI operations in blocking task (sync Win32 API)
    tokio::task::spawn_blocking(move || {
        unsafe {
            // Open the Root certificate store for LOCAL_MACHINE
            let store_name = HSTRING::from("Root");

            let store_handle = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE),
                Some(&store_name as *const _ as *const _),
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to open Root certificate store (error: {}). Ensure running with Administrator privileges.",
                    e
                )
            })?;

            // Ensure store is always closed
            let _store_guard = scopeguard::guard(store_handle, |handle| {
                let _ = CertCloseStore(Some(handle), 0);
            });

            // Search for certificate containing "mcp.kodegen.ai" in subject
            let search_string = HSTRING::from("mcp.kodegen.ai");
            
            let mut cert_context = CertFindCertificateInStore(
                store_handle,
                CERT_QUERY_ENCODING_TYPE(0),
                0,
                CERT_FIND_SUBJECT_STR_W,
                Some(&search_string as *const _ as *const _),
                None,
            );

            let mut deleted_count = 0;

            // Enumerate and delete all matching certificates
            // cert_context is *const CERT_CONTEXT - check for null pointer
            while !cert_context.is_null() {
                info!("Found Kodegen certificate in Root store, removing...");

                // CertDeleteCertificateFromStore frees the context automatically
                // We must NOT call CertFreeCertificateContext after this
                let delete_result = CertDeleteCertificateFromStore(cert_context);

                if delete_result.is_ok() {
                    deleted_count += 1;
                    info!("Successfully deleted certificate from Root store");
                } else {
                    warn!("Failed to delete certificate from Root store");
                }

                // Find next matching certificate
                cert_context = CertFindCertificateInStore(
                    store_handle,
                    CERT_QUERY_ENCODING_TYPE(0),
                    0,
                    CERT_FIND_SUBJECT_STR_W,
                    Some(&search_string as *const _ as *const _),
                    None,
                );
            }

            if deleted_count > 0 {
                info!("✓ Removed {} Kodegen certificate(s) from Windows Root certificate store", deleted_count);
                Ok(())
            } else {
                info!("Kodegen certificate not found in Windows Root store");
                Ok(())
            }
        }
    })
    .await
    .context("Task panicked during certificate removal")?
}

/// Remove Kodegen installation directories from Windows system PATH
///
/// Reads the current system PATH from the registry, removes any entries that match
/// Kodegen installation directories (both System and User scope), writes the cleaned
/// PATH back to the registry, and broadcasts WM_SETTINGCHANGE to notify running processes.
#[cfg(target_os = "windows")]
fn remove_from_windows_path() -> Result<()> {
    use std::process::Command;

    info!("Removing Kodegen directories from Windows system PATH");

    // Get list of installation directories to remove
    let dirs_to_remove = get_installation_directories();
    let dirs_to_remove_strings: Vec<String> = dirs_to_remove
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    // Read current PATH from registry
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            "/v",
            "Path",
        ])
        .output()
        .context("Failed to query system PATH registry")?;

    let current_path = String::from_utf8_lossy(&output.stdout);

    // Extract current PATH value (after "REG_EXPAND_SZ" or "REG_SZ")
    let path_value = current_path
        .lines()
        .find(|line| line.contains("REG_"))
        .and_then(|line| {
            // Format is "    Path    REG_EXPAND_SZ    value"
            let parts: Vec<&str> = line.splitn(3, "    ").collect();
            parts.get(2).map(|s| s.trim())
        })
        .unwrap_or("");

    if path_value.is_empty() {
        info!("System PATH is empty, nothing to remove");
        return Ok(());
    }

    // Split PATH into individual entries and filter out Kodegen directories
    let path_entries: Vec<&str> = path_value.split(';').collect();
    let mut filtered_entries = Vec::new();
    let mut removed_count = 0;

    for entry in path_entries {
        let entry_trimmed = entry.trim();
        if entry_trimmed.is_empty() {
            continue;
        }

        // Check if this entry matches any Kodegen installation directory (case-insensitive)
        let should_remove = dirs_to_remove_strings.iter().any(|dir| {
            entry_trimmed.eq_ignore_ascii_case(dir)
        });

        if should_remove {
            info!("Removing from PATH: {}", entry_trimmed);
            removed_count += 1;
        } else {
            filtered_entries.push(entry_trimmed);
        }
    }

    if removed_count == 0 {
        info!("No Kodegen directories found in PATH, nothing to remove");
        return Ok(());
    }

    // Reconstruct PATH with filtered entries
    let new_path = filtered_entries.join(";");

    // Write cleaned PATH back to registry
    let status = Command::new("reg")
        .args([
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            "/v",
            "Path",
            "/t",
            "REG_EXPAND_SZ",
            "/d",
            &new_path,
            "/f",
        ])
        .status()
        .context("Failed to update system PATH registry")?;

    if !status.success() {
        return Err(anyhow::anyhow!("Failed to write cleaned PATH to registry"));
    }

    // Broadcast WM_SETTINGCHANGE to notify running processes (best effort)
    let _ = Command::new("powershell")
        .args([
            "-Command",
            "Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition '[DllImport(\"user32.dll\", SetLastError = true, CharSet = CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'; $HWND_BROADCAST = [IntPtr]0xffff; $WM_SETTINGCHANGE = 0x1a; $result = [UIntPtr]::Zero; [Win32.NativeMethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)",
        ])
        .status();

    info!("Successfully removed {} Kodegen director{} from system PATH", 
        removed_count, 
        if removed_count == 1 { "y" } else { "ies" }
    );

    Ok(())
}

/// Clean up installation directories with comprehensive cleanup
#[allow(dead_code)] // Function IS used at line 56, but compiler doesn't track usage correctly
fn cleanup_installation_directories() -> Result<()> {
    let directories_to_remove = get_installation_directories();

    for dir in directories_to_remove {
        if dir.exists() {
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => {
                    info!("Removed directory: {dir:?}");
                }
                Err(e) => {
                    warn!("Failed to remove directory {dir:?}: {e}");
                    // Continue with other directories
                }
            }
        }
    }

    Ok(())
}

/// Get list of installation directories to clean up
#[allow(dead_code)] // Function IS used at line 211, but compiler doesn't track call chain correctly
fn get_installation_directories() -> Vec<PathBuf> {
    let mut dirs = vec![];

    // New single-root directory (primary location)
    if let Ok(root) = kodegen_config::KodegenConfig::user_config_dir() {
        dirs.push(root);
    }

    // Legacy system directories (for backwards compatibility - clean up old installations)
    #[cfg(target_os = "macos")]
    dirs.push(PathBuf::from("/usr/local/var/kodegen"));

    #[cfg(target_os = "linux")]
    {
        dirs.push(PathBuf::from("/var/lib/kodegen"));
        dirs.push(PathBuf::from("/etc/kodegen"));
    }

    #[cfg(target_os = "windows")]
    {
        use crate::install::installer::windows::paths;
        dirs.push(paths::installer_data_dir());

        use crate::install::installer::windows::paths::{InstallScope, install_dir};
        // Add both System and User scope installation directories
        dirs.push(install_dir(InstallScope::System));
        dirs.push(install_dir(InstallScope::User));
    }

    // Common legacy directories
    dirs.push(PathBuf::from("/opt/kodegen"));
    dirs.push(std::env::temp_dir().join("kodegen"));

    dirs
}

/// Add Kodegen host entries with optimized host file modification
#[allow(dead_code)] // Library function for host file management operations
fn add_kodegen_host_entries() -> Result<()> {
    #[cfg(target_os = "windows")]
    let hosts_file = super::windows::paths::hosts_file();

    #[cfg(not(target_os = "windows"))]
    let hosts_file = PathBuf::from("/etc/hosts");

    // Read current hosts file
    let current_hosts = fs::read_to_string(&hosts_file).context("Failed to read hosts file")?;

    let kodegen_domains = [
        "kodegen.kodegen.dev",
        "kodegen.kodegen.ai",
        "kodegen.kodegen.cloud",
        "kodegen.kodegen.pro",
    ];

    let mut new_entries = Vec::new();
    let mut entries_added = false;

    // Check which entries need to be added
    for domain in &kodegen_domains {
        if current_hosts.contains(domain) {
            info!("{domain} entry already exists in hosts file");
        } else {
            new_entries.push(format!("127.0.0.1 {domain}"));
            entries_added = true;
        }
    }

    if !entries_added {
        info!("All Kodegen host entries already exist");
        return Ok(());
    }

    // Append new entries
    let mut updated_hosts = current_hosts;
    if !updated_hosts.ends_with('\n') {
        updated_hosts.push('\n');
    }
    updated_hosts.push_str("\n# Kodegen Auto-Integration\n");
    for entry in &new_entries {
        updated_hosts.push_str(&format!("{entry}\n"));
    }

    // Write updated hosts file
    fs::write(hosts_file, updated_hosts).context("Failed to write hosts file")?;

    info!(
        "Successfully added {} Kodegen host entries",
        new_entries.len()
    );
    Ok(())
}

/// Get the installed daemon path for the current platform
#[allow(dead_code)] // Library function for daemon path resolution
fn get_installed_daemon_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        use crate::install::installer::windows::paths::{InstallScope, kodegend_exe};
        // Windows installs to Program Files or System32
        kodegend_exe(InstallScope::System)
    }

    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/usr/local/bin/kodegend")
    }

    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/usr/local/bin/kodegend")
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        PathBuf::from("/usr/local/bin/kodegend")
    }
}

/// Create tar command arguments with proper path validation
fn create_backup_args(backup_path: &Path, config_dir: &Path) -> Result<Vec<String>> {
    let parent = config_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Config directory has no parent",
        )
    })?;

    let filename = config_dir.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Config directory has no filename",
        )
    })?;

    Ok(vec![
        "-czf".to_string(),
        backup_path.to_string_lossy().to_string(),
        "-C".to_string(),
        parent.to_string_lossy().to_string(),
        filename.to_string_lossy().to_string(),
    ])
}

/// Backup configuration before uninstall (API function for future CLI use)
#[allow(dead_code)]
pub fn backup_configuration() -> Result<PathBuf> {
    let config_dir = get_config_directory();
    let backup_dir = get_backup_directory();

    // Create backup directory
    std::fs::create_dir_all(&backup_dir).context("Failed to create backup directory")?;

    // Generate backup filename with timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_path = backup_dir.join(format!("kodegen_config_backup_{timestamp}.tar.gz"));

    // Create tar archive of configuration
    let args = create_backup_args(&backup_path, &config_dir)
        .context("Failed to prepare backup command arguments")?;

    let output = Command::new("tar")
        .args(&args)
        .output()
        .context("Failed to create configuration backup")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "Failed to create configuration backup: {stderr}"
        ));
    }

    info!("Configuration backed up to: {backup_path:?}");
    Ok(backup_path)
}

/// Get configuration directory path (single-root approach)
fn get_config_directory() -> PathBuf {
    kodegen_config::KodegenConfig::data_dir()
        .unwrap_or_else(|_| {
            #[cfg(not(target_os = "windows"))]
            {
                PathBuf::from(".config/kodegen/data")
            }
            #[cfg(target_os = "windows")]
            {
                PathBuf::from("AppData\\Roaming\\kodegen\\data")
            }
        })
}

/// Get backup directory path
fn get_backup_directory() -> PathBuf {
    // All platforms: use subdirectory of data dir for consistency
    get_config_directory().join("backups")
}

/// Create tar extraction arguments with proper path validation  
fn create_restore_args(backup_path: &Path, parent_dir: &Path) -> Vec<String> {
    vec![
        "-xzf".to_string(),
        backup_path.to_string_lossy().to_string(),
        "-C".to_string(),
        parent_dir.to_string_lossy().to_string(),
    ]
}

/// Restore configuration from backup (API function for future CLI use)
#[allow(dead_code)]
pub fn restore_configuration(backup_path: &Path) -> Result<()> {
    if !backup_path.exists() {
        return Err(anyhow::anyhow!("Backup file not found: {backup_path:?}"));
    }

    let config_dir = get_config_directory();
    let parent_dir = config_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid configuration directory"))?;

    // Extract backup
    let args = create_restore_args(backup_path, parent_dir);

    let output = Command::new("tar")
        .args(&args)
        .output()
        .context("Failed to extract configuration backup")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "Failed to extract configuration backup: {stderr}"
        ));
    }

    info!("Configuration restored from: {backup_path:?}");
    Ok(())
}
