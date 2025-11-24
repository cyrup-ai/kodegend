//! Installation state detection
//!
//! Determines if Kodegen is installed, partially installed, or not installed
//! by checking all required components:
//! - 1 binary in /usr/local/bin (kodegen MCP stdio server)
//! - System service file (launchd/systemd) - for kodegend
//! - TLS certificates in config directory
//! - Chromium browser in cache directory
//!
//! NOTE: We do NOT check for kodegend binary because kodegend is already
//! running when this code executes! It's kodegend calling ensure_installed().

use std::path::Path;

/// Installation state enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationState {
    /// No binaries or configuration found
    NotInstalled,
    /// Some components installed but incomplete (repair needed)
    PartiallyInstalled,
    /// All components installed and configured
    FullyInstalled,
}

/// Check current installation state by verifying all components
///
/// Returns:
/// - `FullyInstalled` if kodegen binary, service, certs, and chromium present
/// - `NotInstalled` if kodegen binary not found
/// - `PartiallyInstalled` otherwise (needs repair)
pub fn check_installation_state() -> InstallationState {
    let binaries_ok = check_binaries_installed();
    let service_ok = check_service_configured();
    let certs_ok = check_certificates_present();
    let chromium_ok = check_chromium_installed();
    
    match (binaries_ok, service_ok, certs_ok, chromium_ok) {
        (0, false, false, false) => InstallationState::NotInstalled,
        (1, true, true, true) => InstallationState::FullyInstalled,
        _ => InstallationState::PartiallyInstalled,
    }
}

/// Count how many of the 1 required binaries are installed in /usr/local/bin
///
/// Uses the canonical BINARIES array from src/binaries.rs:
/// ["kodegen"]
///
/// NOTE: We do NOT check for kodegend because it's already running!
fn check_binaries_installed() -> usize {
    use super::binaries::BINARIES;
    
    #[cfg(unix)]
    let bin_dir = Path::new("/usr/local/bin");
    
    #[cfg(windows)]
    let bin_dir = {
        use crate::install::installer::windows::paths::{install_dir, InstallScope};
        install_dir(InstallScope::System)
    };
    
    BINARIES.iter()
        .filter(|name| bin_dir.join(name).exists())
        .count()
}

/// Check if system service is configured
///
/// Paths:
/// - macOS: /Library/LaunchDaemons/com.kodegen.daemon.plist
/// - Linux: /etc/systemd/system/kodegend.service
/// - Windows: Registry key (HKLM\SYSTEM\CurrentControlSet\Services\kodegend)
fn check_service_configured() -> bool {
    #[cfg(target_os = "macos")]
    {
        Path::new("/Library/LaunchDaemons/com.kodegen.daemon.plist").exists()
    }
    
    #[cfg(target_os = "linux")]
    {
        Path::new("/etc/systemd/system/kodegend.service").exists()
    }
    
    #[cfg(target_os = "windows")]
    {
        // Check if kodegend service exists in Windows Service Manager
        // Uses minimal permissions for read-only detection
        use windows::Win32::System::Services::{
            OpenSCManagerW, OpenServiceW, CloseServiceHandle,
            SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
        };
        use windows::core::PCWSTR;
        
        // Service name to check
        let service_name = "kodegend";
        
        // Convert to UTF-16 (Windows native string format)
        let wide_name: Vec<u16> = service_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        
        unsafe {
            // Open Service Control Manager with minimal permissions
            let scm = OpenSCManagerW(
                PCWSTR::null(),           // Local machine
                PCWSTR::null(),           // Default database
                SC_MANAGER_CONNECT,       // Minimal read-only access
            );
            
            if scm.is_invalid() {
                return false;  // SCM not available or no permissions
            }
            
            // Try to open the kodegend service
            let service = OpenServiceW(
                scm,
                PCWSTR::from_raw(wide_name.as_ptr()),
                SERVICE_QUERY_STATUS,     // Minimal read-only access
            );
            
            let exists = !service.is_invalid();
            
            // Clean up handles (RAII pattern)
            if !service.is_invalid() {
                let _ = CloseServiceHandle(service);
            }
            let _ = CloseServiceHandle(scm);
            
            exists  // Return true if service was opened successfully
        }
    }
    
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Check if certificates directory exists and has files
///
/// Path: dirs::config_dir()/kodegen/certs/
/// Expected files: *.crt, *.key, *.pem
fn check_certificates_present() -> bool {
    if let Some(config_dir) = dirs::config_dir() {
        let cert_dir = config_dir.join("kodegen").join("certs");
        cert_dir.exists() && cert_dir.read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    } else {
        false
    }
}

/// Check if Chromium is installed in cache directory
///
/// Chromium is downloaded by kodegen_tools_citescrape::download_managed_browser()
///
/// Paths:
/// - macOS: ~/Library/Caches/kodegen/chromium/
/// - Linux: ~/.cache/kodegen/chromium/
/// - Windows: %LOCALAPPDATA%\kodegen\chromium\
fn check_chromium_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            let chromium_path = home.join("Library/Caches/kodegen/chromium");
            chromium_path.exists()
        } else {
            false
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(cache) = dirs::cache_dir() {
            let chromium_path = cache.join("kodegen/chromium");
            chromium_path.exists()
        } else {
            false
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local_data) = dirs::data_local_dir() {
            let chromium_path = local_data.join("kodegen\\chromium");
            chromium_path.exists()
        } else {
            false
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Get the version of an installed binary by running `binary --version`
///
/// Returns Some(version) if the binary exists and returns a valid version,
/// None otherwise.
pub fn get_installed_binary_version(binary_name: &str) -> Option<String> {
    let output = std::process::Command::new(binary_name)
        .arg("--version")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse version from output like "kodegen 0.3.1" or "kodegen-v0.3.1"
    // Extract the version number (digits and dots)
    for word in stdout.split_whitespace() {
        if word.chars().next().map_or(false, |c| c.is_ascii_digit())
            || word.starts_with('v') && word.len() > 1 && word.chars().nth(1).map_or(false, |c| c.is_ascii_digit())
        {
            let version = word.trim_start_matches('v');
            if version.chars().any(|c| c == '.') {
                return Some(version.to_string());
            }
        }
    }

    None
}

/// Get the latest version of a crate from crates.io using `cargo search`
///
/// Returns Some(version) if the crate is found, None otherwise.
pub fn get_crates_io_version(crate_name: &str) -> Option<String> {
    let output = std::process::Command::new("cargo")
        .args(["search", crate_name, "--limit", "1"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output like: `kodegen = "0.3.1"    # Description`
    // Look for the exact crate name followed by = "version"
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix(crate_name) {
            if let Some(version_part) = rest.trim().strip_prefix('=') {
                // Extract version between quotes, stop at first quote closing
                let version_with_quote = version_part.trim().trim_start_matches('"');
                if let Some(end_quote_idx) = version_with_quote.find('"') {
                    let version_str = &version_with_quote[..end_quote_idx];
                    if !version_str.is_empty() {
                        return Some(version_str.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Check if a binary needs installation by comparing installed version with crates.io version
///
/// Returns true if:
/// - Binary is not installed (command not found)
/// - Installed version doesn't match latest crates.io version
/// - Version information cannot be determined
///
/// Returns false if installed version matches latest crates.io version
pub fn binary_needs_installation(binary_name: &str) -> bool {
    // Get installed version
    let installed_version = match get_installed_binary_version(binary_name) {
        Some(v) => v,
        None => {
            log::info!("{} not found or version unavailable, needs installation", binary_name);
            return true; // Binary not installed
        }
    };

    // Get latest version from crates.io
    let latest_version = match get_crates_io_version(binary_name) {
        Some(v) => v,
        None => {
            log::warn!("Could not determine latest version for {} from crates.io, skipping version check", binary_name);
            return false; // Can't determine latest, assume installed version is OK
        }
    };

    // Compare versions
    if installed_version == latest_version {
        log::info!("{} {} is up to date", binary_name, installed_version);
        false
    } else {
        log::info!("{} version mismatch: installed={}, latest={}", binary_name, installed_version, latest_version);
        true
    }
}
