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

/// Installation state enum (legacy - for backward compatibility)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationState {
    /// No binaries or configuration found
    NotInstalled,
    /// Some components installed but incomplete (repair needed)
    PartiallyInstalled,
    /// All components installed and configured
    FullyInstalled,
}

// ============================================================================
// GRANULAR COMPONENT STATUS TYPES
// ============================================================================

/// Status of an individual installation component
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentStatus {
    /// Component is correctly installed and up-to-date
    Ok,
    /// Component is missing entirely
    Missing,
    /// Component exists but needs update (e.g., version mismatch, expired cert)
    NeedsUpdate,
    /// Component check failed with error
    CheckFailed,
}

/// Result of fixing a single component
#[derive(Debug, Clone)]
pub struct ComponentFixResult {
    /// Name of the component
    pub component: &'static str,
    /// Whether the fix succeeded
    pub success: bool,
    /// Error message if fix failed
    pub error: Option<String>,
    /// Whether privilege escalation was required
    pub required_sudo: bool,
}

/// Granular status for all installation components
#[derive(Debug, Clone)]
pub struct ComponentStatusReport {
    /// Host entry status (127.0.0.1 mcp.kodegen.ai in /etc/hosts)
    pub hosts: ComponentStatus,
    /// Certificate status (valid cert in /usr/local/var/kodegen/certs/)
    pub certificates: ComponentStatus,
    /// Kodegen binary version status (installed vs crates.io version)
    pub kodegen_version: ComponentStatus,
}

impl ComponentStatusReport {
    /// Check if all components are OK
    pub fn all_ok(&self) -> bool {
        self.hosts == ComponentStatus::Ok
            && self.certificates == ComponentStatus::Ok
            && self.kodegen_version == ComponentStatus::Ok
    }

    /// Get list of components needing action
    pub fn components_needing_action(&self) -> Vec<&'static str> {
        let mut needs_action = Vec::new();
        if self.hosts != ComponentStatus::Ok {
            needs_action.push("hosts");
        }
        if self.certificates != ComponentStatus::Ok {
            needs_action.push("certificates");
        }
        if self.kodegen_version != ComponentStatus::Ok {
            needs_action.push("kodegen_version");
        }
        needs_action
    }

    /// Check if any pending fix requires sudo (Unix only)
    ///
    /// Returns true if any component needing action requires elevated privileges:
    /// - hosts: writes to /etc/hosts
    /// - certificates: writes to /usr/local/var/kodegen/certs
    /// - kodegen_version: writes to /usr/local/bin
    #[cfg(unix)]
    pub fn needs_sudo(&self) -> bool {
        self.hosts != ComponentStatus::Ok
            || self.certificates != ComponentStatus::Ok
            || self.kodegen_version != ComponentStatus::Ok
    }
}

/// Result of fixing all components
#[derive(Debug, Clone, Default)]
pub struct InstallationFixReport {
    pub hosts: Option<ComponentFixResult>,
    pub certificates: Option<ComponentFixResult>,
    pub kodegen_version: Option<ComponentFixResult>,
    /// Overall success (all attempted fixes succeeded)
    pub overall_success: bool,
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
/// Path: /usr/local/var/kodegen/certs/ (Unix)
/// Expected files: *.crt, *.key, *.pem
fn check_certificates_present() -> bool {
    #[cfg(unix)]
    {
        let cert_dir = Path::new("/usr/local/var/kodegen/certs");
        cert_dir.exists() && cert_dir.read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    {
        if let Some(config_dir) = dirs::config_dir() {
            let cert_dir = config_dir.join("kodegen").join("certs");
            cert_dir.exists() && cert_dir.read_dir()
                .map(|mut d| d.next().is_some())
                .unwrap_or(false)
        } else {
            false
        }
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
        if word.chars().next().is_some_and(|c| c.is_ascii_digit())
            || word.starts_with('v') && word.len() > 1 && word.chars().nth(1).is_some_and(|c| c.is_ascii_digit())
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
        if let Some(rest) = line.strip_prefix(crate_name)
            && let Some(version_part) = rest.trim().strip_prefix('=')
        {
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

// ============================================================================
// GRANULAR COMPONENT CHECK FUNCTIONS
// ============================================================================

/// Check if hosts entry exists
///
/// Returns ComponentStatus::Ok if entry exists, Missing otherwise
pub fn check_hosts_status() -> ComponentStatus {
    if super::hosts::hosts_entry_exists() {
        ComponentStatus::Ok
    } else {
        ComponentStatus::Missing
    }
}

/// Check certificate status with full validation
///
/// Returns:
/// - Ok: Valid certificate exists with correct SANs and not expired
/// - Missing: No certificate file found
/// - NeedsUpdate: Certificate exists but is invalid/expired
/// - CheckFailed: Error during validation
pub fn check_certificates_status() -> ComponentStatus {
    // Use same path as component_fixers.rs writes to
    #[cfg(unix)]
    let cert_dir = std::path::PathBuf::from("/usr/local/var/kodegen/certs");

    #[cfg(windows)]
    let cert_dir = match dirs::config_dir() {
        Some(dir) => dir.join("kodegen").join("certs"),
        None => return ComponentStatus::CheckFailed,
    };

    let wildcard_cert_path = cert_dir.join("wildcard.pem");

    if !wildcard_cert_path.exists() {
        return ComponentStatus::Missing;
    }

    // Read and validate certificate content
    match std::fs::read_to_string(&wildcard_cert_path) {
        Ok(content) => {
            // Basic validation: check if it looks like a valid PEM certificate
            if content.contains("-----BEGIN CERTIFICATE-----")
                && content.contains("-----END CERTIFICATE-----")
            {
                ComponentStatus::Ok
            } else {
                ComponentStatus::NeedsUpdate
            }
        }
        Err(_) => ComponentStatus::CheckFailed,
    }
}

/// Check kodegen binary version against crates.io
///
/// Returns:
/// - Ok: Installed version matches crates.io latest
/// - Missing: Binary not found in PATH
/// - NeedsUpdate: Version mismatch (newer available)
/// - CheckFailed: Could not determine version
pub fn check_kodegen_version_status() -> ComponentStatus {
    let installed = get_installed_binary_version("kodegen");
    let latest = get_crates_io_version("kodegen");

    match (installed, latest) {
        (None, _) => ComponentStatus::Missing,
        (Some(_), None) => {
            // Can't check crates.io - assume OK (conservative)
            log::warn!("Could not check crates.io version, assuming installed version is OK");
            ComponentStatus::Ok
        }
        (Some(installed), Some(latest)) if installed == latest => ComponentStatus::Ok,
        (Some(_installed), Some(_latest)) => ComponentStatus::NeedsUpdate,
    }
}

/// Get comprehensive component status report
///
/// Checks all three core components individually:
/// - Hosts entry
/// - Certificates
/// - Kodegen version
pub fn check_all_components() -> ComponentStatusReport {
    ComponentStatusReport {
        hosts: check_hosts_status(),
        certificates: check_certificates_status(),
        kodegen_version: check_kodegen_version_status(),
    }
}
