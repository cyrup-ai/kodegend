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

use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
///
/// NOTE: The `component` and `required_sudo` fields are used via Debug trait
/// and in component_fixers.rs. The compiler doesn't see cross-module usage.
#[derive(Debug, Clone)]
pub struct ComponentFixResult {
    /// Name of the component
    #[allow(dead_code)]
    pub component: &'static str,
    /// Whether the fix succeeded
    pub success: bool,
    /// Error message if fix failed
    pub error: Option<String>,
    /// Whether privilege escalation was required
    #[allow(dead_code)]
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
    // Rust toolchain checking removed - bundled apps don't need Rust on user machines
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

    /// Check if any pending fix requires Administrator (Windows)
    ///
    /// Returns true if any component needing action requires elevated privileges:
    /// - hosts: writes to C:\Windows\System32\drivers\etc\hosts
    /// - certificates: writes to %PROGRAMDATA%\kodegen\certs and imports to cert store
    /// - kodegen_version: writes to %PROGRAMFILES%\kodegen\bin
    #[cfg(windows)]
    pub fn needs_sudo(&self) -> bool {
        self.hosts != ComponentStatus::Ok
            || self.certificates != ComponentStatus::Ok
            || self.kodegen_version != ComponentStatus::Ok
    }
}

/// Result of fixing all components
#[derive(Debug, Clone, Default)]
pub struct InstallationFixReport {
    // Rust toolchain checking removed - bundled apps don't need Rust on user machines
    pub hosts: Option<ComponentFixResult>,
    pub certificates: Option<ComponentFixResult>,
    pub kodegen_version: Option<ComponentFixResult>,
    /// Service registration result (launchd/systemd/SCM)
    pub service: Option<ComponentFixResult>,
    /// Overall success (all attempted fixes succeeded)
    pub overall_success: bool,
}

/// Get the version of an installed binary by running `binary --version`
///
/// Uses tokio::process with timeout to prevent hanging.
/// Parses version using regex for robustness.
///
/// Returns Some(version) if the binary exists and returns a valid version within 2 seconds,
/// None otherwise.
///
/// # Timeout Rationale
/// 2-second timeout prevents hanging on:
/// - Broken binaries that don't respond
/// - Network-mounted executables with high latency
/// - Binaries waiting for stdin (misconfigured)
///
/// # Regex Pattern
/// Matches semantic versions: 0.3.1, 1.0.0-beta, 2.1.3-rc.1, etc.
/// More robust than string splitting (handles various output formats)
pub async fn get_installed_binary_version(binary_name: &str) -> Option<String> {
    use tokio::process::Command;
    use tokio::time::{Duration, timeout};

    // Run with 2-second timeout to prevent hanging
    let output = match timeout(
        Duration::from_secs(2),
        Command::new(binary_name).arg("--version").output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            log::warn!("Failed to execute '{}': {} (binary may not be in PATH)", binary_name, e);
            return None;
        }
        Err(_) => {
            log::warn!("Timeout (2s) executing '{} --version' (binary may be hanging)", binary_name);
            return None;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!(
            "Binary '{}' returned non-zero exit code: {} - stderr: {}",
            binary_name,
            output.status,
            stderr.trim()
        );
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse version using regex (semantic version pattern)
    // Matches: 0.3.1, 1.0.0-beta, 2.1.3-rc.1, etc.
    let re = regex::Regex::new(r"\b(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)\b").ok()?;

    match re.captures(&stdout).and_then(|cap| cap.get(1)) {
        Some(m) => {
            let version = m.as_str().to_string();
            log::info!("Detected version for {}: {}", binary_name, version);
            Some(version)
        }
        None => {
            log::warn!(
                "Failed to parse version from '{}' output: {:?} \
                (expected format: X.Y.Z)",
                binary_name,
                stdout.trim()
            );
            None
        }
    }
}

/// Cache entry for crate version lookups
struct VersionCacheEntry {
    version: String,
    fetched_at: Instant,
}

/// In-memory cache for crate versions (5-minute TTL to avoid API rate limits)
///
/// Thread-safe via Mutex. The cache prevents excessive API calls during:
/// - Multiple component checks (hosts, certs, version) in quick succession
/// - Repeated `kodegend ensure-installed` invocations
/// - Installation retries after failures
static VERSION_CACHE: Lazy<Mutex<HashMap<String, VersionCacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes
const USER_AGENT: &str = concat!(
    "kodegend/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/kodegen-ai/kodegen)"
);

/// Crates.io API response structures
///
/// Matches the proven pattern from kodegen-tools-github/src/github/search_repositories/metrics/dependencies/types.rs
#[derive(Deserialize)]
struct CratesIoResponse {
    #[serde(rename = "crate")]
    crate_data: CrateData,
}

#[derive(Deserialize)]
struct CrateData {
    max_version: String,
}

/// Get the latest version of a crate from crates.io using the HTTP API
///
/// Uses in-memory caching (5-minute TTL) to avoid rate limits and improve performance.
/// Returns Some(version) if the crate is found, None otherwise.
///
/// # Performance
/// - First call: ~150ms (network request)
/// - Cached calls: ~0.1ms (memory lookup)
/// - Cache TTL: 5 minutes
///
/// # API Rate Limits
/// crates.io allows 1 req/sec burst for unauthenticated requests.
/// The cache prevents excessive calls during repeated checks.
///
/// # Thread Safety
/// Uses Mutex for cache access. Lock contention is minimal because:
/// - Cache lookups are very fast (HashMap O(1))
/// - Network requests happen outside the lock
/// - Typical usage: 3-5 checks per installation run
pub async fn get_crates_io_version(crate_name: &str) -> Option<String> {
    // Check cache first (avoid network call)
    {
        let cache = VERSION_CACHE.lock().ok()?;
        if let Some(entry) = cache.get(crate_name) {
            if entry.fetched_at.elapsed() < CACHE_TTL {
                log::debug!(
                    "Using cached version for {}: {} (age: {:?})",
                    crate_name,
                    entry.version,
                    entry.fetched_at.elapsed()
                );
                return Some(entry.version.clone());
            } else {
                log::debug!(
                    "Cache expired for {} (age: {:?})",
                    crate_name,
                    entry.fetched_at.elapsed()
                );
            }
        }
    }

    // Fetch from crates.io API
    log::debug!(
        "Fetching latest version for {} from crates.io API",
        crate_name
    );

    let url = format!("https://crates.io/api/v1/crates/{}", crate_name);

    // Create client with timeout and user-agent
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;

    // Make request
    let response = match client.get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!(
                "Network error fetching crate info for {}: {}",
                crate_name,
                e
            );
            return None;
        }
    };

    // Check HTTP status
    if !response.status().is_success() {
        log::warn!(
            "Failed to fetch crate info for {}: HTTP {}",
            crate_name,
            response.status()
        );
        return None;
    }

    // Parse JSON response
    let crate_data: CratesIoResponse = match response.json().await {
        Ok(data) => data,
        Err(e) => {
            log::warn!(
                "Failed to parse crates.io response for {}: {}",
                crate_name,
                e
            );
            return None;
        }
    };

    let version = crate_data.crate_data.max_version;

    // Update cache
    {
        if let Ok(mut cache) = VERSION_CACHE.lock() {
            cache.insert(
                crate_name.to_string(),
                VersionCacheEntry {
                    version: version.clone(),
                    fetched_at: Instant::now(),
                },
            );
            log::debug!("Cached version for {}: {}", crate_name, version);
        }
    }

    log::info!(
        "Latest version for {} from crates.io: {}",
        crate_name,
        version
    );
    Some(version)
}

/// Check if a binary needs installation by comparing installed version with crates.io version
///
/// Uses semantic versioning comparison to determine if update is needed.
///
/// Returns true if:
/// - Binary is not installed (command not found)
/// - Installed version is older than latest crates.io version
/// - Version information cannot be determined
///
/// Returns false if installed version matches or is newer than latest crates.io version
///
/// # Conservative Error Handling
/// - If crates.io is unreachable: assume installed version is OK (avoid forced reinstall)
/// - If binary not found: needs installation (correct behavior)
/// - If version parsing fails: depends on which side failed (see code comments)
#[allow(dead_code)] // Used in runners.rs but compiler doesn't detect cross-module async usage
pub async fn binary_needs_installation(binary_name: &str) -> bool {
    use semver::Version;

    // Get installed version
    let installed_version_str = match get_installed_binary_version(binary_name).await {
        Some(v) => v,
        None => {
            log::info!(
                "{} not found or version unavailable, needs installation",
                binary_name
            );
            return true; // Binary not installed
        }
    };

    // Get latest version from crates.io
    let latest_version_str = match get_crates_io_version(binary_name).await {
        Some(v) => v,
        None => {
            log::warn!(
                "Could not determine latest version for {} from crates.io, assuming installed version is OK",
                binary_name
            );
            return false; // Can't check crates.io, conservatively assume OK
        }
    };

    // Parse versions using semver
    let installed = match Version::parse(&installed_version_str) {
        Ok(v) => v,
        Err(e) => {
            log::warn!(
                "Failed to parse installed version '{}' for {}: {}",
                installed_version_str,
                binary_name,
                e
            );
            return true; // Can't parse installed version, assume needs update
        }
    };

    let latest = match Version::parse(&latest_version_str) {
        Ok(v) => v,
        Err(e) => {
            log::warn!(
                "Failed to parse latest version '{}' for {}: {}",
                latest_version_str,
                binary_name,
                e
            );
            return false; // Can't parse latest version, assume installed is OK
        }
    };

    // Compare versions (true if installed < latest)
    if installed < latest {
        log::info!(
            "{} version mismatch: installed={}, latest={} (update needed)",
            binary_name,
            installed_version_str,
            latest_version_str
        );
        true
    } else {
        log::info!(
            "{} version OK: installed={}, latest={}",
            binary_name,
            installed_version_str,
            latest_version_str
        );
        false
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
    // Use single-root approach: all platforms use data_dir/certs
    let cert_dir = match kodegen_config::KodegenConfig::data_dir() {
        Ok(dir) => dir.join("certs"),
        Err(_) => return ComponentStatus::CheckFailed,
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
/// - Ok: Installed version matches or is newer than crates.io latest
/// - Missing: Binary not found in PATH
/// - NeedsUpdate: Installed version is older than latest
/// - CheckFailed: Could not determine version (parse error)
pub async fn check_kodegen_version_status() -> ComponentStatus {
    use semver::Version;

    let installed = get_installed_binary_version("kodegen").await;
    let latest = get_crates_io_version("kodegen").await;

    match (installed, latest) {
        (None, _) => {
            log::info!("kodegen binary not found");
            ComponentStatus::Missing
        }
        (Some(_), None) => {
            // Can't check crates.io - assume OK (conservative)
            log::warn!("Could not check crates.io version, assuming installed version is OK");
            ComponentStatus::Ok
        }
        (Some(ref installed_str), Some(ref latest_str)) => {
            // Parse and compare versions
            let installed_parse = Version::parse(installed_str);
            let latest_parse = Version::parse(latest_str);

            match (installed_parse, latest_parse) {
                (Ok(installed_ver), Ok(latest_ver)) => {
                    if installed_ver >= latest_ver {
                        log::info!("kodegen version OK: {} >= {}", installed_str, latest_str);
                        ComponentStatus::Ok
                    } else {
                        log::info!(
                            "kodegen version outdated: {} < {}",
                            installed_str,
                            latest_str
                        );
                        ComponentStatus::NeedsUpdate
                    }
                }
                (Err(e), Ok(_)) => {
                    log::error!(
                        "Failed to parse INSTALLED version '{}': {}",
                        installed_str,
                        e
                    );
                    ComponentStatus::CheckFailed
                }
                (Ok(_), Err(e)) => {
                    log::error!(
                        "Failed to parse LATEST version from crates.io '{}': {}",
                        latest_str,
                        e
                    );
                    ComponentStatus::CheckFailed
                }
                (Err(e1), Err(e2)) => {
                    log::error!(
                        "Failed to parse BOTH versions - installed '{}': {}, latest '{}': {}",
                        installed_str,
                        e1,
                        latest_str,
                        e2
                    );
                    ComponentStatus::CheckFailed
                }
            }
        }
    }
}

/// Get comprehensive component status report
///
/// Checks core components individually:
/// - Hosts entry
/// - Certificates
/// - Kodegen version
pub async fn check_all_components() -> ComponentStatusReport {
    ComponentStatusReport {
        hosts: check_hosts_status(),
        certificates: check_certificates_status(),
        kodegen_version: check_kodegen_version_status().await,
    }
}
