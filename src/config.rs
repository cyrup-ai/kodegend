use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Resolve a path relative to a base directory (typically config file's directory)
///
/// # Behavior
/// - **Absolute paths**: Returned unchanged
/// - **Relative paths**: Resolved against `base_dir`
///
/// # Why not std::path::absolute()?
/// `std::path::absolute()` resolves against the **current working directory**.
/// For daemon configs, we need to resolve against the **config file's directory**
/// to maintain portability and predictable behavior after `chdir("/")`.
///
/// # Why not std::fs::canonicalize()?
/// `canonicalize()` has major limitations for daemon configs:
/// - Requires path to exist on disk (PID files don't exist yet!)
/// - Resolves symlinks (destroys user intent)
/// - Requires filesystem I/O (performance overhead)
/// - Produces Windows UNC paths that break many applications
///
/// See: https://github.com/rust-lang/rust/issues/59117
///
/// # Example
/// ```
/// let config_dir = Path::new("/etc/kodegend");
/// let pid_path = Path::new("./run/daemon.pid");
/// let resolved = canonicalize_config_path(pid_path, config_dir);
/// assert_eq!(resolved, PathBuf::from("/etc/kodegend/run/daemon.pid"));
/// ```
fn canonicalize_config_path<P: AsRef<Path>>(path: P, base_dir: &Path) -> PathBuf {
    let path = path.as_ref();

    if path.is_absolute() {
        // Already absolute - use as-is
        path.to_path_buf()
    } else {
        // Relative - resolve against config file's directory
        base_dir.join(path)
    }
}

/// Canonicalize an optional string path
///
/// Convenience wrapper for Option<String> paths common in ServiceConfig
fn canonicalize_optional_string(path_opt: &Option<String>, base_dir: &Path) -> Option<String> {
    path_opt
        .as_ref()
        .map(|p| canonicalize_config_path(p, base_dir).display().to_string())
}

/// Canonicalize a vector of string paths
///
/// Used for fields like `watch_dirs` that contain multiple paths
fn canonicalize_path_vec(paths: &[String], base_dir: &Path) -> Vec<String> {
    paths
        .iter()
        .map(|p| canonicalize_config_path(p, base_dir).display().to_string())
        .collect()
}

/// Vulnerability scanning thresholds configuration
///
/// Configures maximum allowed vulnerabilities by severity level.
/// Used by the VulnerabilityScanner to determine if a scan passes CI/CD checks.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilityThresholds {
    /// Maximum critical vulnerabilities allowed (default: 0)
    #[serde(default)]
    pub critical_max: Option<u32>,
    /// Maximum high vulnerabilities allowed (default: 2)
    #[serde(default)]
    pub high_max: Option<u32>,
    /// Maximum medium vulnerabilities allowed (default: 10)
    #[serde(default)]
    pub medium_max: Option<u32>,
    /// Maximum low vulnerabilities allowed (default: 50)
    #[serde(default)]
    pub low_max: Option<u32>,
}

/// Security configuration section
///
/// Controls daemon security features including vulnerability scanning.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    /// Enable periodic vulnerability scanning (default: false)
    #[serde(default)]
    pub enable_vulnerability_scanning: Option<bool>,
    
    /// Interval between vulnerability scans in seconds (default: 3600 = 1 hour)
    #[serde(default)]
    pub vulnerability_scan_interval_secs: Option<u64>,
    
    /// Vulnerability count thresholds for CI/CD integration
    #[serde(default)]
    pub vulnerability_thresholds: VulnerabilityThresholds,
}

/// Top‑level daemon configuration (mirrors original defaults).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_services_dir")]
    pub services_dir: Option<String>,

    #[serde(default = "default_log_dir")]
    pub log_dir: Option<String>,

    /// Default user to run services as (Unix-only, ignored on Windows)
    ///
    /// On Windows, services run under the account specified during installation
    /// (typically LocalSystem, NetworkService, or a specific user account).
    pub default_user: Option<String>,

    /// Default group to run services as (Unix-only, ignored on Windows)
    pub default_group: Option<String>,
    pub auto_restart: Option<bool>,
    pub services: Vec<ServiceDefinition>,
    /// MCP Streamable HTTP transport binding (host:port)
    pub mcp_bind: Option<String>,
    /// Category HTTP servers (14 tool categories)
    #[serde(default)]
    pub category_servers: Vec<CategoryServerConfig>,

    /// Maximum time to wait for all workers to shutdown gracefully (seconds)
    ///
    /// This timeout applies to the entire worker shutdown process:
    /// - Each worker has its own per-service timeout (shutdown_timeout_secs)
    /// - This provides a global bound to prevent indefinite daemon hangs
    /// - Must be less than systemd TimeoutStopSec (default: 90s)
    ///
    /// Recommended values:
    /// - Development: 15s (fast iteration)
    /// - Production: 30s (allows 10s per worker + overhead, 60s buffer before systemd kill)
    /// - Heavy workloads: 60s (max before systemd default timeout)
    #[serde(default = "default_daemon_shutdown_timeout")]
    pub daemon_shutdown_timeout_secs: u64,

    /// PID file location - defaults to privileged location if elevated,
    /// user runtime directory otherwise
    ///
    /// # Platform-Specific Defaults
    ///
    /// **Unix (elevated/root)**:
    /// - `/var/run/kodegend/kodegend.pid`
    ///
    /// **Unix (user)**:
    /// - `$XDG_RUNTIME_DIR/kodegend/kodegend.pid` (systemd)
    /// - `~/.local/state/kodegend/kodegend.pid` (fallback)
    ///
    /// **Windows (Administrator)**:
    /// - `C:\ProgramData\kodegend\run\kodegend.pid`
    ///
    /// **Windows (user)**:
    /// - `%LOCALAPPDATA%\kodegend\run\kodegend.pid`
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,

    /// Daemon working directory after daemonization
    ///
    /// The daemon changes to this directory after fork() to prevent
    /// holding references to the original directory, which could prevent
    /// unmounting filesystems.
    ///
    /// # Platform-Specific Defaults
    ///
    /// **Unix (all variants)**:
    /// - `/` (root directory, standard POSIX daemon practice)
    ///
    /// **Windows**:
    /// - `C:\` (system root, though daemonization doesn't apply)
    ///
    /// # Security Considerations
    ///
    /// Using `/` as working directory:
    /// - Prevents holding locks on user directories
    /// - Allows filesystem unmounting during daemon operation
    /// - Standard practice per POSIX daemon specification
    ///
    /// Custom directories should be carefully chosen to avoid:
    /// - Network-mounted filesystems (NFS, SMB)
    /// - Removable media
    /// - User home directories
    #[serde(default = "default_working_directory")]
    pub working_directory: PathBuf,

    /// Security configuration including vulnerability scanning
    #[serde(default)]
    pub security: SecurityConfig,

    /// Path to config file (not serialized, used for reload)
    #[serde(skip)]
    pub config_file_path: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

/// Default daemon shutdown timeout (30 seconds)
///
/// Provides 30s for all workers to complete shutdown, with 60s buffer
/// before systemd's default 90s SIGKILL timeout.
fn default_daemon_shutdown_timeout() -> u64 {
    30
}

/// Smart PID file default based on user permissions and platform conventions
fn default_pid_file() -> PathBuf {
    use crate::platform;

    let is_elevated = platform::is_elevated();
    platform::runtime_dir(is_elevated).join("kodegend.pid")
}

/// Platform-specific working directory default
fn default_working_directory() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/")
    }

    #[cfg(windows)]
    {
        PathBuf::from("C:\\")
    }
}

/// Restart policy configuration for service failure handling
///
/// Modeled after systemd StartLimitBurst/RestartSec and Docker exponential backoff.
/// Uses proven exponential backoff pattern from kodegen-bundler-release/retry.rs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartPolicy {
    /// Maximum restart attempts before giving up (None = infinite)
    /// Analogous to systemd StartLimitBurst (default: 5)
    ///
    /// Set to None to retry forever (not recommended for production)
    /// Set to 0 to disable auto-restart entirely
    pub max_attempts: Option<u32>,

    /// Initial delay in milliseconds before first restart
    /// Analogous to systemd RestartSec (default: 100ms)
    pub initial_delay_ms: u64,

    /// Maximum delay in milliseconds (exponential backoff cap)
    /// Similar to Docker's 1-minute max backoff
    ///
    /// Prevents exponential backoff from producing impractical wait times.
    /// After this delay is reached, all subsequent retries use this fixed delay.
    pub max_delay_ms: u64,

    /// Backoff multiplier for exponential delay (typically 2.0)
    /// Docker uses 2x, Kubernetes uses 2x
    ///
    /// Formula: delay = initial_delay_ms * backoff_multiplier^(attempts-1)
    /// Example with multiplier=2.0: 100ms, 200ms, 400ms, 800ms, ...
    pub backoff_multiplier: f64,

    /// Success window in seconds - if service runs this long, reset attempts
    /// Analogous to systemd StartLimitIntervalSec (default: 60s)
    ///
    /// Distinguishes transient issues from persistent failures.
    /// If service runs successfully for this duration, next restart starts at attempt 1.
    pub success_window_secs: u64,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_attempts: Some(5),   // systemd default
            initial_delay_ms: 100,   // systemd default
            max_delay_ms: 60_000,    // Docker default (1 minute)
            backoff_multiplier: 2.0, // Industry standard (see retry.rs:103)
            success_window_secs: 60, // Reset after 1 minute of success
        }
    }
}

/// Category HTTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryServerConfig {
    pub name: String,
    pub binary: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Discover certificate paths from standard installation locations
/// Checks system-wide and user-level install directories
pub fn discover_certificate_paths() -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    // Standard certificate file names
    const CERT_FILE: &str = "server.crt";
    const KEY_FILE: &str = "server.key";

    // Build search paths using single-root approach
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let search_paths = vec![
        kodegen_config::KodegenConfig::data_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("certs"),
    ];

    #[cfg(target_os = "windows")]
    let search_paths = {
        use crate::install::installer::windows::paths;
        vec![
            paths::cert_dir(),
            kodegen_config::KodegenConfig::data_dir()
                .unwrap_or_else(|_| PathBuf::from("C:\\temp"))
                .join("certs"),
        ]
    };

    // Search for certificates in priority order
    for cert_dir in search_paths {
        let cert_path = cert_dir.join(CERT_FILE);
        let key_path = cert_dir.join(KEY_FILE);

        // Check if both certificate and key exist
        if cert_path.exists() && key_path.exists() {
            log::info!(
                "Auto-discovered TLS certificates at: cert={}, key={}",
                cert_path.display(),
                key_path.display()
            );
            return (Some(cert_path), Some(key_path));
        }
    }

    // No certificates found - will run in HTTP mode
    log::info!("No TLS certificates found in standard locations, HTTPS will not be available");
    log::debug!("To enable HTTPS, ensure certificates exist at one of the standard paths");
    (None, None)
}

impl ServiceConfig {
    fn default_category_servers() -> Vec<CategoryServerConfig> {
        kodegen_config::CATEGORY_PORTS
            .iter()
            .map(|(category, port)| CategoryServerConfig {
                name: category.to_string(),
                binary: format!("kodegen-{}", category),
                port: *port,
                enabled: true,
            })
            .collect()
    }

    /// Load config from file and canonicalize all path fields
    ///
    /// # Path Resolution Strategy
    ///
    /// All relative paths in the config file are resolved relative to the **config file's directory**,
    /// not the current working directory. This follows industry best practices:
    ///
    /// - **Microsoft Dev Proxy**: "All file paths used in configuration files are relative to the location of the configuration file"
    /// - **Docker Compose**: Resolves paths relative to compose file location  
    /// - **Unix daemons**: Must work after `chdir("/")` so relative paths need a stable anchor
    ///
    /// ## Examples
    ///
    /// ### Config at /etc/kodegend/kodegend.toml
    /// ```toml
    /// pid_file = "./run/daemon.pid"     # → /etc/kodegend/run/daemon.pid
    /// log_dir = "../logs"               # → /etc/logs
    /// ```
    ///
    /// ### Config at /home/user/myapp/kodegend.toml
    /// ```toml
    /// pid_file = "./run/daemon.pid"     # → /home/user/myapp/run/daemon.pid
    /// ```
    ///
    /// ## Why This Matters
    ///
    /// After daemonization, the working directory is `/` on Unix systems.
    /// Without canonicalization, `./run/daemon.pid` would resolve to `/run/daemon.pid`,
    /// which is almost certainly wrong (and may cause permission errors).
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, anyhow::Error> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let mut cfg: ServiceConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        // Determine base directory for path resolution
        // Use config file's parent directory, or current directory if path has no parent
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));

        // ════════════════════════════════════════════════════════════════════
        // Canonicalize Top-Level ServiceConfig Paths
        // ════════════════════════════════════════════════════════════════════

        // pid_file is PathBuf, need to convert through string
        cfg.pid_file = canonicalize_config_path(&cfg.pid_file, base_dir);
        cfg.services_dir = canonicalize_optional_string(&cfg.services_dir, base_dir);
        cfg.log_dir = canonicalize_optional_string(&cfg.log_dir, base_dir);

        // ════════════════════════════════════════════════════════════════════
        // Canonicalize Paths in Each ServiceDefinition
        // ════════════════════════════════════════════════════════════════════

        for service in &mut cfg.services {
            service.working_dir = canonicalize_optional_string(&service.working_dir, base_dir);
            service.log_stdout = canonicalize_optional_string(&service.log_stdout, base_dir);
            service.log_stderr = canonicalize_optional_string(&service.log_stderr, base_dir);
            service.ephemeral_dir = canonicalize_optional_string(&service.ephemeral_dir, base_dir);
            service.watch_dirs = canonicalize_path_vec(&service.watch_dirs, base_dir);
        }

        // ════════════════════════════════════════════════════════════════════
        // Diagnostic Logging
        // ════════════════════════════════════════════════════════════════════

        // Log a warning if the config file path itself is relative
        // (This is unusual but allowed - paths will be resolved relative to config file's location)
        if !path.is_absolute() {
            log::warn!(
                "Config file path is relative: {}. All paths in the config will be \
                 resolved relative to config file's directory: {}",
                path.display(),
                base_dir.display()
            );
        }

        // Validate all service configurations
        // Fail-fast: Reject invalid configs at load time, not during rotation
        for service in &cfg.services {
            service.validate().with_context(|| {
                format!(
                    "Invalid configuration in {} for service '{}'",
                    path.display(),
                    service.name
                )
            })?;
        }

        // Validate working_directory is an absolute path
        if !cfg.working_directory.is_absolute() {
            anyhow::bail!(
                "working_directory must be an absolute path, got: {}",
                cfg.working_directory.display()
            );
        }

        // Check directory exists (warn but don't fail)
        #[cfg(unix)]
        {
            if !cfg.working_directory.exists() {
                log::warn!(
                    "Working directory does not exist: {} (daemon may fail to start)",
                    cfg.working_directory.display()
                );
            }
        }

        cfg.config_file_path = Some(path.to_path_buf());
        Ok(cfg)
    }
}

/// Smart default for services directory based on privilege level
///
/// Uses platform module to get correct path:
/// - Unix (elevated): /etc/kodegend/services
/// - Unix (user): ~/.config/kodegend/services
/// - Windows (elevated): C:\ProgramData\kodegend\services
/// - Windows (user): %APPDATA%\kodegend\services
fn default_services_dir() -> Option<String> {
    use crate::platform;

    let is_elevated = platform::is_elevated();
    let base = if is_elevated {
        platform::system_config_dir()
    } else {
        platform::user_config_dir()
    };
    Some(base.join("services").display().to_string())
}

/// Smart default for log directory based on privilege level
///
/// Uses platform module to get correct path:
/// - Unix (elevated): /var/log/kodegend
/// - Unix (user): ~/.local/state/kodegend/logs
/// - Windows (elevated): C:\ProgramData\kodegend\logs
/// - Windows (user): %LOCALAPPDATA%\kodegend\logs
fn default_log_dir() -> Option<String> {
    use crate::platform;

    let is_elevated = platform::is_elevated();
    Some(platform::log_dir(is_elevated).display().to_string())
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            services_dir: default_services_dir(),
            log_dir: default_log_dir(),
            default_user: Some("kodegend".into()),
            default_group: Some("cyops".into()),
            auto_restart: Some(true),
            services: vec![],
            mcp_bind: Some("0.0.0.0:33399".into()),
            category_servers: ServiceConfig::default_category_servers(),
            daemon_shutdown_timeout_secs: default_daemon_shutdown_timeout(),
            pid_file: default_pid_file(),
            working_directory: default_working_directory(),
            security: SecurityConfig::default(),
            config_file_path: None,
        }
    }
}

/// On‑disk TOML description of a single service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub name: String,
    pub description: Option<String>,
    pub command: String,
    pub working_dir: Option<String>,

    /// Path to redirect stdout to (None = /dev/null for backward compatibility)
    pub log_stdout: Option<String>,
    /// Path to redirect stderr to (None = /dev/null for backward compatibility)
    pub log_stderr: Option<String>,

    #[serde(default)]
    pub env_vars: HashMap<String, String>,
    #[serde(default)]
    pub auto_restart: bool,

    /// Restart policy configuration (replaces simple restart_delay_s)
    /// Uses exponential backoff pattern from kodegen-bundler-release/retry.rs
    #[serde(default)]
    pub restart_policy: RestartPolicy,

    pub user: Option<String>,
    pub group: Option<String>,
    pub restart_delay_s: Option<u64>,
    /// Graceful shutdown timeout in seconds (default: 10)
    /// Time to wait after SIGTERM before sending SIGKILL
    pub shutdown_timeout_secs: Option<u64>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub log_rotation: Option<LogRotationConfig>,
    #[serde(default)]
    pub watch_dirs: Vec<String>,
    pub ephemeral_dir: Option<String>,
    /// Service type (e.g., "autoconfig" for special handling)
    pub service_type: Option<String>,
    pub memfs: Option<MemoryFsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryFsConfig {
    pub size_mb: u32, // clamped at 2048 elsewhere
    pub mount_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub check_type: String, // http | tcp | script
    pub target: String,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub retries: u32,
    pub expected_response: Option<String>,
    #[serde(default)]
    pub on_failure: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    pub max_size_mb: u64,
    pub max_files: u32,
    pub interval_days: u32,
    pub compress: bool,
    pub timestamp: bool,
}

/// Validate log file path
///
/// Checks for common path issues that cause rotation failures or security vulnerabilities.
///
/// # Security Considerations
///
/// - Null byte injection (CWE-158): Prevents path truncation attacks
/// - Directory confusion: Ensures path points to a file, not directory
///
/// # Arguments
///
/// * `path` - The log file path to validate
/// * `field_name` - Config field name (for error messages)
/// * `service_name` - Service name (for error context)
fn validate_log_path(
    path: &str,
    field_name: &str,
    service_name: &str,
) -> Result<(), anyhow::Error> {
    if path.is_empty() {
        anyhow::bail!("Service '{}': {} cannot be empty", service_name, field_name);
    }

    // Security: Prevent null byte injection (CWE-158)
    // Reference: https://cwe.mitre.org/data/definitions/158.html
    if path.contains('\0') {
        anyhow::bail!(
            "Service '{}': {} contains null byte (potential security issue)",
            service_name,
            field_name
        );
    }

    // Validate path is not a directory
    let path_obj = std::path::Path::new(path);
    if path_obj.exists() && path_obj.is_dir() {
        anyhow::bail!(
            "Service '{}': {} '{}' is a directory, must be a file path",
            service_name,
            field_name,
            path
        );
    }

    Ok(())
}

/// Validate log rotation configuration
///
/// Enforces industry-standard constraints based on logrotate, Docker, and systemd practices.
///
/// # Validation Rules
///
/// - `max_size_mb`: Must be >= 1 MB (prevents constant rotation)
/// - `max_size_mb`: Warning if > 10 GB (memory issues during compression)
/// - `max_files`: Must be >= 1 (prevents immediate deletion bug)
/// - `max_files`: Warning if > 1000 (performance implications)
///
/// # References
///
/// - Docker requires max_files >= 1: https://docs.docker.com/config/containers/logging/json-file/
/// - logrotate allows 0 but it's unusual: https://linux.die.net/man/8/logrotate
/// - systemd journald size limits: https://www.freedesktop.org/software/systemd/man/journald.conf.html
fn validate_log_rotation(
    rotation: &LogRotationConfig,
    service_name: &str,
) -> Result<(), anyhow::Error> {
    // Validate max_size_mb
    // Rationale: 0 causes rotation on every call (service.rs:439 check always fails)
    if rotation.max_size_mb == 0 {
        anyhow::bail!(
            "Service '{}': log_rotation.max_size_mb must be at least 1 MB, got 0. \
             This would cause constant rotation cycles and performance degradation.",
            service_name
        );
    }

    // Warning for excessive max_size_mb
    // Rationale: Compression reads entire file into memory (service.rs:506-514)
    // 10 GB cap prevents OOM conditions
    if rotation.max_size_mb > 10_000 {
        log::warn!(
            "Service '{}': log_rotation.max_size_mb is very large ({} MB = {} GB). \
             Compression reads the entire file into memory, which may cause OOM. \
             Consider reducing to <= 10000 MB (10 GB).",
            service_name,
            rotation.max_size_mb,
            rotation.max_size_mb / 1024
        );
    }

    // Validate max_files
    // Rationale: 0 causes immediate deletion of rotated logs (service.rs:520 cleanup starts at max_files+1=1)
    // Follows Docker's requirement: max_files >= 1
    if rotation.max_files == 0 {
        anyhow::bail!(
            "Service '{}': log_rotation.max_files must be at least 1, got 0. \
             This would cause rotated logs to be immediately deleted, losing all log history. \
             Docker and most log rotation systems require max_files >= 1.",
            service_name
        );
    }

    // Warning for excessive max_files
    // Rationale: Large values cause directory entry overhead and slow cleanup loops
    if rotation.max_files > 1000 {
        log::warn!(
            "Service '{}': log_rotation.max_files is very large ({}). \
             This may cause directory entry overhead and slow log rotation. \
             Consider reducing to a more reasonable value (typically 7-30).",
            service_name,
            rotation.max_files
        );
    }

    Ok(())
}

impl ServiceDefinition {
    /// Validate service configuration
    ///
    /// Called during config load to fail-fast on invalid configurations.
    /// Validates log paths and rotation parameters according to industry standards.
    ///
    /// # Errors
    ///
    /// Returns detailed validation errors for:
    /// - Invalid log paths (empty, null bytes, directories)
    /// - Invalid rotation parameters (zero values, excessive sizes)
    ///
    /// # References
    ///
    /// - logrotate validation: https://github.com/logrotate/logrotate
    /// - Docker log validation: https://docs.docker.com/config/containers/logging/
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // Validate log paths
        if let Some(ref path) = self.log_stdout {
            validate_log_path(path, "log_stdout", &self.name)?;
        }
        if let Some(ref path) = self.log_stderr {
            validate_log_path(path, "log_stderr", &self.name)?;
        }

        // Validate log rotation config
        if let Some(ref rotation) = self.log_rotation {
            validate_log_rotation(rotation, &self.name)?;
        }

        Ok(())
    }
}
