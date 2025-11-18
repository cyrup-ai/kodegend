use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

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
    
    /// Path to config file (not serialized, used for reload)
    #[serde(skip)]
    pub config_file_path: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

/// Smart PID file default based on user permissions and platform conventions
fn default_pid_file() -> PathBuf {
    use crate::platform;

    let is_elevated = platform::is_elevated();
    platform::runtime_dir(is_elevated).join("kodegend.pid")
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
            max_attempts: Some(5),       // systemd default
            initial_delay_ms: 100,        // systemd default
            max_delay_ms: 60_000,         // Docker default (1 minute)
            backoff_multiplier: 2.0,      // Industry standard (see retry.rs:103)
            success_window_secs: 60,      // Reset after 1 minute of success
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
    use std::path::PathBuf;

    // Standard certificate file names
    const CERT_FILE: &str = "server.crt";
    const KEY_FILE: &str = "server.key";

    // Build search paths using conditional compilation
    #[cfg(target_os = "macos")]
    let search_paths = vec![
        PathBuf::from("/usr/local/var/kodegen/certs"),
        dirs::data_local_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp")))
            .join("kodegen")
            .join("certs"),
    ];

    #[cfg(target_os = "linux")]
    let search_paths = vec![
        PathBuf::from("/var/lib/kodegen/certs"),
        dirs::data_local_dir()
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("/tmp"))
                    .join(".local")
                    .join("share")
            })
            .join("kodegen")
            .join("certs"),
    ];

    #[cfg(target_os = "windows")]
    let search_paths = {
        use crate::install::installer::windows::paths;
        vec![
            paths::cert_dir(),
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("C:\\temp"))
                .join("Kodegen")
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
        vec![
            CategoryServerConfig {
                name: "browser".to_string(),
                binary: "kodegen-browser".to_string(),
                port: 30438,
                enabled: true,
            },
            CategoryServerConfig {
                name: "citescrape".to_string(),
                binary: "kodegen-citescrape".to_string(),
                port: 30439,
                enabled: true,
            },
            CategoryServerConfig {
                name: "claude-agent".to_string(),
                binary: "kodegen-claude-agent".to_string(),
                port: 30440,
                enabled: true,
            },
            CategoryServerConfig {
                name: "config".to_string(),
                binary: "kodegen-config".to_string(),
                port: 30441,
                enabled: true,
            },
            CategoryServerConfig {
                name: "database".to_string(),
                binary: "kodegen-database".to_string(),
                port: 30442,
                enabled: true,
            },
            CategoryServerConfig {
                name: "filesystem".to_string(),
                binary: "kodegen-filesystem".to_string(),
                port: 30443,
                enabled: true,
            },
            CategoryServerConfig {
                name: "git".to_string(),
                binary: "kodegen-git".to_string(),
                port: 30444,
                enabled: true,
            },
            CategoryServerConfig {
                name: "github".to_string(),
                binary: "kodegen-github".to_string(),
                port: 30445,
                enabled: true,
            },
            CategoryServerConfig {
                name: "introspection".to_string(),
                binary: "kodegen-introspection".to_string(),
                port: 30446,
                enabled: true,
            },
            CategoryServerConfig {
                name: "process".to_string(),
                binary: "kodegen-process".to_string(),
                port: 30447,
                enabled: true,
            },
            CategoryServerConfig {
                name: "prompt".to_string(),
                binary: "kodegen-prompt".to_string(),
                port: 30448,
                enabled: true,
            },
            CategoryServerConfig {
                name: "reasoner".to_string(),
                binary: "kodegen-reasoner".to_string(),
                port: 30449,
                enabled: true,
            },
            CategoryServerConfig {
                name: "sequential-thinking".to_string(),
                binary: "kodegen-sequential-thinking".to_string(),
                port: 30450,
                enabled: true,
            },
            CategoryServerConfig {
                name: "terminal".to_string(),
                binary: "kodegen-terminal".to_string(),
                port: 30451,
                enabled: true,
            },
            CategoryServerConfig {
                name: "candle-agent".to_string(),
                binary: "kodegen-candle-agent".to_string(),
                port: 30452,
                enabled: true,
            },
        ]
    }
    
    /// Load config from file and remember the path for reload
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, anyhow::Error> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        
        let mut cfg: ServiceConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        
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
            pid_file: default_pid_file(),
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
