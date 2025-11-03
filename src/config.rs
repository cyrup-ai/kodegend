use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Top‑level daemon configuration (mirrors original defaults).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub services_dir: Option<String>,
    pub log_dir: Option<String>,
    pub default_user: Option<String>,
    pub default_group: Option<String>,
    pub auto_restart: Option<bool>,
    pub services: Vec<ServiceDefinition>,
    /// MCP Streamable HTTP transport binding (host:port)
    pub mcp_bind: Option<String>,
    /// Category HTTP servers (14 tool categories)
    #[serde(default)]
    pub category_servers: Vec<CategoryServerConfig>,
}

fn default_true() -> bool {
    true
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
    let search_paths = vec![
        PathBuf::from("C:\\ProgramData\\Kodegen\\certs"),
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\temp"))
            .join("Kodegen")
            .join("certs"),
    ];

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
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            services_dir: Some("/etc/kodegend/services".into()),
            log_dir: Some("/var/log/kodegend".into()),
            default_user: Some("kodegend".into()),
            default_group: Some("cyops".into()),
            auto_restart: Some(true),
            services: vec![],
            mcp_bind: Some("0.0.0.0:33399".into()),
            category_servers: ServiceConfig::default_category_servers(),
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
    #[serde(default)]
    pub env_vars: HashMap<String, String>,
    #[serde(default)]
    pub auto_restart: bool,
    pub user: Option<String>,
    pub group: Option<String>,
    pub restart_delay_s: Option<u64>,
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
