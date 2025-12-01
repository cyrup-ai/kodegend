//! Service configuration for installer

use std::path::PathBuf;

/// Service configuration for installer
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Service name (read in services.rs:103, 97, 128 during conversion)
    pub name: String,
    /// Service description (read in services.rs:104)
    pub description: String,
    /// Command to execute (read in services.rs:90, 92)
    pub command: String,
    /// Command arguments (read in services.rs:92)
    pub args: Vec<String>,
    /// Working directory (read in services.rs:106-109)
    pub working_dir: Option<PathBuf>,
    /// Environment variables (read in services.rs:76-84, 110)
    pub env_vars: std::collections::HashMap<String, String>,
    /// Auto-restart on failure (read in services.rs:111)
    pub auto_restart: bool,
    /// Service user (read in services.rs:114)
    pub user: Option<String>,
    /// Service group (read in services.rs:115)
    pub group: Option<String>,
    /// Service dependencies (read in services.rs:118)
    pub dependencies: Vec<String>,
}

impl ServiceConfig {
    /// Create new service config with optimized initialization
    #[allow(dead_code)]
    pub fn new(name: String, command: String) -> Self {
        Self {
            name,
            description: String::new(),
            command,
            args: Vec::new(),
            working_dir: None,
            env_vars: std::collections::HashMap::new(),
            auto_restart: true,
            user: None,
            group: None,
            dependencies: Vec::new(),
        }
    }

    /// Set description
    #[allow(dead_code)]
    pub fn description(mut self, desc: String) -> Self {
        self.description = desc;
        self
    }

    /// Add argument
    #[allow(dead_code)]
    pub fn arg(mut self, arg: String) -> Self {
        self.args.push(arg);
        self
    }

    /// Add multiple arguments
    #[allow(dead_code)]
    pub fn args(mut self, args: Vec<String>) -> Self {
        self.args.extend(args);
        self
    }

    /// Set working directory
    #[allow(dead_code)]
    pub fn working_dir(mut self, dir: PathBuf) -> Self {
        self.working_dir = Some(dir);
        self
    }

    /// Add environment variable
    #[allow(dead_code)]
    pub fn env(mut self, key: String, value: String) -> Self {
        self.env_vars.insert(key, value);
        self
    }

    /// Set auto restart
    #[allow(dead_code)]
    pub fn auto_restart(mut self, restart: bool) -> Self {
        self.auto_restart = restart;
        self
    }

    /// Set user
    #[allow(dead_code)]
    pub fn user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    /// Set group
    #[allow(dead_code)]
    pub fn group(mut self, group: String) -> Self {
        self.group = Some(group);
        self
    }

    /// Add dependency
    #[allow(dead_code)]
    pub fn depends_on(mut self, service: String) -> Self {
        self.dependencies.push(service);
        self
    }
}
