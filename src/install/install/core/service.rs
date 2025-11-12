//! Service configuration for installer

use std::path::PathBuf;

/// Service configuration for installer
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub description: String,
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub env_vars: std::collections::HashMap<String, String>,
    pub auto_restart: bool,
    pub user: Option<String>,
    pub group: Option<String>,
    pub dependencies: Vec<String>,
}

impl ServiceConfig {
    /// Create new service config with optimized initialization
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
    pub fn env(mut self, key: String, value: String) -> Self {
        self.env_vars.insert(key, value);
        self
    }

    /// Set auto restart
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
    pub fn depends_on(mut self, service: String) -> Self {
        self.dependencies.push(service);
        self
    }
}
