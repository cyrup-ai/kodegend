use std::{collections::HashMap, path::PathBuf};

use crate::config::ServiceDefinition;

/// Resource limits for daemon processes.
///
/// Configures operating system resource constraints to prevent runaway processes
/// from destabilizing the system. Applies to macOS (launchd), Linux (systemd),
/// and Windows (Job Objects).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResourceLimits {
    /// Maximum number of open file descriptors (default: 65536)
    pub max_files: u64,

    /// Maximum number of processes/threads (default: 4096)
    pub max_processes: u64,

    /// Maximum memory usage in bytes (default: 1GB = 1073741824)
    ///
    /// Platform notes:
    /// - Linux: Hard limit via cgroups (MemoryMax)
    /// - macOS: Soft limit via RSS, advisory only
    /// - Windows: Hard limit via Job Objects
    pub max_memory_bytes: u64,

    /// Process scheduling priority (default: -5)
    ///
    /// Range: -20 (highest) to 19 (lowest)
    /// - Negative values = higher priority (requires elevated permissions)
    /// - Positive values = lower priority
    /// - Zero = normal priority
    pub nice: i32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_files: 65536,
            max_processes: 4096,
            max_memory_bytes: 1024 * 1024 * 1024, // 1GB
            nice: -5,
        }
    }
}

/// Builder for daemon installation metadata.
///
/// This struct describes the daemon to be installed, including its executable path,
/// arguments, environment variables, and service configuration.
#[derive(Debug, Clone)]
pub struct InstallerBuilder {
    /// Service identifier (systemd unit name, launchd label, Windows service name)
    pub label: String,

    /// Path to the daemon executable
    pub program: PathBuf,

    /// Command line arguments for the daemon
    pub args: Vec<String>,

    /// Environment variables to set for the daemon process
    pub env: HashMap<String, String>,

    /// User account to run the daemon as
    pub run_as_user: String,

    /// Group to run the daemon as (Unix only)
    pub run_as_group: String,

    /// Human-readable description of the service
    pub description: String,

    /// Whether to automatically restart on failure
    pub auto_restart: bool,

    /// Whether the daemon requires network availability
    pub wants_network: bool,

    /// Service definitions to install with the daemon
    pub services: Vec<ServiceDefinition>,

    /// Whether to start service automatically after installation
    pub auto_start: bool,

    /// Resource limits for the daemon process
    ///
    /// Controls file descriptors, process count, memory usage, and scheduling priority.
    /// If None, platform-specific defaults are applied (65536 files, 4096 processes, 1GB memory, nice -5).
    pub resource_limits: Option<ResourceLimits>,

    /// Installation scope (Windows only)
    #[cfg(windows)]
    pub scope: crate::install::installer::windows::paths::InstallScope,
}

impl InstallerBuilder {
    /// Create a new installer configuration.
    ///
    /// # Arguments
    ///
    /// * `label` - Unique identifier for the service (e.g., "my-daemon")
    /// * `program` - Path to the daemon executable
    pub fn new(label: &str, program: impl Into<PathBuf>) -> Self {
        Self {
            label: label.to_string(),
            program: program.into(),
            args: Vec::new(),
            env: HashMap::new(),
            run_as_user: "daemon".into(),
            run_as_group: "daemon".into(),
            description: format!("{label} service"),
            auto_restart: true,
            wants_network: true,
            services: Vec::new(),
            auto_start: true,
            resource_limits: None,
            #[cfg(windows)]
            scope: crate::install::installer::windows::paths::InstallScope::System,
        }
    }

    /// Add multiple command line arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an environment variable.
    /// Used by services.rs:47 (Windows installer path)
    #[allow(dead_code)]
    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    /// Set the user account to run as.
    /// Used by services.rs:69 (macOS installer path)
    #[allow(dead_code)]
    pub fn user(mut self, u: impl Into<String>) -> Self {
        self.run_as_user = u.into();
        self
    }

    /// Set the group to run as (Unix only).
    /// Used by services.rs:61,69 (Linux/macOS installer paths)
    #[allow(dead_code)]
    pub fn group(mut self, g: impl Into<String>) -> Self {
        self.run_as_group = g.into();
        self
    }

    /// Set the service description.
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    /// Enable or disable automatic restart on failure.
    pub fn auto_restart(mut self, v: bool) -> Self {
        self.auto_restart = v;
        self
    }

    /// Specify whether the daemon requires network availability.
    /// Used by services.rs:49 (Windows installer path)
    #[allow(dead_code)]
    pub fn network(mut self, v: bool) -> Self {
        self.wants_network = v;
        self
    }

    /// Add a service definition to install with the daemon.
    /// Used by services.rs:54 (Windows installer path)
    #[allow(dead_code)]
    pub fn service(self, service: ServiceDefinition) -> Self {
        let mut services = self.services;
        services.push(service);
        Self { services, ..self }
    }

    /// Set whether to start service automatically after installation.
    pub fn auto_start(mut self, auto_start: bool) -> Self {
        self.auto_start = auto_start;
        self
    }

    /// Set the installation scope (Windows only).
    #[cfg(windows)]
    pub fn with_scope(mut self, scope: crate::install::installer::windows::paths::InstallScope) -> Self {
        self.scope = scope;
        self
    }
}
