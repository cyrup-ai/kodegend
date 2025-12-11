use clap::{Parser, Subcommand};
use std::path::PathBuf;
use serde_json::json;

#[derive(Parser, Debug)]
#[command(version, about = "kodegen service manager")]
pub struct Args {
    /// Path to config file (overrides default search path)
    #[arg(long, short = 'c', global = true)]
    pub config: Option<PathBuf>,
    
    /// Override log directory
    #[arg(long, global = true)]
    pub log_dir: Option<String>,
    
    /// Override MCP bind address
    #[arg(long, global = true)]
    pub mcp_bind: Option<String>,
    
    /// Override services directory
    #[arg(long, global = true)]
    pub services_dir: Option<String>,
    
    /// Sub‑commands (uninstall, status, etc.)
    #[command(subcommand)]
    pub sub: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Uninstall kodegend daemon and clean up system configuration
    Uninstall,
    /// Check daemon status (Exit 0 = running, 1 = stopped)
    Status,
    /// Start the daemon service (Exit 0 = success, 1 = failed)
    Start {
        /// Config file permission validation mode
        ///
        /// - strict: Reject configs with unsafe permissions (default, production)
        /// - warn: Log warnings but continue (development only)
        /// - ignore: Skip permission checks (DANGEROUS - CI/testing only)
        #[arg(long, default_value = "strict", value_parser = ["strict", "warn", "ignore"])]
        config_permissions: String,
    },
    /// Stop the daemon service (Exit 0 = success, 1 = failed)
    Stop,
    /// Restart the daemon service (Exit 0 = success, 1 = failed)
    Restart,
    /// Query vulnerability scan results
    #[command(name = "vulns")]
    Vulnerabilities {
        /// Filter by pattern (RUSTSEC ID, package name, or description)
        #[arg(long)]
        filter: Option<String>,

        /// Filter by specific package name (exact match)
        #[arg(long)]
        package: Option<String>,

        /// Show only critical/high severity
        #[arg(long)]
        critical_only: bool,
    },
}

impl Args {
    /// Convert CLI arguments to JSON overrides for config merging
    pub fn to_overrides(&self) -> serde_json::Value {
        let mut overrides = serde_json::Map::new();
        
        if let Some(ref log_dir) = self.log_dir {
            overrides.insert("log_dir".to_string(), json!(log_dir));
        }
        if let Some(ref mcp_bind) = self.mcp_bind {
            overrides.insert("mcp_bind".to_string(), json!(mcp_bind));
        }
        if let Some(ref services_dir) = self.services_dir {
            overrides.insert("services_dir".to_string(), json!(services_dir));
        }
        
        serde_json::Value::Object(overrides)
    }
}
