use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about = "kodegen service manager")]
pub struct Args {
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
    Start,
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
