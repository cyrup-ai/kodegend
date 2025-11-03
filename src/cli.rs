use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about = "kodegen service manager")]
pub struct Args {
    /// Sub‑commands (run, install, etc.)
    #[command(subcommand)]
    pub sub: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Normal daemon operation (default if no sub‑command)
    Run {
        /// Stay in foreground even on plain Unix
        #[arg(long)]
        foreground: bool,

        /// Path to configuration file
        #[arg(long, short = 'c')]
        config: Option<String>,

        /// Use system-wide config (/etc/kodegend/kodegend.toml)
        #[arg(long, conflicts_with = "config")]
        system: bool,
    },
    /// Check daemon status (Exit 0 = running, 1 = stopped)
    Status,
    /// Start the daemon service (Exit 0 = success, 1 = failed)
    Start,
    /// Stop the daemon service (Exit 0 = success, 1 = failed)
    Stop,
    /// Restart the daemon service (Exit 0 = success, 1 = failed)
    Restart,
}
