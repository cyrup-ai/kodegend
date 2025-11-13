//! Kodegen installer binary
//!
//! This is a thin wrapper around the kodegend::install module.
//! The actual installation logic lives in lib.rs.
//!
//! This binary preserves the standalone installer behavior for users who
//! want to manually install/uninstall Kodegen.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    kodegend::install::install_interactive().await
}
