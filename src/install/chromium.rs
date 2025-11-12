//! Chromium browser installation for kodegen citescrape tools
//!
//! This module handles downloading and installing the managed Chromium browser
//! required for web automation and citescrape functionality.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;

/// Read Chromium installation timeout from environment or use default
///
/// Reads KODEGEN_CHROMIUM_TIMEOUT environment variable (seconds).
/// Falls back to 900 seconds (15 minutes) if not set or invalid.
pub fn get_chromium_install_timeout() -> Duration {
    std::env::var("KODEGEN_CHROMIUM_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(900))
}

/// Install Chromium using citescrape's `download_managed_browser`
///
/// Chromium is REQUIRED - installation fails if this fails.
/// Timeout can be configured via KODEGEN_CHROMIUM_TIMEOUT environment variable (seconds).
pub async fn install_chromium() -> Result<PathBuf> {
    use kodegen_tools_citescrape::download_managed_browser;
    use std::io::Write;
    use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

    // Get timeout from environment or use default
    let timeout_duration = get_chromium_install_timeout();

    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(stdout, "\n📥 Installing Chromium...");
    let _ = stdout.reset();
    let _ = writeln!(stdout, "   This may take 30-60 seconds (~100MB download)");
    let _ = writeln!(stdout, "   Timeout: {} seconds", timeout_duration.as_secs());

    let chromium_path = match timeout(timeout_duration, download_managed_browser()).await {
        Ok(result) => result
            .context("Failed to download Chromium - check network connection and disk space")?,
        Err(_) => anyhow::bail!(
            "Timeout installing Chromium after {} seconds ({} minutes). \
             Chromium is ~100MB and required for citescrape functionality. \
             Increase timeout with: KODEGEN_CHROMIUM_TIMEOUT={} {}",
            timeout_duration.as_secs(),
            timeout_duration.as_secs() / 60,
            timeout_duration.as_secs() * 2,
            std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_else(|| "kodegen_install".to_string())
        ),
    };

    // Verify installation
    if !chromium_path.exists() {
        anyhow::bail!("Chromium path not found: {}", chromium_path.display());
    }

    Ok(chromium_path)
}
