//! Rust toolchain management for Kodegen installation
//!
//! This module handles installation and verification of the Rust nightly toolchain
//! without modifying the user's global default toolchain.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{info, warn};
use tokio::process::Command;
use tokio::time::timeout;

// Timeout constants
const RUSTUP_INSTALL_TIMEOUT: Duration = Duration::from_secs(1800); // 30 minutes
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes default

/// Verify that rust-toolchain.toml exists and specifies nightly channel
///
/// This function checks that the project root contains a rust-toolchain.toml file
/// that specifies the nightly channel. The presence of this file ensures that cargo
/// will automatically use nightly when building this project, without requiring any
/// changes to the user's global default toolchain.
pub fn verify_rust_toolchain_file() -> Result<()> {
    // Get the project root (3 levels up from packages/bundler-install/src/install)
    let current_file = std::path::Path::new(file!());
    let project_root = current_file
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Could not determine project root"))?;

    let toolchain_file = project_root.join("rust-toolchain.toml");

    if !toolchain_file.exists() {
        return Err(anyhow::anyhow!(
            "Missing rust-toolchain.toml in project root!\n\
             This file is required to specify the nightly toolchain for this project.\n\
             Expected location: {}",
            toolchain_file.display()
        ));
    }

    // Read and verify the file specifies nightly channel
    let content = fs::read_to_string(&toolchain_file)
        .with_context(|| format!("Failed to read {}", toolchain_file.display()))?;

    if !content.contains("channel") || !content.contains("nightly") {
        return Err(anyhow::anyhow!(
            "rust-toolchain.toml doesn't specify nightly channel!\n\
             The file must contain: channel = \"nightly\"\n\
             File location: {}",
            toolchain_file.display()
        ));
    }

    info!(
        "Verified rust-toolchain.toml specifies nightly at {}",
        toolchain_file.display()
    );
    Ok(())
}

/// Ensure Rust nightly toolchain is installed without changing global default
///
/// This function checks if Rust is installed and ensures the nightly toolchain
/// is available. It NEVER changes the user's global default toolchain, which would
/// be destructive to their existing Rust projects.
///
/// The function follows these principles:
/// 1. Only install toolchains, never change the default
/// 2. Preserve the user's existing default toolchain
/// 3. Rely on rust-toolchain.toml to activate nightly for this project
/// 4. Provide clear feedback about what was done
pub async fn ensure_rust_toolchain() -> Result<()> {
    // Check if rustc is installed
    let rustc_check = timeout(
        COMMAND_TIMEOUT,
        Command::new("rustc").arg("--version").output(),
    )
    .await;

    match rustc_check {
        Ok(Ok(output)) if output.status.success() => {
            // Rust is installed, get current default
            let default_output = timeout(
                COMMAND_TIMEOUT,
                Command::new("rustup").args(["default"]).output(),
            )
            .await
            .context("Rustup default check timed out after 5 minutes")?
            .context("Failed to check rustup default toolchain")?;

            if default_output.status.success() {
                let default_toolchain = String::from_utf8_lossy(&default_output.stdout);
                let default_name = default_toolchain
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().next())
                    .unwrap_or("unknown");

                info!("Rust already installed: {default_name}");

                // Check if nightly is installed
                let list_output = timeout(
                    COMMAND_TIMEOUT,
                    Command::new("rustup").args(["toolchain", "list"]).output(),
                )
                .await
                .context("Rustup toolchain list timed out after 5 minutes")?
                .context("Failed to list rustup toolchains")?;

                if !list_output.status.success() {
                    return Err(anyhow::anyhow!("Failed to list rustup toolchains"));
                }

                let toolchains = String::from_utf8_lossy(&list_output.stdout);

                if toolchains.lines().any(|line| line.contains("nightly")) {
                    info!("Nightly toolchain already available");
                } else {
                    // Install nightly without changing default
                    info!(
                        "Installing nightly toolchain for kodegen (this may take up to 30 minutes)..."
                    );

                    let install_output = timeout(
                        RUSTUP_INSTALL_TIMEOUT,
                        Command::new("rustup")
                            .args(["toolchain", "install", "nightly"])
                            .output(),
                    )
                    .await
                    .context("Rustup nightly install timed out after 30 minutes")?
                    .context("Failed to install nightly toolchain")?;

                    if !install_output.status.success() {
                        let stderr = String::from_utf8_lossy(&install_output.stderr);
                        return Err(anyhow::anyhow!(
                            "Failed to install nightly toolchain: {stderr}"
                        ));
                    }

                    info!("Nightly toolchain installed");
                }

                info!(
                    "Project will use nightly via rust-toolchain.toml (global default unchanged: {default_name})"
                );
            } else {
                warn!("Could not determine current default toolchain, but Rust is installed");
            }
        }
        Ok(_) | Err(_) => {
            // Rust not installed, install with stable as default and nightly as additional
            info!("Installing Rust toolchain (this may take up to 30 minutes)...");

            // Download and run rustup installer
            let rustup_init = if cfg!(unix) {
                timeout(
                    RUSTUP_INSTALL_TIMEOUT,
                    Command::new("sh")
                        .args([
                            "-c",
                            "curl --proto '=https' --tlsv1.2 -sSf --max-time 300 --connect-timeout 30 https://sh.rustup.rs | sh -s -- -y --default-toolchain stable"
                        ])
                        .output()
                ).await
                    .context("Rustup installation timed out after 30 minutes")?
                    .context("Failed to download and run rustup installer")?
            } else {
                return Err(anyhow::anyhow!(
                    "Automatic Rust installation only supported on Unix systems"
                ));
            };

            if !rustup_init.status.success() {
                let stderr = String::from_utf8_lossy(&rustup_init.stderr);
                return Err(anyhow::anyhow!("Failed to install Rust: {stderr}"));
            }

            // Get path to rustup binary (it's not in current process PATH yet)
            let home_dir = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

            let cargo_env = home_dir.join(".cargo").join("env");
            if cargo_env.exists() {
                info!("Rust stable installed: {}", cargo_env.display());
            }

            // Use full path to rustup since it's not in current process PATH yet
            let rustup_path = home_dir.join(".cargo").join("bin").join("rustup");

            if !rustup_path.exists() {
                return Err(anyhow::anyhow!(
                    "Rustup binary not found at expected location: {}",
                    rustup_path.display()
                ));
            }

            // Install nightly as additional toolchain using full path
            info!("Installing nightly toolchain for kodegen (this may take up to 30 minutes)...");

            let install_nightly = timeout(
                RUSTUP_INSTALL_TIMEOUT,
                Command::new(&rustup_path)
                    .args(["toolchain", "install", "nightly"])
                    .output(),
            )
            .await
            .context("Nightly toolchain installation timed out after 30 minutes")?
            .context("Failed to install nightly toolchain")?;

            if !install_nightly.status.success() {
                let stderr = String::from_utf8_lossy(&install_nightly.stderr);
                return Err(anyhow::anyhow!(
                    "Failed to install nightly toolchain: {stderr}"
                ));
            }

            info!("Rust stable installed as default");
            info!("Nightly available for kodegen");
        }
    }

    Ok(())
}
