//! macOS platform implementation using osascript and launchd.

use std::{path::PathBuf, process::Command};

use super::{builder::CommandBuilder, InstallerBuilder, InstallerError};

mod executor;
mod helper;
mod plist;

pub(crate) struct PlatformExecutor;

impl PlatformExecutor {
    pub fn install(b: InstallerBuilder) -> Result<(), InstallerError> {
        // Initialize helper path if not already set
        helper::ensure_helper_path()?;

        // System daemons always use system directories
        let plist_dir = PathBuf::from("/Library/LaunchDaemons");
        let bin_dir = PathBuf::from("/usr/local/bin");
        let needs_sudo = true;

        // First, copy the binary to temp so elevated context can access it
        let temp_path = std::env::temp_dir().join(&b.label);
        std::fs::copy(&b.program, &temp_path)
            .map_err(|e| InstallerError::System(format!("Failed to copy binary to temp: {e}")))?;

        let plist_content = plist::generate_plist(&b)?;

        // Convert paths to strings with error handling
        let plist_dir_str = plist_dir
            .to_str()
            .ok_or_else(|| InstallerError::System("Invalid plist directory path".to_string()))?;
        let bin_dir_str = bin_dir
            .to_str()
            .ok_or_else(|| InstallerError::System("Invalid bin directory path".to_string()))?;

        // Build the installation commands using CommandBuilder
        let mkdir_cmd = CommandBuilder::new("mkdir").args([
            "-p",
            plist_dir_str,
            bin_dir_str,
            &format!("/var/log/{}", b.label),
        ]);

        let bin_path = bin_dir.join(&b.label);
        let bin_path_str = bin_path
            .to_str()
            .ok_or_else(|| InstallerError::System("Invalid binary path".to_string()))?;
        let temp_path_str = temp_path
            .to_str()
            .ok_or_else(|| InstallerError::System("Invalid temp path".to_string()))?;

        let cp_cmd = CommandBuilder::new("cp").args([temp_path_str, bin_path_str]);

        let chown_cmd = if needs_sudo {
            CommandBuilder::new("chown").args(["root:wheel", bin_path_str])
        } else {
            // For user installs, no chown needed
            CommandBuilder::new("true").args::<[&str; 0], &str>([])
        };

        let chmod_cmd = CommandBuilder::new("chmod").args(["755", bin_path_str]);

        let rm_cmd = CommandBuilder::new("rm").args(["-f", temp_path_str]);

        // Write files to temp location first, then move them in elevated context
        let temp_plist = std::env::temp_dir().join(format!("{}.plist", b.label));
        std::fs::write(&temp_plist, &plist_content)
            .map_err(|e| InstallerError::System(format!("Failed to write temp plist: {e}")))?;

        let plist_file = plist_dir.join(format!("{}.plist", b.label));
        let plist_file_str = plist_file
            .to_str()
            .ok_or_else(|| InstallerError::System("Invalid plist file path".to_string()))?;
        let temp_plist_str = temp_plist
            .to_str()
            .ok_or_else(|| InstallerError::System("Invalid temp plist path".to_string()))?;

        let mut script = format!(
            "set -e\n{}",
            executor::command_to_script(&mkdir_cmd)
        );
        script.push_str(&format!(" && {}", executor::command_to_script(&cp_cmd)));
        if needs_sudo {
            script.push_str(&format!(" && {}", executor::command_to_script(&chown_cmd)));
        }
        script.push_str(&format!(" && {}", executor::command_to_script(&chmod_cmd)));
        script.push_str(&format!(" && {}", executor::command_to_script(&rm_cmd)));
        script.push_str(&format!(" && mv {temp_plist_str} {plist_file_str}"));

        // Set plist permissions (only for system-wide installs)
        if needs_sudo {
            let plist_perms_chown =
                CommandBuilder::new("chown").args(["root:wheel", plist_file_str]);
            let plist_perms_chmod = CommandBuilder::new("chmod").args(["644", plist_file_str]);

            script.push_str(&format!(
                " && {}",
                executor::command_to_script(&plist_perms_chown)
            ));
            script.push_str(&format!(
                " && {}",
                executor::command_to_script(&plist_perms_chmod)
            ));
        }

        // Create services directory
        let services_dir = CommandBuilder::new("mkdir").args(["-p", "/etc/kodegend/services"]);

        script.push_str(&format!(
            " && {}",
            executor::command_to_script(&services_dir)
        ));

        // Add service definitions using CommandBuilder
        if !b.services.is_empty() {
            for service in &b.services {
                let service_toml = toml::to_string_pretty(service).map_err(|e| {
                    InstallerError::System(format!("Failed to serialize service: {e}"))
                })?;

                // Write service file to temp first
                let temp_service = std::env::temp_dir().join(format!("{}.toml", service.name));
                std::fs::write(&temp_service, &service_toml).map_err(|e| {
                    InstallerError::System(format!("Failed to write temp service: {e}"))
                })?;
                let temp_service_str = temp_service.to_str().ok_or_else(|| {
                    InstallerError::System("Invalid temp service path".to_string())
                })?;

                let service_file = format!("/etc/kodegend/services/{}.toml", service.name);
                script.push_str(&format!(" && mv {temp_service_str} {service_file}"));

                // Set service file permissions using CommandBuilder
                let service_perms_chown =
                    CommandBuilder::new("chown").args(["root:wheel", &service_file]);

                let service_perms_chmod = CommandBuilder::new("chmod").args(["644", &service_file]);

                script.push_str(&format!(
                    " && {}",
                    executor::command_to_script(&service_perms_chown)
                ));
                script.push_str(&format!(
                    " && {}",
                    executor::command_to_script(&service_perms_chmod)
                ));
            }
        }

        // Load the daemon using CommandBuilder (only if auto_start is enabled)
        if b.auto_start {
            let load_daemon = CommandBuilder::new("launchctl").args(["load", "-w", plist_file_str]);

            script.push_str(&format!(
                " && {}",
                executor::command_to_script(&load_daemon)
            ));
        }

        // For user installs, run script without helper (no sudo needed)
        if needs_sudo {
            executor::run_helper(&script)
        } else {
            // User install - run directly with sh
            let output = Command::new("sh")
                .arg("-c")
                .arg(&script)
                .output()
                .map_err(|e| {
                    InstallerError::System(format!("Failed to execute install script: {e}"))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(InstallerError::System(format!(
                    "Installation script failed: {stderr}"
                )));
            }

            Ok(())
        }
    }

    pub fn uninstall(label: &str) -> Result<(), InstallerError> {
        let script = format!(
            r"
            set -e
            # Unload daemon if running
            launchctl unload -w /Library/LaunchDaemons/{label}.plist 2>/dev/null || true

            # Remove files
            rm -f /Library/LaunchDaemons/{label}.plist
            rm -f /usr/local/bin/{label}
            rm -rf /var/log/{label}
        "
        );

        executor::run_helper(&script)
    }
}
