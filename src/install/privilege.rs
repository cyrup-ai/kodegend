//! Privilege escalation and sudo operations for kodegen installer
//!
//! This module handles operations that require elevated privileges (root/admin),
//! including certificate installation, hosts file updates, and binary installation
//! to system directories.

use anyhow::{Context, Result};

/// Build platform-specific certificate import command
pub fn get_cert_import_command(cert_path: &std::path::Path) -> String {
    #[cfg(target_os = "macos")]
    {
        format!(
            "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '{}'",
            cert_path.display()
        )
    }

    #[cfg(target_os = "linux")]
    {
        let cert_name = cert_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("kodegen-mcp.crt");
        format!(
            "cp '{}' /usr/local/share/ca-certificates/{} && update-ca-certificates",
            cert_path.display(),
            cert_name
        )
    }

    #[cfg(target_os = "windows")]
    {
        format!(
            "certutil -addstore -f Root '{}'",
            cert_path.display()
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        format!("echo 'Certificate import not supported on this platform: {}'", cert_path.display())
    }
}

/// Execute ONLY the privileged operations using a minimal sudo script (Phase 3)
///
/// This function is called AFTER all unprivileged operations (downloads, extraction, staging)
/// are complete. It performs only the operations that genuinely require root privileges:
/// - Copy binaries from staging to /usr/local/bin
/// - Set ownership and permissions
/// - Update /etc/hosts
/// - Import certificates to system trust store
///
/// Security: By deferring privilege escalation until this point, we ensure that network
/// operations, downloads, and extraction all run as an unprivileged user, dramatically
/// reducing the attack surface.
pub async fn install_with_elevated_privileges(
    staging_dir: &std::path::Path,
    cert_content: Option<&str>,
    data_dir: &std::path::Path,
) -> Result<()> {
    use std::process::Command;

    eprintln!("🔐 Installing to system (requires sudo)...");
    eprintln!("   You may be prompted for your password");

    // Get list of files in staging directory
    let staged_files: Vec<String> = std::fs::read_dir(staging_dir)
        .with_context(|| format!("Failed to read staging directory: {}", staging_dir.display()))?
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                let path = e.path();
                if path.is_file() {
                    Some(path.display().to_string())
                } else {
                    None
                }
            })
        })
        .collect();

    if staged_files.is_empty() {
        return Err(anyhow::anyhow!("No files found in staging directory"));
    }

    // Build minimal script with ONLY privileged operations
    let mut script = String::from("#!/bin/sh\nset -e\n\n");

    // Copy verified binaries from staging to /usr/local/bin
    script.push_str("echo 'Installing binaries...'\n");

    #[cfg(unix)]
    {
        script.push_str("mkdir -p /usr/local/bin\n");
        for file in &staged_files {
            script.push_str(&format!("cp -f '{}' /usr/local/bin/\n", file));
        }

        // Set ownership and permissions
        script.push_str("\n# Set ownership and permissions\n");
        script.push_str("chown root:wheel /usr/local/bin/kodegend 2>/dev/null || chown root:root /usr/local/bin/kodegend\n");
        script.push_str("chmod 755 /usr/local/bin/kodegend\n");
        script.push_str("chmod 755 /usr/local/bin/kodegen 2>/dev/null || true\n");
    }

    #[cfg(windows)]
    {
        script.push_str("mkdir \"C:\\Program Files\\Kodegen\" 2>nul || echo Directory exists\n");
        for file in &staged_files {
            script.push_str(&format!("copy /Y \"{}\" \"C:\\Program Files\\Kodegen\\\"\n", file));
        }
    }

    // Update hosts file (idempotent)
    #[cfg(unix)]
    {
        script.push_str("\n# Update /etc/hosts\n");
        script.push_str("echo 'Updating /etc/hosts...'\n");
        script.push_str("if ! grep -q '127.0.0.1 mcp.kodegen.ai' /etc/hosts 2>/dev/null; then\n");
        script.push_str("    echo '127.0.0.1 mcp.kodegen.ai' >> /etc/hosts\n");
        script.push_str("fi\n");
    }

    // Import certificate to system trust store (if provided)
    if let Some(cert_content) = cert_content {
        script.push_str("\n# Import certificate\n");
        script.push_str("echo 'Importing certificate...'\n");

        // Extract certificate-only part (remove private key)
        let cert_only = if let Some(key_start) = cert_content.find("-----BEGIN PRIVATE KEY-----") {
            &cert_content[..key_start]
        } else {
            cert_content
        };

        // Create secure temp file with process ID for uniqueness
        let temp_cert_path = format!("/tmp/kodegen_cert_import_{}.crt", std::process::id());

        // Write certificate to secure temp location
        tokio::fs::write(&temp_cert_path, cert_only)
            .await
            .context("Failed to write temp certificate")?;

        // Set restrictive permissions immediately (owner-only read/write)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&temp_cert_path)
                .await
                .context("Failed to get temp cert metadata")?
                .permissions();
            perms.set_mode(0o600); // Owner read/write only
            tokio::fs::set_permissions(&temp_cert_path, perms)
                .await
                .context("Failed to set temp cert permissions")?;
        }

        // Add import command to script
        script.push_str(&get_cert_import_command(std::path::Path::new(&temp_cert_path)));
        script.push('\n');

        // Clean up temp file in script (after import completes)
        script.push_str(&format!("rm -f '{}'\n", temp_cert_path));
    }

    // Install service files (use data_dir for service file location)
    #[cfg(target_os = "macos")]
    {
        let plist_src = data_dir.join("com.kodegen.daemon.plist");
        if plist_src.exists() {
            script.push_str("\n# Install launchd service\n");
            script.push_str("echo 'Installing service...'\n");
            script.push_str(&format!(
                "cp '{}' /Library/LaunchDaemons/com.kodegen.daemon.plist\n",
                plist_src.display()
            ));
            script.push_str("launchctl load /Library/LaunchDaemons/com.kodegen.daemon.plist 2>/dev/null || true\n");
        }
    }

    #[cfg(target_os = "linux")]
    {
        let service_src = data_dir.join("kodegend.service");
        if service_src.exists() {
            script.push_str("\n# Install systemd service\n");
            script.push_str("echo 'Installing service...'\n");
            script.push_str(&format!(
                "cp '{}' /etc/systemd/system/kodegend.service\n",
                service_src.display()
            ));
            script.push_str("systemctl daemon-reload\n");
            script.push_str("systemctl enable kodegend 2>/dev/null || true\n");
        }
    }

    script.push_str("\necho '✓ Privileged operations complete'\n");

    // Execute ONLY this minimal script with sudo
    #[cfg(unix)]
    {
        let status = Command::new("sudo")
            .arg("sh")
            .arg("-c")
            .arg(&script)
            .status()
            .context("Failed to execute sudo")?;

        if !status.success() {
            return Err(anyhow::anyhow!(
                "Privileged installation failed with exit code: {}",
                status.code().unwrap_or(-1)
            ));
        }
    }

    #[cfg(windows)]
    {
        // On Windows, use runas or similar (simplified for now)
        let status = Command::new("cmd")
            .arg("/C")
            .arg(&script)
            .status()
            .context("Failed to execute privileged operations")?;

        if !status.success() {
            return Err(anyhow::anyhow!("Privileged installation failed"));
        }
    }

    // Cleanup staging directory
    std::fs::remove_dir_all(staging_dir)
        .with_context(|| format!("Failed to cleanup staging directory: {}", staging_dir.display()))?;

    Ok(())
}
