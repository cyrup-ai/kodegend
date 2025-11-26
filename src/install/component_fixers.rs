//! Individual component fix functions
//!
//! Each function fixes a single component independently.
//! Privilege escalation is collected ONCE and shared across all operations.

use anyhow::Result;
use std::path::PathBuf;

use super::detection::{ComponentFixResult, ComponentStatus};
#[cfg(unix)]
use super::privilege::PrivilegedExecutor;

/// Fix hosts file entry using shared privileged executor
#[cfg(unix)]
pub async fn fix_hosts(executor: &mut PrivilegedExecutor) -> ComponentFixResult {
    log::info!("Fixing hosts file entry...");

    // Check if already configured
    if super::hosts::hosts_entry_exists() {
        log::info!("Hosts entry: already present");
        return ComponentFixResult {
            component: "hosts",
            success: true,
            error: None,
            required_sudo: false,
        };
    }

    // Add entry using direct file append (privileged)
    let hosts_path = if cfg!(unix) {
        std::path::Path::new("/etc/hosts")
    } else {
        std::path::Path::new(r"C:\Windows\System32\drivers\etc\hosts")
    };

    match executor
        .append_to_file(hosts_path, "127.0.0.1 mcp.kodegen.ai\n")
        .await
    {
        Ok(()) => {
            log::info!("Hosts entry: added");
            ComponentFixResult {
                component: "hosts",
                success: true,
                error: None,
                required_sudo: true,
            }
        }
        Err(e) => {
            log::error!("Failed to fix hosts: {}", e);
            ComponentFixResult {
                component: "hosts",
                success: false,
                error: Some(e.to_string()),
                required_sudo: true,
            }
        }
    }
}

/// Fix certificates using shared privileged executor
///
/// 1. Generate certificate content in memory (unprivileged)
/// 2. Write to system path using executor (privileged)
/// 3. Import to trust store using executor (privileged)
#[cfg(unix)]
pub async fn fix_certificates(executor: &mut PrivilegedExecutor) -> ComponentFixResult {
    log::info!("Fixing certificates...");

    // Step 1: Generate certificate content directly in memory (no file I/O)
    let cert_content = match generate_certificate_content_only() {
        Ok(content) => content,
        Err(e) => {
            return ComponentFixResult {
                component: "certificates",
                success: false,
                error: Some(format!("Failed to generate certificate: {}", e)),
                required_sudo: false,
            };
        }
    };

    // Step 2: Get the certificate path (system location)
    let cert_dir = PathBuf::from("/usr/local/var/kodegen/certs");
    let cert_path = cert_dir.join("wildcard.pem");

    // Step 3: Write certificate using privileged executor
    if let Err(e) = executor.write_file(&cert_path, &cert_content).await {
        return ComponentFixResult {
            component: "certificates",
            success: false,
            error: Some(format!("Failed to write certificate: {}", e)),
            required_sudo: true,
        };
    }

    // Step 4: Set secure permissions
    if let Err(e) = executor.chmod(&cert_path, "600").await {
        log::warn!("Failed to set certificate permissions: {}", e);
    }

    // Step 5: Import to system trust store (macOS)
    #[cfg(target_os = "macos")]
    {
        let cert_path_str = cert_path.to_string_lossy();
        if let Err(e) = executor
            .exec(&[
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                &cert_path_str,
            ])
            .await
        {
            log::warn!("Failed to import certificate to trust store: {}", e);
            // Don't fail - certificate is still generated
        } else {
            log::info!("Certificate imported to system trust store");
        }
    }

    log::info!("Certificate generated and written to {}", cert_path.display());
    ComponentFixResult {
        component: "certificates",
        success: true,
        error: None,
        required_sudo: true,
    }
}

/// Generate certificate content in memory without writing to disk
fn generate_certificate_content_only() -> Result<String> {
    use rcgen::string::Ia5String;
    use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};

    log::info!("Generating certificate content in memory...");

    let mut params = CertificateParams::new(vec!["mcp.kodegen.ai".to_string()])?;

    params.subject_alt_names = vec![
        SanType::DnsName(Ia5String::try_from("mcp.kodegen.ai")?),
        SanType::DnsName(Ia5String::try_from("localhost")?),
        SanType::IpAddress("127.0.0.1".parse()?),
        SanType::IpAddress("::1".parse()?),
    ];

    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Kodegen");
    dn.push(DnType::CommonName, "mcp.kodegen.ai");
    params.distinguished_name = dn;

    // Set non-expiring validity period (100 years)
    use time::OffsetDateTime;
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::seconds(100 * 365 * 24 * 60 * 60);

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok(format!("{}\n{}", cert.pem(), key_pair.serialize_pem()))
}

/// Fix kodegen binary version using shared privileged executor
#[cfg(unix)]
pub async fn fix_kodegen_version(executor: &mut PrivilegedExecutor) -> ComponentFixResult {
    use super::binary_staging;
    use super::download;
    use tokio::sync::mpsc;

    log::info!("Fixing kodegen version...");

    // Check current status
    let status = super::detection::check_kodegen_version_status().await;

    match status {
        ComponentStatus::Ok => {
            log::info!("Kodegen version is already up to date");
            return ComponentFixResult {
                component: "kodegen_version",
                success: true,
                error: None,
                required_sudo: false,
            };
        }
        ComponentStatus::Missing | ComponentStatus::NeedsUpdate => {
            // Continue with installation
        }
        ComponentStatus::CheckFailed => {
            return ComponentFixResult {
                component: "kodegen_version",
                success: false,
                error: Some("Could not determine kodegen version status".to_string()),
                required_sudo: false,
            };
        }
    }

    // Step 1: Download binary (unprivileged)
    let (tx, mut rx) = mpsc::channel(100);

    let progress_task = tokio::spawn(async move {
        while rx.recv().await.is_some() {
            // Silently consume progress messages
        }
    });

    let binary_paths = match download::download_all_binaries(tx).await {
        Ok(paths) => paths,
        Err(e) => {
            return ComponentFixResult {
                component: "kodegen_version",
                success: false,
                error: Some(format!("Failed to download kodegen: {}", e)),
                required_sudo: false,
            };
        }
    };

    let _ = progress_task.await;

    if binary_paths.is_empty() {
        return ComponentFixResult {
            component: "kodegen_version",
            success: true,
            error: None,
            required_sudo: false,
        };
    }

    // Step 2: Stage binaries (unprivileged)
    let staging_dir = match binary_staging::stage_binaries_for_install(&binary_paths).await {
        Ok(dir) => dir,
        Err(e) => {
            return ComponentFixResult {
                component: "kodegen_version",
                success: false,
                error: Some(format!("Failed to stage binaries: {}", e)),
                required_sudo: false,
            };
        }
    };

    // Step 3: Copy to /usr/local/bin using privileged executor
    if let Err(e) = executor.exec(&["mkdir", "-p", "/usr/local/bin"]).await {
        return ComponentFixResult {
            component: "kodegen_version",
            success: false,
            error: Some(format!("Failed to create /usr/local/bin: {}", e)),
            required_sudo: true,
        };
    }

    // Copy each staged binary
    for entry in std::fs::read_dir(&staging_dir).into_iter().flatten().flatten() {
        let src = entry.path();
        let filename = src.file_name().unwrap();
        let dst = PathBuf::from("/usr/local/bin").join(filename);

        if let Err(e) = executor.copy_file(&src, &dst).await {
            return ComponentFixResult {
                component: "kodegen_version",
                success: false,
                error: Some(format!("Failed to copy {}: {}", src.display(), e)),
                required_sudo: true,
            };
        }

        // Set permissions
        if let Err(e) = executor.chmod(&dst, "755").await {
            log::warn!("Failed to set permissions on {}: {}", dst.display(), e);
        }
    }

    // Set ownership (use sh -c for shell logic with fallback)
    let _ = executor
        .exec(&["sh", "-c", "chown root:wheel /usr/local/bin/kodegend 2>/dev/null || chown root:root /usr/local/bin/kodegend"])
        .await;
    let _ = executor
        .exec(&["sh", "-c", "chown root:wheel /usr/local/bin/kodegen 2>/dev/null || chown root:root /usr/local/bin/kodegen 2>/dev/null || true"])
        .await;

    // Cleanup staging directory
    let _ = std::fs::remove_dir_all(&staging_dir);

    log::info!("Kodegen binary installed to /usr/local/bin");
    ComponentFixResult {
        component: "kodegen_version",
        success: true,
        error: None,
        required_sudo: true,
    }
}

/// Fix all components that need action
///
/// Checks each component and fixes only those that need it.
/// Spawns privileged executor ONCE if any operation needs sudo.
/// Uses fail-fast behavior: stops on first failure.
#[cfg(unix)]
pub async fn fix_all_components() -> Result<super::detection::InstallationFixReport> {
    let status = super::detection::check_all_components().await;

    if status.all_ok() {
        log::info!("All installation components verified OK");
        return Ok(super::detection::InstallationFixReport {
            hosts: None,
            certificates: None,
            kodegen_version: None,
            overall_success: true,
        });
    }

    log::info!(
        "Components needing action: {:?}",
        status.components_needing_action()
    );

    let mut report = super::detection::InstallationFixReport {
        hosts: None,
        certificates: None,
        kodegen_version: None,
        overall_success: true,
    };

    // Spawn privileged executor ONCE if any operation needs sudo
    let mut executor = if status.needs_sudo() {
        log::info!("Privileged operations required, collecting sudo credentials...");
        Some(PrivilegedExecutor::spawn().await?)
    } else {
        None
    };

    // Fix hosts if needed (FAIL-FAST)
    if status.hosts != ComponentStatus::Ok {
        log::info!("Fixing hosts entry (status: {:?})...", status.hosts);
        let result = if let Some(ref mut exec) = executor {
            fix_hosts(exec).await
        } else {
            ComponentFixResult {
                component: "hosts",
                success: false,
                error: Some("No privileged executor available".to_string()),
                required_sudo: true,
            }
        };
        let success = result.success;
        report.hosts = Some(result);
        if !success {
            report.overall_success = false;
            return Ok(report);
        }
    }

    // Fix certificates if needed (FAIL-FAST)
    if status.certificates != ComponentStatus::Ok {
        log::info!(
            "Fixing certificates (status: {:?})...",
            status.certificates
        );
        let result = if let Some(ref mut exec) = executor {
            fix_certificates(exec).await
        } else {
            ComponentFixResult {
                component: "certificates",
                success: false,
                error: Some("No privileged executor available".to_string()),
                required_sudo: true,
            }
        };
        let success = result.success;
        report.certificates = Some(result);
        if !success {
            report.overall_success = false;
            return Ok(report);
        }
    }

    // Fix kodegen version if needed (FAIL-FAST)
    if status.kodegen_version != ComponentStatus::Ok {
        log::info!(
            "Fixing kodegen version (status: {:?})...",
            status.kodegen_version
        );
        let result = if let Some(ref mut exec) = executor {
            fix_kodegen_version(exec).await
        } else {
            ComponentFixResult {
                component: "kodegen_version",
                success: false,
                error: Some("No privileged executor available".to_string()),
                required_sudo: true,
            }
        };
        let success = result.success;
        report.kodegen_version = Some(result);
        if !success {
            report.overall_success = false;
            return Ok(report);
        }
    }

    log::info!("All component fixes completed successfully");
    Ok(report)
}

// Non-Unix stub implementations
#[cfg(not(unix))]
pub async fn fix_all_components() -> Result<super::detection::InstallationFixReport> {
    // Windows implementation would go here
    Ok(super::detection::InstallationFixReport {
        hosts: None,
        certificates: None,
        kodegen_version: None,
        overall_success: true,
    })
}
