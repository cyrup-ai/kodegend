//! Individual component fix functions
//!
//! Each function fixes a single component independently.
//! Privilege escalation is collected ONCE and shared across all operations.
//!
//! This is THE logic layer - GUI and CLI are presentation only.

use anyhow::Result;
use std::path::PathBuf;
use tokio::sync::mpsc;

use super::cleanup::InstallationCleanupContext;
use super::core::InstallProgress;
use super::detection::{ComponentFixResult, ComponentStatus};
#[cfg(unix)]
use super::privilege::PrivilegedExecutor;

/// Helper to send progress (best effort, ignores errors)
fn send_progress(tx: &Option<mpsc::Sender<InstallProgress>>, progress: InstallProgress) {
    if let Some(sender) = tx {
        let _ = sender.try_send(progress);
    }
}

/// Fix hosts file entry using atomic flock + write operations
///
/// Uses the proper `add_kodegen_host_entries()` function which provides:
/// - flock-based locking (prevents concurrent modification)
/// - Atomic temp file + rename pattern
/// - Proper Kodegen block format
#[cfg(unix)]
pub async fn fix_hosts(_executor: &mut PrivilegedExecutor) -> ComponentFixResult {
    log::info!("Fixing hosts file entry...");

    // Use the proper atomic function from installer::config::hosts
    // This handles checking if entry exists, locking, and atomic write
    match crate::install::installer::config::add_kodegen_host_entries() {
        Ok(()) => {
            log::info!("Hosts entry: OK");
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

    log::info!(
        "Certificate generated and written to {}",
        cert_path.display()
    );
    ComponentFixResult {
        component: "certificates",
        success: true,
        error: None,
        required_sudo: true,
    }
}

/// Generate certificate content in memory without writing to disk
///
/// Creates a 2-year self-signed certificate for mcp.kodegen.ai.
/// Auto-renewed by daemon startup checks when <1 year validity remains.
///
/// # Certificate Lifecycle
///
/// - Validity: 2 years (730 days)
/// - Renewal threshold: 1 year (50% of validity)
/// - Renewal mechanism: Automatic on daemon startup via `ensure_installed()`
///
/// # References
///
/// - NIST SP 800-57 Part 1 Rev. 5: Key Management Guidelines
/// - CA/Browser Forum Baseline Requirements
/// - Microsoft PKI Best Practices
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

    // Set 2-year validity period with automatic renewal
    // Follows industry best practice: renew at 50% of validity (1 year)
    use time::OffsetDateTime;
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(730);  // 2 years (730 days)

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok(format!("{}\n{}", cert.pem(), key_pair.serialize_pem()))
}

/// Fix kodegen binary version using shared privileged executor
///
/// Accepts optional progress channel - if provided, download progress flows through it.
#[cfg(unix)]
pub async fn fix_kodegen_version(
    executor: &mut PrivilegedExecutor,
    progress_tx: Option<mpsc::Sender<InstallProgress>>,
) -> ComponentFixResult {
    use super::binary_staging;
    use super::download;

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

    // Create cleanup context for RAII cleanup on failure
    let mut cleanup_ctx = InstallationCleanupContext::new();

    // Step 1: Download binary (unprivileged)
    // Use provided channel or create a dummy one that discards progress
    let (tx, rx) = if let Some(ref sender) = progress_tx {
        (sender.clone(), None)
    } else {
        let (tx, mut rx) = mpsc::channel(100);
        // Spawn task to consume progress if no external channel
        tokio::spawn(async move {
            while rx.recv().await.is_some() {}
        });
        (tx, None::<mpsc::Receiver<InstallProgress>>)
    };
    let _ = rx; // Silence unused warning

    let binary_paths = match download::download_all_binaries(tx).await {
        Ok((paths, download_dir)) => {
            cleanup_ctx.downloaded_binaries_dir = Some(download_dir);
            paths
        }
        Err(e) => {
            // Drop will automatically clean up any registered resources
            return ComponentFixResult {
                component: "kodegen_version",
                success: false,
                error: Some(format!("Failed to download kodegen: {}", e)),
                required_sudo: false,
            };
        }
    };

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
        Ok(dir) => {
            cleanup_ctx.staging_dir = Some(dir.clone());
            dir
        }
        Err(e) => {
            // Drop will automatically clean up download_dir
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
    for entry in std::fs::read_dir(&staging_dir)
        .into_iter()
        .flatten()
        .flatten()
    {
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
    
    // Defuse cleanup context - installation succeeded
    cleanup_ctx.defuse();

    ComponentFixResult {
        component: "kodegen_version",
        success: true,
        error: None,
        required_sudo: true,
    }
}

/// Fix Rust toolchain using shared privileged executor
///
/// Ensures Rust nightly toolchain is installed without changing user's default.
/// This is required for building kodegen from source.
#[cfg(unix)]
pub async fn fix_toolchain(_executor: &mut PrivilegedExecutor) -> ComponentFixResult {
    use super::installer::config::toolchain::{ensure_rust_toolchain, verify_rust_toolchain_file};

    log::info!("Checking Rust toolchain...");

    // First verify rust-toolchain.toml exists
    if let Err(e) = verify_rust_toolchain_file() {
        log::warn!("rust-toolchain.toml verification failed: {}", e);
        // This is non-fatal - the file should exist in the repo
        // but we can still install the toolchain
    }

    // Ensure nightly toolchain is available
    match ensure_rust_toolchain().await {
        Ok(()) => {
            log::info!("Rust toolchain: verified");
            ComponentFixResult {
                component: "toolchain",
                success: true,
                error: None,
                required_sudo: false, // rustup doesn't require sudo
            }
        }
        Err(e) => {
            log::error!("Failed to ensure Rust toolchain: {}", e);
            ComponentFixResult {
                component: "toolchain",
                success: false,
                error: Some(e.to_string()),
                required_sudo: false,
            }
        }
    }
}

#[cfg(not(unix))]
pub async fn fix_toolchain(_executor: &mut PrivilegedExecutor) -> ComponentFixResult {
    // TODO: Implement Windows toolchain installation
    log::warn!("Toolchain verification not yet implemented for Windows");
    ComponentFixResult {
        component: "toolchain",
        success: true,
        error: None,
        required_sudo: false,
    }
}

/// Fix all components that need action
///
/// Checks each component and fixes only those that need it.
/// Spawns privileged executor ONCE if any operation needs sudo.
/// Emits progress events to the provided channel for GUI/CLI display.
///
/// This is THE logic layer - GUI and CLI are presentation only.
#[cfg(unix)]
pub async fn fix_all_components(
    progress_tx: Option<mpsc::Sender<InstallProgress>>,
) -> Result<super::detection::InstallationFixReport> {
    // === TOOLCHAIN ===
    send_progress(
        &progress_tx,
        InstallProgress::new("toolchain".into(), 0.0, "Checking toolchain...".into()),
    );
    let status = super::detection::check_all_components().await;

    if status.toolchain == ComponentStatus::Ok {
        send_progress(
            &progress_tx,
            InstallProgress::new("toolchain".into(), 1.0, "✓ Toolchain OK".into()),
        );
    }

    // === HOSTS ===
    send_progress(
        &progress_tx,
        InstallProgress::new("hosts".into(), 0.0, "Checking hosts...".into()),
    );
    if status.hosts == ComponentStatus::Ok {
        send_progress(
            &progress_tx,
            InstallProgress::new("hosts".into(), 1.0, "✓ Hosts OK".into()),
        );
    }

    // === CERTIFICATES ===
    send_progress(
        &progress_tx,
        InstallProgress::new("certificates".into(), 0.0, "Checking certificates...".into()),
    );
    if status.certificates == ComponentStatus::Ok {
        send_progress(
            &progress_tx,
            InstallProgress::new("certificates".into(), 1.0, "✓ Certificates OK".into()),
        );
    }

    // === KODEGEN VERSION ===
    send_progress(
        &progress_tx,
        InstallProgress::new("kodegen".into(), 0.0, "Checking kodegen version...".into()),
    );
    if status.kodegen_version == ComponentStatus::Ok {
        let version_str = super::detection::get_installed_binary_version("kodegen")
            .await
            .unwrap_or_else(|| "unknown".to_string());
        send_progress(
            &progress_tx,
            InstallProgress::new("kodegen".into(), 1.0, format!("✓ Kodegen {} (up to date)", version_str)),
        );
    }

    // If all OK, we're done
    if status.all_ok() {
        log::info!("All installation components verified OK");
        send_progress(
            &progress_tx,
            InstallProgress::complete("complete".into(), "All components OK".into()),
        );
        return Ok(super::detection::InstallationFixReport {
            toolchain: None,
            hosts: None,
            certificates: None,
            kodegen_version: None,
            service: None,
            overall_success: true,
        });
    }

    log::info!(
        "Components needing action: {:?}",
        status.components_needing_action()
    );

    let mut report = super::detection::InstallationFixReport {
        toolchain: None,
        hosts: None,
        certificates: None,
        kodegen_version: None,
        service: None,
        overall_success: true,
    };

    // Spawn privileged executor ONCE if any operation needs sudo
    let mut executor = if status.needs_sudo() {
        log::info!("Privileged operations required, collecting sudo credentials...");
        send_progress(
            &progress_tx,
            InstallProgress::new("privilege".into(), 0.0, "Requesting elevated privileges...".into()),
        );
        Some(PrivilegedExecutor::spawn().await?)
    } else {
        None
    };

    // Fix toolchain FIRST if needed (FAIL-FAST) - required for building
    if status.toolchain != ComponentStatus::Ok {
        send_progress(
            &progress_tx,
            InstallProgress::new("toolchain".into(), 0.5, "Fixing toolchain...".into()),
        );
        log::info!("Fixing toolchain (status: {:?})...", status.toolchain);
        let result = if let Some(ref mut exec) = executor {
            fix_toolchain(exec).await
        } else {
            let mut temp_exec = PrivilegedExecutor::spawn().await?;
            fix_toolchain(&mut temp_exec).await
        };
        let success = result.success;
        if success {
            send_progress(
                &progress_tx,
                InstallProgress::new("toolchain".into(), 1.0, "✓ Toolchain fixed".into()),
            );
        } else {
            send_progress(
                &progress_tx,
                InstallProgress::error("toolchain".into(), format!("✗ Toolchain failed: {}", result.error.as_deref().unwrap_or("unknown"))),
            );
        }
        report.toolchain = Some(result);
        if !success {
            report.overall_success = false;
            return Ok(report);
        }
    }

    // Fix hosts if needed (FAIL-FAST)
    if status.hosts != ComponentStatus::Ok {
        send_progress(
            &progress_tx,
            InstallProgress::new("hosts".into(), 0.5, "Fixing hosts entry...".into()),
        );
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
        if success {
            send_progress(
                &progress_tx,
                InstallProgress::new("hosts".into(), 1.0, "✓ Hosts fixed".into()),
            );
        } else {
            send_progress(
                &progress_tx,
                InstallProgress::error("hosts".into(), format!("✗ Hosts failed: {}", result.error.as_deref().unwrap_or("unknown"))),
            );
        }
        report.hosts = Some(result);
        if !success {
            report.overall_success = false;
            return Ok(report);
        }
    }

    // Fix certificates if needed (FAIL-FAST)
    if status.certificates != ComponentStatus::Ok {
        send_progress(
            &progress_tx,
            InstallProgress::new("certificates".into(), 0.5, "Fixing certificates...".into()),
        );
        log::info!("Fixing certificates (status: {:?})...", status.certificates);
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
        if success {
            send_progress(
                &progress_tx,
                InstallProgress::new("certificates".into(), 1.0, "✓ Certificates fixed".into()),
            );
        } else {
            send_progress(
                &progress_tx,
                InstallProgress::error("certificates".into(), format!("✗ Certificates failed: {}", result.error.as_deref().unwrap_or("unknown"))),
            );
        }
        report.certificates = Some(result);
        if !success {
            report.overall_success = false;
            return Ok(report);
        }
    }

    // Fix kodegen version if needed (FAIL-FAST)
    // This passes the progress channel through for download progress
    if status.kodegen_version != ComponentStatus::Ok {
        send_progress(
            &progress_tx,
            InstallProgress::new("kodegen".into(), 0.1, "Updating kodegen...".into()),
        );
        log::info!(
            "Fixing kodegen version (status: {:?})...",
            status.kodegen_version
        );
        let result = if let Some(ref mut exec) = executor {
            fix_kodegen_version(exec, progress_tx.clone()).await
        } else {
            ComponentFixResult {
                component: "kodegen_version",
                success: false,
                error: Some("No privileged executor available".to_string()),
                required_sudo: true,
            }
        };
        let success = result.success;
        if success {
            send_progress(
                &progress_tx,
                InstallProgress::new("kodegen".into(), 1.0, "✓ Kodegen updated".into()),
            );
        } else {
            send_progress(
                &progress_tx,
                InstallProgress::error("kodegen".into(), format!("✗ Kodegen failed: {}", result.error.as_deref().unwrap_or("unknown"))),
            );
        }
        report.kodegen_version = Some(result);
        if !success {
            report.overall_success = false;
            return Ok(report);
        }
    }

    // === CHROMIUM ===
    send_progress(
        &progress_tx,
        InstallProgress::new("chromium".into(), 0.0, "Checking Chromium...".into()),
    );

    // Check if chromium is installed
    let chromium_installed = kodegen_tools_browser::find_browser_executable().await.is_ok();

    if chromium_installed {
        send_progress(
            &progress_tx,
            InstallProgress::new("chromium".into(), 1.0, "✓ Chromium OK".into()),
        );
    } else {
        send_progress(
            &progress_tx,
            InstallProgress::new("chromium".into(), 0.1, "Installing Chromium (~100MB)...".into()),
        );
        match super::chromium::install_chromium().await {
            Ok(_) => {
                send_progress(
                    &progress_tx,
                    InstallProgress::new("chromium".into(), 1.0, "✓ Chromium installed".into()),
                );
            }
            Err(e) => {
                send_progress(
                    &progress_tx,
                    InstallProgress::error("chromium".into(), format!("✗ Chromium failed: {}", e)),
                );
                report.overall_success = false;
                return Ok(report);
            }
        }
    }

    // === SERVICE REGISTRATION (ALL PLATFORMS) ===
    send_progress(
        &progress_tx,
        InstallProgress::new("service".into(), 0.0, "Checking service registration...".into()),
    );

    let service_result = fix_service_registration(&progress_tx).await;
    report.service = Some(service_result.clone());

    if service_result.success {
        send_progress(
            &progress_tx,
            InstallProgress::new("service".into(), 1.0, "✓ Service registered".into()),
        );
    } else {
        send_progress(
            &progress_tx,
            InstallProgress::error(
                "service".into(),
                format!("✗ Service registration failed: {}", service_result.error.as_deref().unwrap_or("unknown")),
            ),
        );
        // Service registration failure is not fatal - daemon can still run manually
        log::warn!("Service registration failed, daemon will run but not as system service");
    }

    log::info!("All component fixes completed successfully");
    send_progress(
        &progress_tx,
        InstallProgress::complete("complete".into(), "Installation complete".into()),
    );
    Ok(report)
}

// ============================================================================
// SERVICE REGISTRATION - Cross-platform daemon service installation
// ============================================================================

/// Fix service registration - register daemon as system service if needed
///
/// ALL PLATFORMS: macOS (launchd), Linux (systemd), Windows (SCM), BSD (rc.d)
/// Checks on EVERY startup - installs if missing, updates if outdated.
pub async fn fix_service_registration(
    progress_tx: &Option<mpsc::Sender<InstallProgress>>,
) -> ComponentFixResult {
    use crate::platform;

    // Skip if already running under service manager
    if platform::running_under_service_manager() {
        log::info!("Running under service manager, skipping registration");
        return ComponentFixResult {
            component: "service",
            success: true,
            error: None,
            required_sudo: false,
        };
    }

    // Check if service is registered (platform-specific)
    let service_registered = check_service_registered();

    if service_registered {
        // Check if service file needs update (version mismatch)
        if !service_needs_update() {
            log::info!("Service already registered and up-to-date");
            return ComponentFixResult {
                component: "service",
                success: true,
                error: None,
                required_sudo: false,
            };
        }
        log::info!("Service registered but outdated, updating...");
    } else {
        log::info!("Service not registered, installing...");
    }

    send_progress(
        progress_tx,
        InstallProgress::new("service".into(), 0.5, "Registering system service...".into()),
    );

    // Build installer config
    let exe_path = std::env::current_exe().unwrap_or_default();

    let builder = crate::install::installer::InstallerBuilder::new("kodegend", exe_path)
        .description("Kodegen Service Manager")
        .args(["run", "--foreground"])
        .auto_restart(true)
        .auto_start(true);

    // Install service - dispatches to platform-specific implementation
    match crate::install::installer::install_daemon_async(builder).await {
        Ok(()) => {
            log::info!("Service registered successfully");
            ComponentFixResult {
                component: "service",
                success: true,
                error: None,
                required_sudo: true,
            }
        }
        Err(e) => {
            log::error!("Failed to register service: {}", e);
            ComponentFixResult {
                component: "service",
                success: false,
                error: Some(e.to_string()),
                required_sudo: true,
            }
        }
    }
}

/// Check if service is registered on the current platform
/// Returns true if service file/registration exists
fn check_service_registered() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::path::Path::new("/Library/LaunchDaemons/kodegend.plist").exists()
    }

    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/etc/systemd/system/kodegend.service").exists()
            || dirs::config_dir()
                .map(|d| d.join("systemd/user/kodegend.service").exists())
                .unwrap_or(false)
    }

    #[cfg(target_os = "windows")]
    {
        check_windows_service_registered()
    }

    #[cfg(target_os = "freebsd")]
    {
        std::path::Path::new("/usr/local/etc/rc.d/kodegend").exists()
    }

    #[cfg(target_os = "openbsd")]
    {
        std::path::Path::new("/etc/rc.d/kodegend").exists()
    }

    #[cfg(target_os = "netbsd")]
    {
        std::path::Path::new("/etc/rc.d/kodegend").exists()
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        // Generic Unix: Check common init script locations
        std::path::Path::new("/etc/init.d/kodegend").exists()
    }
}

/// Check if service needs update (version mismatch, binary changed, etc.)
fn service_needs_update() -> bool {
    #[cfg(target_os = "macos")]
    {
        check_macos_plist_needs_update()
    }

    #[cfg(target_os = "linux")]
    {
        check_linux_unit_needs_update()
    }

    #[cfg(target_os = "windows")]
    {
        check_windows_service_needs_update()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        check_unix_init_needs_update()
    }
}

#[cfg(target_os = "windows")]
fn check_windows_service_registered() -> bool {
    use std::process::Command;
    // Use sc.exe query to check if service exists
    Command::new("sc.exe")
        .args(["query", "kodegend"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn check_macos_plist_needs_update() -> bool {
    use std::fs;
    let plist_path = "/Library/LaunchDaemons/kodegend.plist";
    let current_exe = std::env::current_exe().ok();

    if let (Some(exe), Ok(content)) = (current_exe, fs::read_to_string(plist_path)) {
        // Check if plist contains the current exe path
        !content.contains(&exe.to_string_lossy().to_string())
    } else {
        true // If we can't check, assume update needed
    }
}

#[cfg(target_os = "linux")]
fn check_linux_unit_needs_update() -> bool {
    use std::fs;
    let unit_paths = [
        PathBuf::from("/etc/systemd/system/kodegend.service"),
        dirs::config_dir()
            .map(|d| d.join("systemd/user/kodegend.service"))
            .unwrap_or_default(),
    ];
    let current_exe = std::env::current_exe().ok();

    for path in unit_paths.iter().filter(|p| p.exists()) {
        if let (Some(exe), Ok(content)) = (&current_exe, fs::read_to_string(path)) {
            if content.contains(&exe.to_string_lossy().to_string()) {
                return false; // Unit is up-to-date
            }
        }
    }
    true // Update needed
}

#[cfg(target_os = "windows")]
fn check_windows_service_needs_update() -> bool {
    use std::process::Command;
    let current_exe = std::env::current_exe().ok();

    if let Some(exe) = current_exe {
        // Query service config and compare binary path
        let output = Command::new("sc.exe")
            .args(["qc", "kodegend"])
            .output()
            .ok();

        if let Some(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            return !stdout.contains(&exe.to_string_lossy().to_string());
        }
    }
    true
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn check_unix_init_needs_update() -> bool {
    // For BSD/generic Unix, check init script content
    let init_paths = [
        "/usr/local/etc/rc.d/kodegend",
        "/etc/rc.d/kodegend",
        "/etc/init.d/kodegend",
    ];
    let current_exe = std::env::current_exe().ok();

    for path in init_paths {
        if std::path::Path::new(path).exists() {
            if let (Some(exe), Ok(content)) = (&current_exe, std::fs::read_to_string(path)) {
                if content.contains(&exe.to_string_lossy().to_string()) {
                    return false;
                }
            }
        }
    }
    true
}

// Non-Unix stub implementations
#[cfg(not(unix))]
pub async fn fix_all_components(
    _progress_tx: Option<mpsc::Sender<InstallProgress>>,
) -> Result<super::detection::InstallationFixReport> {
    // Windows implementation would go here
    // TODO: Implement full Windows support using the same pattern as Unix
    Ok(super::detection::InstallationFixReport {
        toolchain: None,
        hosts: None,
        certificates: None,
        kodegen_version: None,
        service: None,
        overall_success: true,
    })
}
