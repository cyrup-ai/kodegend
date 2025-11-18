//! Privilege escalation and sudo operations for kodegen installer
//!
//! This module handles operations that require elevated privileges (root/admin),
//! including certificate installation, hosts file updates, and binary installation
//! to system directories.

use anyhow::{Context, Result};

// Windows-specific imports for UAC elevation
#[cfg(windows)]
use crate::install::installer::windows::privileges::{ensure_helper_path, HELPER_PATH};

#[cfg(windows)]
use windows::{
    Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW, SEE_MASK_NOCLOSEPROCESS},
    Win32::UI::WindowsAndMessaging::SW_HIDE,
    Win32::Foundation::{HWND, CloseHandle, GetLastError},
    Win32::System::Threading::{WaitForSingleObject, GetExitCodeProcess, INFINITE},
    core::PCWSTR,
};

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
        use crate::install::installer::windows::paths::{self, InstallScope};

        let install_dir = paths::install_dir(InstallScope::System);
        
        script.push_str(&paths::mkdir_command(&install_dir));
        script.push_str("\n");

        for file in &staged_files {
            script.push_str(&paths::copy_file_command(
                std::path::Path::new(file),
                &install_dir
            ));
            script.push_str("\n");
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

    // Update hosts file (idempotent)
    #[cfg(windows)]
    {
        use crate::install::installer::windows::paths;

        script.push_str("\n@REM Update Windows hosts file\n");
        script.push_str("echo Updating hosts file...\n");

        let hosts_path = paths::hosts_file();
        
        // Check if entry exists (case-insensitive search)
        // findstr /i = case-insensitive, /c: = exact string match
        // errorlevel 1 means NOT found
        script.push_str(&format!(
            r#"findstr /i /c:"mcp.kodegen.ai" "{}" >nul 2>&1
if errorlevel 1 (
    echo 127.0.0.1 mcp.kodegen.ai >> "{}"
    echo Hosts entry added
) else (
    echo Hosts entry already exists
)

"#,
            hosts_path.display(), hosts_path.display()
        ));
        
        // Flush DNS cache so changes take effect immediately
        script.push_str("ipconfig /flushdns >nul 2>&1\n");
        script.push_str("echo DNS cache flushed\n");
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
        #[cfg(windows)]
        let temp_cert_path = {
            use crate::install::installer::windows::paths;
            paths::temp_cert_path()
        };

        #[cfg(unix)]
        let temp_cert_path = std::path::PathBuf::from(format!("/tmp/kodegen_cert_import_{}.crt", std::process::id()));

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
        script.push_str(&get_cert_import_command(&temp_cert_path));
        script.push('\n');

        // Clean up temp file in script (after import completes)
        #[cfg(unix)]
        script.push_str(&format!("rm -f '{}'\n", temp_cert_path.display()));

        #[cfg(windows)]
        {
            use crate::install::installer::windows::paths;
            script.push_str(&paths::delete_file_command(&temp_cert_path));
            script.push_str("\n");
        }
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

    #[cfg(target_os = "windows")]
    {
        // Note: Windows service registration happens via Windows API (not script)
        // The service will be registered after the privileged script completes
        // See register_windows_service() function below
        script.push_str("\n# Windows service registration\n");
        script.push_str("echo Service will be registered via Windows Service Control Manager...\n");
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
        // Step 1: Ensure helper is extracted and validated (using spawn_blocking for sync fn)
        tokio::task::spawn_blocking(|| ensure_helper_path())
            .await
            .context("Failed to spawn helper extraction task")?
            .context("Failed to extract Windows helper executable")?;

        // Step 2: Get helper path (guaranteed to be initialized after ensure_helper_path)
        let helper_path = HELPER_PATH
            .get()
            .ok_or_else(|| anyhow::anyhow!("Helper path not initialized - this is a bug"))?;

        // Step 3: Prepare ShellExecuteEx for UAC elevation
        // The "runas" verb triggers the UAC prompt
        let verb: Vec<u16> = "runas\0".encode_utf16().collect();
        let helper_path_wide: Vec<u16> = helper_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Encode script content directly as wide string (helper expects content, not path)
        let script_wide: Vec<u16> = script
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut sei = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,  // Get process handle for waiting
            hwnd: HWND::default(),
            lpVerb: PCWSTR(verb.as_ptr()),
            lpFile: PCWSTR(helper_path_wide.as_ptr()),
            lpParameters: PCWSTR(script_wide.as_ptr()),  // Pass script content, not path
            lpDirectory: PCWSTR::null(),
            nShow: SW_HIDE.0 as i32,  // Hide console window
            hInstApp: Default::default(),
            lpIDList: std::ptr::null_mut(),
            lpClass: PCWSTR::null(),
            hkeyClass: Default::default(),
            dwHotKey: 0,
            hMonitor: Default::default(),
            hProcess: Default::default(),
        };

        // Step 5: Execute with UAC elevation (shows UAC prompt to user)
        let elevation_result = unsafe {
            ShellExecuteExW(&mut sei)
        };

        if elevation_result.is_err() || sei.hProcess.is_invalid() {
            // Check if user cancelled UAC (ERROR_CANCELLED = 1223)
            let error_code = unsafe { GetLastError() };
            if error_code.0 == 1223 {
                return Err(anyhow::anyhow!(
                    "UAC elevation cancelled by user. Administrator privileges are required to install kodegen."
                ));
            }
            
            return Err(anyhow::anyhow!(
                "Failed to launch elevated helper process (error code: {})",
                error_code.0
            ));
        }

        // Step 6: Wait for elevated process to complete
        let wait_result = unsafe {
            WaitForSingleObject(sei.hProcess, INFINITE)
        };

        if wait_result.0 != 0 {
            unsafe { let _ = CloseHandle(sei.hProcess); }
            return Err(anyhow::anyhow!("Wait for elevated process failed"));
        }

        // Step 7: Get exit code
        let mut exit_code: u32 = 0;
        let exit_code_result = unsafe {
            GetExitCodeProcess(sei.hProcess, &mut exit_code)
        };

        // Step 8: Cleanup
        unsafe { let _ = CloseHandle(sei.hProcess); }

        if exit_code_result.is_err() || exit_code != 0 {
            return Err(anyhow::anyhow!(
                "Privileged installation failed with exit code: {}",
                exit_code
            ));
        }

        // Register Windows service (requires elevation, uses Windows API)
        use crate::install::installer::windows::paths::{kodegend_exe, InstallScope};
        let binary_path = kodegend_exe(InstallScope::System);
        register_windows_service(&binary_path).await?;
    }

    // Cleanup staging directory
    std::fs::remove_dir_all(staging_dir)
        .with_context(|| format!("Failed to cleanup staging directory: {}", staging_dir.display()))?;

    Ok(())
}

/// Register the kodegend service with Windows Service Control Manager.
///
/// This function is called after privileged file operations complete to register
/// the Windows service. It uses the Windows API (CreateServiceW) rather than
/// file-based configuration like Unix systems.
///
/// # Arguments
/// * `binary_path` - Path to the installed kodegend.exe binary
///
/// # Returns
/// * `Ok(())` on successful service registration
/// * `Err` if service registration fails
///
/// # Implementation Note
/// This function is async but calls sync Windows APIs via spawn_blocking.
/// PlatformExecutor::install() is a blocking operation that makes Windows API calls.
#[cfg(windows)]
async fn register_windows_service(binary_path: &std::path::Path) -> Result<()> {
    use crate::install::installer::windows::PlatformExecutor;
    use crate::install::installer::InstallerBuilder;

    eprintln!("🔧 Registering Windows service...");

    // Verify binary exists before attempting service registration
    if !binary_path.exists() {
        return Err(anyhow::anyhow!(
            "kodegend.exe not found at {}. Binary installation may have failed.",
            binary_path.display()
        ));
    }

    // Build service installer configuration
    // Note: InstallerBuilder is defined in ../installer/builder.rs
    let installer = InstallerBuilder::new("kodegend", binary_path)
        .description("KODEGEN MCP Tool Server Daemon")
        .args(["run", "--foreground"])  // --service flag added automatically by service_creation.rs
        .env("RUST_LOG", "info")
        .auto_restart(true)         // Configure automatic restart on failure
        .network(true)              // Service requires network (depends on Tcpip/Afd)
        .auto_start(true);          // Start service automatically on boot (delayed start)

    // Call Windows service creation API
    // This is a blocking operation, so wrap in spawn_blocking
    // PlatformExecutor::install() performs these operations:
    //   1. CreateServiceW() - Register service with SCM
    //   2. ChangeServiceConfig2W() - Configure description, failure actions, delayed start, SID
    //   3. Registry operations - Create service metadata entries
    //   4. Event log registration - Register as event source
    //   5. StartServiceW() - Start the service if auto_start=true
    //
    // See: packages/kodegend/src/install/installer/windows/mod.rs:60-94
    tokio::task::spawn_blocking(move || PlatformExecutor::install(installer))
        .await
        .context("Failed to spawn service registration task")?
        .context("Failed to register Windows service")?;

    eprintln!("✓ Windows service registered successfully");
    eprintln!("  Service name: kodegend");
    eprintln!("  Display name: KODEGEN MCP Tool Server Daemon");
    eprintln!("  Binary path: {}", binary_path.display());
    eprintln!("  Start type: Automatic (delayed start)");
    eprintln!("  Recovery: Restart on failure (5s, 10s, 30s delays)");
    eprintln!("  Dependencies: TCP/IP stack (Tcpip, Afd)");

    Ok(())
}
