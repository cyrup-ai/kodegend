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

/// Escape a path for safe use in POSIX shell scripts.
///
/// Uses the `shlex` crate to properly quote paths containing shell metacharacters.
/// This prevents command injection by ensuring paths are treated as literal strings.
///
/// # Security
/// - Handles all POSIX shell metacharacters: ', ", $, `, ;, |, &, <, >, (, ), etc.
/// - Returns Err for paths that cannot be safely escaped (non-UTF8, control characters)
/// - MUST be used for ALL user-controlled paths in shell scripts
///
/// # Example
/// ```rust
/// let path = Path::new("/tmp/file'; rm -rf / #.bin");
/// let escaped = shell_escape(path)?;
/// // Result: "'/tmp/file'\'' rm -rf / #.bin'"
/// //                    ^^^^
/// //              Single quote escaped as '\''
/// ```
fn shell_escape(path: &std::path::Path) -> Result<String> {
    // Convert path to string (reject non-UTF8 paths)
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!(
            "Path contains invalid UTF-8: {}. This may be a security issue.",
            path.display()
        ))?;

    // Reject paths with control characters (potential terminal injection)
    if path_str.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(anyhow::anyhow!(
            "Path contains control characters: {}. Possible attack attempt.",
            path.display()
        ));
    }

    // Use shlex to properly escape for POSIX shells
    // shlex::try_quote() returns Cow<str>:
    //   - Borrowed if no escaping needed
    //   - Owned if escaping applied
    match shlex::try_quote(path_str) {
        Ok(quoted) => Ok(quoted.to_string()),
        Err(e) => Err(anyhow::anyhow!(
            "Failed to escape path '{}': {}. This should never happen.",
            path.display(),
            e
        )),
    }
}

/// Validate that a filename is safe (alphanumeric + limited special chars).
///
/// This is a DEFENSE-IN-DEPTH measure in addition to shell escaping.
/// Even with proper escaping, we enforce strict filename rules for binaries.
///
/// # Allowed Characters
/// - Alphanumeric: a-z, A-Z, 0-9
/// - Special: dash (-), underscore (_), dot (.)
///
/// # Rejected
/// - Shell metacharacters: ', ", $, `, ;, |, &, etc.
/// - Path separators: / (slash), \ (backslash)
/// - Whitespace (except already validated above)
/// - Control characters
///
/// # Security Rationale
/// Binary filenames should NEVER contain shell metacharacters. If they do,
/// it's either a mistake or an attack. Rejecting them early prevents exploitation
/// even if shell escaping has bugs.
fn validate_binary_filename(path: &std::path::Path) -> Result<()> {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!(
            "Invalid filename in path: {}",
            path.display()
        ))?;

    // Check for safe characters only
    let is_safe = filename
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');

    if !is_safe {
        return Err(anyhow::anyhow!(
            "Unsafe binary filename detected: '{}'\n\
             Binary filenames must contain only: a-z, A-Z, 0-9, dash, underscore, dot\n\
             This restriction prevents command injection attacks.\n\
             If this is a legitimate file, please rename it and try again.",
            filename
        ));
    }

    // Additional check: reject hidden files (start with .)
    if filename.starts_with('.') {
        return Err(anyhow::anyhow!(
            "Hidden files not allowed as binaries: '{}'",
            filename
        ));
    }

    // Additional check: reject files without extension or with suspicious extensions
    if !filename.contains('.') || filename.ends_with(".sh") || filename.ends_with(".bash") {
        return Err(anyhow::anyhow!(
            "Invalid binary filename: '{}'\n\
             Expected executable binaries (e.g., kodegend, kodegen), not shell scripts.",
            filename
        ));
    }

    Ok(())
}

/// Build platform-specific certificate import command.
///
/// # Security
/// The `escaped_cert_path` parameter MUST be pre-escaped using `shell_escape()`.
/// This function does NOT perform escaping itself.
///
/// # Arguments
/// * `escaped_cert_path` - Shell-escaped certificate path (output of `shell_escape()`)
pub fn get_cert_import_command_escaped(escaped_cert_path: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        format!(
            "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
            escaped_cert_path
        )
    }

    #[cfg(target_os = "linux")]
    {
        // Use a safe static filename instead of parsing escaped string
        format!(
            "cp {} /usr/local/share/ca-certificates/kodegen-mcp.crt && update-ca-certificates",
            escaped_cert_path
        )
    }

    #[cfg(target_os = "windows")]
    {
        format!(
            "certutil -addstore -f Root {}",
            escaped_cert_path
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        format!("echo 'Certificate import not supported on this platform'")
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
            let path = std::path::Path::new(file);
            
            // LAYER 1: Validate filename (reject malicious names)
            validate_binary_filename(path)?;
            
            // LAYER 2: Escape for shell safety (handle remaining edge cases)
            let escaped_path = shell_escape(path)?;
            
            // Now safe to use in shell script
            script.push_str(&format!("cp -f {} /usr/local/bin/\n", escaped_path));
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
        // Escape certificate path before passing to command builder
        let escaped_cert_path = shell_escape(&temp_cert_path)?;
        script.push_str(&get_cert_import_command_escaped(&escaped_cert_path));
        script.push('\n');

        // Clean up temp file in script (after import completes)
        #[cfg(unix)]
        script.push_str(&format!("rm -f {}\n", escaped_cert_path));

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
            // Validate and escape service file path
            validate_binary_filename(&plist_src)?;
            let escaped_plist = shell_escape(&plist_src)?;
            
            script.push_str("\n# Install launchd service\n");
            script.push_str("echo 'Installing service...'\n");
            script.push_str(&format!(
                "cp {} /Library/LaunchDaemons/com.kodegen.daemon.plist\n",
                escaped_plist
            ));
            script.push_str("launchctl load /Library/LaunchDaemons/com.kodegen.daemon.plist 2>/dev/null || true\n");
        }
    }

    #[cfg(target_os = "linux")]
    {
        let service_src = data_dir.join("kodegend.service");
        if service_src.exists() {
            // Validate and escape service file path
            validate_binary_filename(&service_src)?;
            let escaped_service = shell_escape(&service_src)?;
            
            script.push_str("\n# Install systemd service\n");
            script.push_str("echo 'Installing service...'\n");
            script.push_str(&format!(
                "cp {} /etc/systemd/system/kodegend.service\n",
                escaped_service
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
        // Write script to secure temporary file
        let script_path = std::env::temp_dir()
            .join(format!("kodegen_install_script_{}.sh", std::process::id()));
        
        // Write script content
        tokio::fs::write(&script_path, &script)
            .await
            .context("Failed to write installation script")?;
        
        // Set restrictive permissions: owner read/execute only (mode 0700)
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&script_path)
                .await
                .context("Failed to get script metadata")?
                .permissions();
            perms.set_mode(0o700);  // rwx------ (owner only)
            tokio::fs::set_permissions(&script_path, perms)
                .await
                .context("Failed to set script permissions")?;
        }
        
        // Execute script file (NOT via sh -c)
        let status = Command::new("sudo")
            .arg("sh")
            .arg(&script_path)
            .status()
            .context("Failed to execute sudo")?;
        
        // Cleanup script file (even if execution failed)
        let _ = tokio::fs::remove_file(&script_path).await;
        
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
