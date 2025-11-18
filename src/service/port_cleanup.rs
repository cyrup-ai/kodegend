//! Port cleanup utilities for kodegend HTTP server startup.
//!
//! Detects and terminates processes occupying required ports before
//! attempting to bind new servers. Cross-platform implementation for
//! Linux, macOS, and Windows.

use anyhow::{Context, Result};
use std::time::Duration;
use tokio::time::sleep;

/// Check if a port is available for binding
///
/// Tests port availability by attempting to bind a TcpListener.
/// Does not actually hold the port - releases immediately.
pub async fn check_port_available(port: u16) -> bool {
    tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .is_ok()
}

/// Find PID of process listening on specified port
///
/// Platform-specific implementation:
/// - Unix (macOS/Linux): Uses `lsof -ti :PORT`
/// - Windows: Uses `netstat -ano` and parses output
///
/// Returns `None` if no process found or command fails
pub async fn find_process_by_port(port: u16) -> Result<Option<u32>> {
    #[cfg(unix)]
    {
        find_process_by_port_unix(port).await
    }

    #[cfg(windows)]
    {
        find_process_by_port_windows(port).await
    }
}

#[cfg(unix)]
async fn find_process_by_port_unix(port: u16) -> Result<Option<u32>> {
    use tokio::process::Command;

    // Try lsof first (standard on macOS and most Linux)
    let output = Command::new("lsof")
        .args(["-ti", &format!(":{}", port)])
        .output()
        .await;

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let pid_str = stdout.trim();
            
            if pid_str.is_empty() {
                return Ok(None);
            }

            // lsof -ti can return multiple PIDs (one per line)
            // Take the first one
            if let Some(first_line) = pid_str.lines().next() {
                match first_line.parse::<u32>() {
                    Ok(pid) => return Ok(Some(pid)),
                    Err(e) => {
                        log::warn!("Failed to parse lsof PID '{}': {}", first_line, e);
                        return Ok(None);
                    }
                }
            }

            Ok(None)
        }
        Ok(_) => {
            // lsof returned non-zero (no process found or lsof not available)
            Ok(None)
        }
        Err(e) => {
            log::warn!("lsof command failed: {}", e);
            Ok(None)
        }
    }
}

#[cfg(windows)]
async fn find_process_by_port_windows(port: u16) -> Result<Option<u32>> {
    use tokio::process::Command;

    // netstat -ano shows all connections with PIDs
    let output = Command::new("netstat")
        .args(["-ano"])
        .output()
        .await?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse netstat output
    // Format: "  TCP    127.0.0.1:30438    0.0.0.0:0    LISTENING       12345"
    for line in stdout.lines() {
        if !line.contains("LISTENING") {
            continue;
        }

        if !line.contains(&format!(":{}", port)) {
            continue;
        }

        // Extract PID from last column
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pid_str) = parts.last() {
            if let Ok(pid) = pid_str.parse::<u32>() {
                return Ok(Some(pid));
            }
        }
    }

    Ok(None)
}

/// Kill process gracefully with fallback to force kill
///
/// Attempts SIGTERM (Unix) or graceful termination (Windows),
/// waits 2 seconds, then uses SIGKILL if process still exists.
pub async fn kill_process_graceful(pid: u32) -> Result<()> {
    use sysinfo::{Pid, ProcessesToUpdate, Signal, System};

    // Spawn blocking task for sysinfo operations
    tokio::task::spawn_blocking(move || {
        let mut system = System::new();
        system.refresh_processes(ProcessesToUpdate::All, true);

        let sysinfo_pid = Pid::from(pid as usize);
        
        let process = system.process(sysinfo_pid)
            .ok_or_else(|| anyhow::anyhow!("Process {} not found", pid))?;

        // Try graceful termination first (SIGTERM on Unix)
        #[cfg(unix)]
        let graceful_result = process.kill_with(Signal::Term);
        
        #[cfg(windows)]
        let graceful_result = Some(true); // Windows doesn't distinguish

        if graceful_result.is_some() {
            // Wait a moment for graceful shutdown
            std::thread::sleep(Duration::from_secs(2));
            
            // Refresh and check if still running
            system.refresh_processes(ProcessesToUpdate::All, true);
            if system.process(sysinfo_pid).is_some() {
                log::warn!("Process {} did not terminate gracefully, force killing", pid);
            } else {
                log::info!("Process {} terminated gracefully", pid);
                return Ok(());
            }
        }

        // Force kill with SIGKILL
        system.refresh_processes(ProcessesToUpdate::All, true);
        if let Some(process) = system.process(sysinfo_pid) {
            process.kill_with(Signal::Kill)
                .ok_or_else(|| anyhow::anyhow!("Failed to kill process {}", pid))?;
            log::info!("Process {} force killed", pid);
        }

        Ok(())
    })
    .await?
}

/// Wait for port to be released with timeout
///
/// Polls port availability every 100ms until timeout.
pub async fn wait_for_port_release(port: u16, timeout: Duration) -> Result<()> {
    let start = tokio::time::Instant::now();
    
    while start.elapsed() < timeout {
        if check_port_available(port).await {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    Err(anyhow::anyhow!(
        "Timeout waiting for port {} to be released after {:?}",
        port,
        timeout
    ))
}

/// Main cleanup orchestrator - attempts to free up a port if occupied
///
/// Steps:
/// 1. Check if port is available
/// 2. If not, find process using the port
/// 3. Kill the process (gracefully, then forcefully)
/// 4. Wait for port to be released
///
/// This is a best-effort operation - failures are logged but not propagated.
pub async fn cleanup_port_if_needed(port: u16) -> Result<()> {
    // Quick check: is port already free?
    if check_port_available(port).await {
        log::debug!("Port {} is already available", port);
        return Ok(());
    }

    log::warn!("Port {} is in use, attempting cleanup", port);

    // Find process using the port
    let pid = match find_process_by_port(port).await? {
        Some(pid) => pid,
        None => {
            // Race condition: port was in use but we can't find the process
            // Try binding one more time
            if check_port_available(port).await {
                log::info!("Port {} became available during lookup", port);
                return Ok(());
            }
            return Err(anyhow::anyhow!(
                "Port {} in use but no process found (system command may have failed)",
                port
            ));
        }
    };

    log::warn!("Terminating process {} using port {}", pid, port);

    // Kill the process
    kill_process_graceful(pid)
        .await
        .context(format!("Failed to kill process {}", pid))?;

    // Wait for port to be released
    wait_for_port_release(port, Duration::from_secs(3))
        .await
        .context(format!("Port {} still in use after killing process {}", port, pid))?;

    log::info!("Successfully freed port {} (terminated PID {})", port, pid);
    Ok(())
}
