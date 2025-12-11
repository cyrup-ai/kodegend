//! Enhanced panic handler with system state collection and file backup logging
//!
//! Architecture:
//! 1. Custom panic hook collects system state (memory, threads, FDs)
//! 2. Writes to backup panic.log file (survives journald rotation)
//! 3. Chains to log_panics which routes through log crate
//! 4. Existing platform loggers handle the rest (journald/eventlog/oslog)

use std::panic;
use std::path::PathBuf;
use sysinfo::{System, ProcessesToUpdate, Pid};

/// Initialize panic handler with system state collection
///
/// MUST be called BEFORE logging::init_logging() in main()
/// so that panics during logging setup are still captured.
pub fn init() {
    // Set up custom panic hook that collects system state and writes to file
    let default_hook = panic::take_hook();
    
    panic::set_hook(Box::new(move |panic_info| {
        // Collect system state immediately
        let system_state = collect_system_state();
        
        // Write to backup panic.log file (before process dies)
        write_panic_to_file(panic_info, &system_state);
        
        // Call default hook for backward compatibility (stderr output)
        default_hook(panic_info);
    }));
    
    // Initialize log_panics to route panics through log crate
    // This will install its own hook that chains with ours
    log_panics::init();
}

/// System state snapshot at panic time
#[derive(Debug)]
struct SystemState {
    memory_mb: u64,
    thread_count: usize,
    open_fds: usize,
    cpu_percent: f32,
    uptime_secs: u64,
}

/// Collect current system state for diagnostics
fn collect_system_state() -> SystemState {
    let mut sys = System::new();
    
    // Refresh only our process (efficient)
    let pid = Pid::from(std::process::id() as usize);
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    
    let process = sys.process(pid);
    
    SystemState {
        memory_mb: process.map(|p| p.memory() / 1024 / 1024).unwrap_or(0),
        thread_count: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        open_fds: count_open_fds(),
        cpu_percent: process.map(|p| p.cpu_usage()).unwrap_or(0.0),
        uptime_secs: process.map(|p| p.run_time()).unwrap_or(0),
    }
}

/// Count open file descriptors (platform-specific)
#[cfg(all(unix, not(target_os = "macos")))]
fn count_open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn count_open_fds() -> usize {
    // macOS doesn't have /proc/self/fd
    // Could use lsof or proc_pidinfo but that requires additional dependencies
    // For now return 0 - panic logging will still work
    0
}

#[cfg(windows)]
fn count_open_fds() -> usize {
    // Windows handle counting requires Win32 API
    // Could use GetProcessHandleCount but that requires unsafe code
    // For now return 0 - panic logging will still work
    0
}

/// Write panic to dedicated panic.log file as backup
///
/// This ensures panic details survive even if:
/// - systemd journald rotates logs
/// - Windows Event Log reaches size limit
/// - Service crashes before logs are flushed
fn write_panic_to_file(panic_info: &panic::PanicHookInfo, state: &SystemState) {
    use std::io::Write;
    
    let panic_log = get_panic_log_path();
    
    // Create parent directory if needed
    if let Some(parent) = panic_log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    
    // Open in append mode (create if doesn't exist)
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&panic_log)
    {
        let timestamp = chrono::Utc::now();
        let location = panic_info.location();
        let filename = location.map(|l| l.file()).unwrap_or("<unknown>");
        let line = location.map(|l| l.line()).unwrap_or(0);
        
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<no message>".to_string()
        };
        
        let separator = "=".repeat(60);
        let _ = writeln!(file, "\n{}", separator);
        let _ = writeln!(file, "PANIC REPORT");
        let _ = writeln!(file, "{}", separator);
        let _ = writeln!(file, "Timestamp: {}", timestamp.to_rfc3339());
        let _ = writeln!(file, "Version: {}", env!("CARGO_PKG_VERSION"));
        let _ = writeln!(file, "Location: {}:{}", filename, line);
        let _ = writeln!(file, "Message: {}", message);
        let _ = writeln!(file, "\nSystem State:");
        let _ = writeln!(file, "  Memory: {} MB", state.memory_mb);
        let _ = writeln!(file, "  Threads: {}", state.thread_count);
        let _ = writeln!(file, "  Open FDs: {}", state.open_fds);
        let _ = writeln!(file, "  CPU: {:.1}%", state.cpu_percent);
        let _ = writeln!(file, "  Uptime: {} seconds", state.uptime_secs);
        let _ = writeln!(file, "\nBacktrace will be in systemd/eventlog");
        let _ = writeln!(file, "{}\n", separator);
        let _ = file.flush();
    }
}

/// Get platform-appropriate panic log file path
fn get_panic_log_path() -> PathBuf {
    #[cfg(unix)]
    {
        // Unix: /var/log/kodegend/panic.log
        // Falls back to home directory if /var/log not writable
        let system_log = PathBuf::from("/var/log/kodegend/panic.log");
        if system_log.parent().map(|p| p.exists()).unwrap_or(false) {
            return system_log;
        }
        
        // Fallback: ~/.local/share/kodegend/panic.log
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kodegend")
            .join("panic.log")
    }
    
    #[cfg(windows)]
    {
        // Windows: %LOCALAPPDATA%\kodegend\panic.log
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kodegend")
            .join("panic.log")
    }
}
