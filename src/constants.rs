//! Daemon operation constants
//!
//! Centralized configuration for all kodegend timing, resource limits,
//! and system integration parameters. Values are based on:
//! - Unix daemon best practices (Stevens APUE, daemon(7))
//! - systemd/launchd integration requirements
//! - Production testing and empirical tuning
//!
//! # References
//! - W. Richard Stevens, "Advanced Programming in the UNIX Environment"
//! - daemon(7) - Linux manual page
//! - systemd.service(5) - TimeoutStartSec, TimeoutStopSec defaults
//! - RFC 793 - TCP specification (TIME_WAIT state)

use std::time::Duration;

// ============================================================================
// DAEMONIZATION CONSTANTS
// ============================================================================

/// File creation mask for daemonized processes
///
/// Standard Unix daemon umask: 0o022
/// - Owner: read/write (6)
/// - Group: read (4)
/// - Others: read (4)
///
/// This allows daemon-created files to be readable by all users while
/// only writable by the daemon user.
///
/// Reference: daemon(7), Stevens APUE §13.3
#[cfg(unix)]
pub const DAEMON_UMASK: u32 = 0o022;

/// PID file permissions (Unix only)
///
/// Standard permissions for PID files: 0o644 (rw-r--r--)
/// - Owner: read/write
/// - Group: read only
/// - Others: read only
///
/// World-readable to allow non-root users to check daemon status.
/// Owner-writable only to prevent unauthorized modification.
///
/// Matches industry standard (systemd, nginx, redis, Apache httpd).
/// Reference: LSB FHS 3.0, systemd pidfile.c
#[cfg(unix)]
pub const PID_FILE_MODE: u32 = 0o644;

/// PID file directory permissions (Unix only)
///
/// Standard permissions for runtime directories: 0o755 (rwxr-xr-x)
/// - Owner: read/write/execute
/// - Group: read/execute
/// - Others: read/execute
///
/// Standard for /var/run subdirectories. Execute permission required
/// for directory traversal.
///
/// Reference: FHS 3.0 §5.13, systemd-tmpfiles
#[cfg(unix)]
pub const PID_DIR_MODE: u32 = 0o755;

/// Maximum file descriptor soft limit cap
///
/// Modern Linux systems support 1,048,576 open files, but we cap at
/// 65,536 for safety and to avoid excessive iteration during FD cleanup.
/// This is the typical macOS default (kern.maxfilesperproc).
///
/// Reference: getrlimit(2), RLIMIT_NOFILE
#[cfg(unix)]
pub const MAX_FD_SOFT_LIMIT: i32 = 65536;

/// Fallback maximum file descriptor count
///
/// Used when getrlimit() fails. POSIX.1 guarantees at least 1024.
/// This is also the historical Linux default (ulimit -n).
///
/// Reference: POSIX.1-2001 _POSIX_OPEN_MAX
#[cfg(unix)]
pub const FALLBACK_MAX_FD: i32 = 1024;

/// First non-standard file descriptor
///
/// File descriptors 0, 1, 2 are stdin, stdout, stderr.
/// FD ≥3 are user-opened files that should be closed during daemonization.
///
/// Reference: ISO C standard streams, daemon(7)
#[cfg(unix)]
pub const FIRST_USER_FD: i32 = 3;

/// Standard input file descriptor
#[cfg(unix)]
pub const STDIN_FD: i32 = 0;

/// Standard output file descriptor
#[cfg(unix)]
pub const STDOUT_FD: i32 = 1;

/// Standard error file descriptor
#[cfg(unix)]
pub const STDERR_FD: i32 = 2;

/// Readiness signal sent from grandchild to original parent
///
/// After double-fork daemonization, the grandchild writes this to a
/// pipe to signal successful initialization.
#[cfg(unix)]
pub const READINESS_SIGNAL: &[u8] = b"OK";

/// Size of buffer for reading readiness signal
///
/// Must match READINESS_SIGNAL length (2 bytes for "OK")
#[cfg(unix)]
pub const READINESS_BUFFER_SIZE: usize = 2;

// ============================================================================
// PROCESS CONTROL TIMEOUTS
// ============================================================================

/// Graceful shutdown timeout before force-kill
///
/// After sending SIGTERM, we wait this long before escalating to SIGKILL.
/// This matches systemd's DefaultTimeoutStopSec on many distributions.
///
/// 10 seconds is sufficient for most services to:
/// - Flush buffers and close files
/// - Send final network responses
/// - Clean up temporary resources
///
/// Reference: systemd.service(5) DefaultTimeoutStopSec
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Startup verification timeout
///
/// Maximum time to wait for daemon to become active after start command.
/// This should exceed the daemon's initialization time plus OS scheduler
/// jitter. 30 seconds accommodates:
/// - launchd initialization overhead (~5s)
/// - Network port binding and TLS setup (~2s)
/// - Configuration parsing and validation (~1s)
/// - Safety margin for loaded systems (~20s)
///
/// Reference: systemd.service(5) DefaultTimeoutStartSec (90s default)
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub const STARTUP_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Post-graceful-shutdown wait before bootout/unload
///
/// After sending SIGTERM to launchd/SCM managed service, wait this
/// duration before issuing bootout/unload command. This allows the
/// service to flush logs and close file descriptors cleanly.
///
/// 500ms is empirically sufficient for typical cleanup operations
/// without adding noticeable delay to restart operations.
#[cfg(unix)]
pub const POST_SIGTERM_DELAY: Duration = Duration::from_millis(500);

/// Port release delay before restart
///
/// After stopping a service, wait for the OS to release bound ports.
/// Accounts for:
/// - SO_LINGER socket option delays
/// - Kernel TCP state cleanup
/// - Port allocator cache flush
///
/// 500ms is conservative and prevents "address already in use" errors
/// on restart. Can be reduced to 100ms on systems with SO_REUSEPORT.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub const PORT_RELEASE_DELAY: Duration = Duration::from_millis(500);

/// Graceful kill wait time before force kill
///
/// After sending SIGTERM to a process, wait this duration for it to
/// exit before sending SIGKILL. This gives the process time to:
/// - Run registered atexit() handlers
/// - Flush stdio buffers
/// - Close network connections gracefully
///
/// 2 seconds is a standard value used by many process supervisors.
pub const GRACEFUL_KILL_WAIT: Duration = Duration::from_secs(2);

/// Force kill verification timeout
///
/// Maximum time to wait for SIGKILL to take effect. Even uninterruptible
/// processes should die within 1 second unless stuck in kernel code.
///
/// Uses 10 attempts × 100ms = 1 second total
#[cfg(unix)]
pub const FORCE_KILL_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(1);

/// Force kill verification poll interval
///
/// Check process death every 100ms after SIGKILL. This is approximately
/// the Linux scheduler tick on many systems (HZ=100 → 10ms, but we add
/// margin for scheduler jitter).
#[cfg(unix)]
pub const FORCE_KILL_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum attempts to verify force kill succeeded
///
/// Poll 10 times at 100ms intervals = 1 second total verification period
#[allow(dead_code)] // Reserved for future retry logic in force_kill_process
pub const FORCE_KILL_MAX_ATTEMPTS: u32 = 10;

// ============================================================================
// STATUS POLLING AND BACKOFF
// ============================================================================

/// Initial backoff delay for exponential backoff polling
///
/// Start with 1ms to catch immediate state transitions (e.g., process
/// already stopped). Doubles each iteration up to BACKOFF_MAX_DELAY.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub const BACKOFF_INITIAL_DELAY_MS: u64 = 1;

/// Maximum backoff delay cap
///
/// Cap exponential backoff at 100ms to maintain reasonable responsiveness
/// while avoiding excessive CPU usage. Polling faster than 100ms rarely
/// improves user experience and wastes resources.
///
/// Sequence: 1ms → 2ms → 4ms → 8ms → 16ms → 32ms → 64ms → 100ms (capped)
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub const BACKOFF_MAX_DELAY_MS: u64 = 100;

// ============================================================================
// PORT CLEANUP RETRY STRATEGY  
// ============================================================================

/// Maximum port cleanup retry attempts
///
/// Retry up to 5 times with exponential backoff before giving up.
/// This handles transient issues like:
/// - Race conditions between process death and port release
/// - Kernel delays in updating socket tables
/// - Brief TIME_WAIT states
///
/// Total max time: ~10 seconds (100ms + 200ms + 400ms + 800ms + 1600ms + ...)
pub const PORT_CLEANUP_MAX_RETRIES: u32 = 5;

/// Initial delay for port cleanup exponential backoff
///
/// Start with 100ms to give the kernel time to update socket state
/// after process termination.
pub const PORT_CLEANUP_INITIAL_DELAY_MS: u64 = 100;

/// Maximum delay between port cleanup retries
///
/// Cap at 5 seconds to prevent excessively long waits. This is shorter
/// than typical TIME_WAIT duration (60s) since we're force-killing the
/// process rather than waiting for graceful connection close.
pub const PORT_CLEANUP_MAX_DELAY_MS: u64 = 5000;

/// Port release verification timeout
///
/// After killing a process, wait up to 3 seconds for the kernel to
/// release its bound ports. This is much shorter than TIME_WAIT (60s)
/// because SIGKILL aborts connections immediately (RST packets).
pub const PORT_RELEASE_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(3);

/// Port availability poll interval
///
/// Check port availability every 100ms. This balances:
/// - Responsiveness (catch release within 100ms)
/// - CPU efficiency (avoid tight spin loop)
/// - Scheduler granularity (match typical OS time slice)
pub const PORT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// TIME_WAIT state tolerance delay
///
/// When a port appears in use but no process is found, wait 500ms
/// to allow TIME_WAIT states to clear. This handles the race where:
/// 1. Process terminates and releases port
/// 2. Socket enters TIME_WAIT (still bound but no process)
/// 3. Our check sees bound port with no owner
///
/// 500ms gives the kernel time to clean up orphaned sockets.
pub const TIME_WAIT_TOLERANCE_DELAY: Duration = Duration::from_millis(500);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Get the array of standard file descriptors (stdin, stdout, stderr)
///
/// Returns file descriptors in canonical order: stdin (0), stdout (1), stderr (2).
/// Used during daemonization to redirect standard streams to /dev/null.
///
/// Reference: Stevens APUE §13.3 - Daemon Conventions
#[cfg(unix)]
pub const fn standard_fds() -> [i32; 3] {
    [STDIN_FD, STDOUT_FD, STDERR_FD]
}

/// Calculate total maximum time for port cleanup with retries
///
/// Sum of geometric series: initial * (2^n - 1) for n retries
pub const fn port_cleanup_max_total_time_ms() -> u64 {
    PORT_CLEANUP_INITIAL_DELAY_MS * ((1 << PORT_CLEANUP_MAX_RETRIES) - 1)
}
