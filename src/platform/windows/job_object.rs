//! Windows Job Object resource limits
//!
//! Applies memory and process limits via Job Objects.
//! Integrates with WINDOWS_SIGNAL_03 spec for child lifecycle management.

use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

/// Job Object handle wrapper with automatic cleanup
pub struct JobObject {
    handle: HANDLE,
}

impl JobObject {
    /// Create a new Job Object with resource limits applied
    ///
    /// # Arguments
    /// * `max_memory_bytes` - Maximum memory per process (0 = unlimited)
    /// * `max_processes` - Maximum active processes in job (0 = unlimited)
    ///
    /// # Returns
    /// * `Ok(JobObject)` - Job object ready for process assignment
    /// * `Err(String)` - Creation or configuration failed
    pub fn new(max_memory_bytes: u64, max_processes: u64) -> Result<Self, String> {
        unsafe {
            // Create unnamed job object
            let handle = CreateJobObjectW(None, None)
                .map_err(|e| format!("CreateJobObjectW failed: {e}"))?;

            if handle.is_invalid() {
                return Err("CreateJobObjectW returned invalid handle".to_string());
            }

            // Build limit flags
            let mut limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            if max_memory_bytes > 0 {
                limit_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            }
            if max_processes > 0 {
                limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            }

            // Configure extended limit information
            let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    LimitFlags: limit_flags,
                    ActiveProcessLimit: if max_processes > 0 {
                        max_processes as u32
                    } else {
                        0
                    },
                    ..Default::default()
                },
                ProcessMemoryLimit: if max_memory_bytes > 0 {
                    max_memory_bytes as usize
                } else {
                    0
                },
                ..Default::default()
            };

            let result = SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );

            if let Err(e) = result {
                let _ = CloseHandle(handle);
                return Err(format!("SetInformationJobObject failed: {e}"));
            }

            Ok(Self { handle })
        }
    }

    /// Assign the current process to this job object
    ///
    /// Once assigned, resource limits apply to this process and all
    /// child processes spawned from it.
    pub fn assign_current_process(&self) -> Result<(), String> {
        unsafe {
            let current = GetCurrentProcess();
            AssignProcessToJobObject(self.handle, current)
                .map_err(|e| format!("AssignProcessToJobObject failed: {e}"))
        }
    }

    /// Assign a child process to this job object by PID
    ///
    /// This allows kodegend to manage child process lifecycle:
    /// - When job handle is closed (daemon exit), all children are terminated
    /// - Works with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag
    ///
    /// # Arguments
    /// * `pid` - Process ID of child process to assign
    ///
    /// # Windows API Flow
    /// 1. OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, pid)
    /// 2. AssignProcessToJobObject(job_handle, process_handle)
    /// 3. CloseHandle(process_handle)
    ///
    /// # Errors
    /// - ERROR_ACCESS_DENIED: Child already in another job (Windows 7) or lacks permissions
    /// - ERROR_INVALID_PARAMETER: Invalid PID or process doesn't exist
    ///
    /// # Race Condition
    /// There's an unavoidable race between CreateProcess and AssignProcessToJobObject
    /// where the child could spawn its own children before being assigned. This is
    /// acceptable as it's a fundamental Windows limitation.
    ///
    /// See: https://stackoverflow.com/questions/17623541
    pub fn assign_process(&self, pid: u32) -> Result<(), String> {
        unsafe {
            // Open process handle with required permissions for job assignment
            let process_handle = OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE,
                false,  // Don't inherit handle
                pid,
            ).map_err(|e| format!("OpenProcess failed for PID {}: {}", pid, e))?;
            
            // Assign to job object
            let result = AssignProcessToJobObject(self.handle, process_handle);
            
            // Always close process handle (even if assignment fails)
            let _ = CloseHandle(process_handle);
            
            // Check result after cleanup
            result.map_err(|e| format!("AssignProcessToJobObject failed for PID {}: {}", pid, e))?;
            
            Ok(())
        }
    }

    /// Get the raw handle (for advanced use cases)
    #[allow(dead_code)]
    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_invalid() {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

// SAFETY: Job object handles can be sent between threads
unsafe impl Send for JobObject {}
unsafe impl Sync for JobObject {}

/// Apply resource limits to the current process via Job Object
///
/// This should be called early in daemon startup, before spawning
/// any child processes.
///
/// # Arguments
/// * `max_memory_bytes` - Maximum memory per process (0 = use default)
/// * `max_processes` - Maximum active processes (0 = use default)
///
/// # Returns
/// * `Ok(JobObject)` - Keep this alive for the lifetime of the daemon
/// * `Err(String)` - Failed to apply limits
pub fn apply_resource_limits(
    max_memory_bytes: u64,
    max_processes: u64,
) -> Result<JobObject, String> {
    let job = JobObject::new(max_memory_bytes, max_processes)?;
    job.assign_current_process()?;
    Ok(job)
}
