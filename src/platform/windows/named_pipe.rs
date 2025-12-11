//! Windows Named Pipe wrapper providing Read/Write traits
//!
//! Implements identical interface to UnixStream for cross-platform IPC.

use std::io::{self, Read, Write};
use std::time::Duration;
use windows::Win32::Foundation::{HANDLE, CloseHandle, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::{OVERLAPPED, GetOverlappedResult, CancelIo};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

/// RAII guard for Windows event handle cleanup
struct EventGuard(HANDLE);

impl Drop for EventGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Windows Named Pipe stream wrapper
///
/// Provides Read/Write traits over Windows HANDLE for cross-platform compatibility.
/// HANDLE is automatically closed on drop.
pub struct NamedPipeStream {
    handle: HANDLE,
    read_timeout: Option<Duration>,   // NEW: Store timeout setting
    write_timeout: Option<Duration>,  // NEW: For future write timeout support
}

impl NamedPipeStream {
    /// Create from raw Windows HANDLE
    ///
    /// # Safety
    /// - Caller must ensure handle is valid and open
    /// - Caller must transfer ownership (handle will be closed on drop)
    pub unsafe fn from_handle(handle: HANDLE) -> Self {
        debug_assert!(handle != INVALID_HANDLE_VALUE);
        Self { 
            handle,
            read_timeout: None,    // Default: no timeout (backward compatible)
            write_timeout: None,
        }
    }

    /// Get raw handle (for low-level operations if needed)
    pub fn as_raw_handle(&self) -> HANDLE {
        self.handle
    }
    
    /// Set read timeout for this pipe
    /// 
    /// Uses overlapped I/O internally to enforce timeout.
    /// Compatible with Unix socket `set_read_timeout()` API.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeout = timeout;
        Ok(())
    }
    
    /// Set write timeout for this pipe
    /// 
    /// Uses overlapped I/O internally to enforce timeout.
    /// Compatible with Unix socket `set_write_timeout()` API.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.write_timeout = timeout;
        Ok(())
    }
    
    /// Synchronous write (original implementation)
    #[inline]
    fn write_sync(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0u32;
        unsafe {
            WriteFile(
                self.handle,
                Some(buf),
                Some(&mut bytes_written),
                None,  // No overlapped structure
            )
            .map_err(|e| io::Error::other(format!("WriteFile failed: {}", e)))?;
        }
        Ok(bytes_written as usize)
    }
    
    /// Write with timeout using overlapped I/O
    fn write_with_timeout(&mut self, buf: &[u8], timeout: Duration) -> io::Result<usize> {
        // Create event for overlapped operation
        let event_handle = unsafe {
            CreateEventW(None, true, false, None)
                .map_err(|e| io::Error::other(format!("CreateEventW failed: {}", e)))?
        };
        
        // RAII cleanup
        let _guard = EventGuard(event_handle);
        
        // Initialize overlapped structure
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event_handle;
        
        let mut bytes_written = 0u32;
        
        // Start asynchronous write
        let write_result = unsafe {
            WriteFile(
                self.handle,
                Some(buf),
                Some(&mut bytes_written),
                Some(&mut overlapped),
            )
        };
        
        match write_result {
            Ok(_) => {
                // Write completed synchronously
                Ok(bytes_written as usize)
            }
            Err(e) => {
                let error_code = unsafe { windows::Win32::Foundation::GetLastError() };
                
                // ERROR_IO_PENDING (997) means async operation started
                if error_code.0 == 997 {
                    // Wait for completion with timeout
                    let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
                    
                    let wait_result = unsafe {
                        WaitForSingleObject(event_handle, timeout_ms)
                    };
                    
                    match wait_result {
                        WAIT_OBJECT_0 => {
                            // Write completed - get result
                            let mut transferred = 0u32;
                            unsafe {
                                GetOverlappedResult(
                                    self.handle,
                                    &overlapped,
                                    &mut transferred,
                                    false,
                                )
                                .map_err(|e| io::Error::other(format!("GetOverlappedResult failed: {}", e)))?;
                            }
                            Ok(transferred as usize)
                        }
                        WAIT_TIMEOUT => {
                            // Timeout expired
                            unsafe {
                                let _ = CancelIo(self.handle);
                            }
                            Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("Write timeout after {:?}", timeout)
                            ))
                        }
                        _ => {
                            Err(io::Error::other(format!("WaitForSingleObject failed: {:?}", wait_result)))
                        }
                    }
                } else {
                    // Actual error
                    Err(io::Error::other(format!("WriteFile failed: {}", e)))
                }
            }
        }
    }
}

impl Read for NamedPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If no timeout set, use synchronous read (fast path)
        if let Some(timeout) = self.read_timeout {
            // Timeout set: use overlapped I/O
            self.read_with_timeout(buf, timeout)
        } else {
            self.read_sync(buf)
        }
    }
}

impl NamedPipeStream {
    /// Synchronous read (original implementation)
    #[inline]
    fn read_sync(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0u32;
        unsafe {
            ReadFile(
                self.handle,
                Some(buf),
                Some(&mut bytes_read),
                None,  // No overlapped structure
            )
            .map_err(|e| io::Error::other(format!("ReadFile failed: {}", e)))?;
        }
        Ok(bytes_read as usize)
    }
    
    /// Read with timeout using overlapped I/O
    fn read_with_timeout(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        use windows::Win32::System::IO::GetOverlappedResult;
        
        // Create event for overlapped operation
        let event_handle = unsafe {
            CreateEventW(
                None,        // Default security
                true,        // Manual reset
                false,       // Initially non-signaled
                None,        // No name
            )
            .map_err(|e| io::Error::other(format!("CreateEventW failed: {}", e)))?
        };
        
        // Ensure event is cleaned up on scope exit
        let _guard = EventGuard(event_handle);
        
        // Initialize overlapped structure
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event_handle;
        
        let mut bytes_read = 0u32;
        
        // Start asynchronous read
        let read_result = unsafe {
            ReadFile(
                self.handle,
                Some(buf),
                Some(&mut bytes_read),
                Some(&mut overlapped),
            )
        };
        
        // Handle immediate completion or pending operation
        match read_result {
            Ok(_) => {
                // Read completed synchronously
                Ok(bytes_read as usize)
            }
            Err(e) => {
                let error_code = unsafe { windows::Win32::Foundation::GetLastError() };
                
                // ERROR_IO_PENDING means async operation started successfully
                if error_code.0 == 997 {  // ERROR_IO_PENDING
                    // Wait for completion with timeout
                    let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
                    
                    let wait_result = unsafe {
                        WaitForSingleObject(event_handle, timeout_ms)
                    };
                    
                    match wait_result {
                        WAIT_OBJECT_0 => {
                            // Operation completed - get result
                            let mut transferred = 0u32;
                            unsafe {
                                GetOverlappedResult(
                                    self.handle,
                                    &overlapped,
                                    &mut transferred,
                                    false,  // Don't wait (already signaled)
                                )
                                .map_err(|e| io::Error::other(format!("GetOverlappedResult failed: {}", e)))?;
                            }
                            Ok(transferred as usize)
                        }
                        WAIT_TIMEOUT => {
                            // Timeout expired
                            // Cancel pending I/O operation
                            unsafe {
                                use windows::Win32::System::IO::CancelIo;
                                let _ = CancelIo(self.handle);
                            }
                            Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("Read timeout after {:?}", timeout)
                            ))
                        }
                        _ => {
                            Err(io::Error::other(format!("WaitForSingleObject failed: {:?}", wait_result)))
                        }
                    }
                } else {
                    // Actual error
                    Err(io::Error::other(format!("ReadFile failed: {}", e)))
                }
            }
        }
    }
}

impl Write for NamedPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // If no timeout set, use synchronous write (fast path)
        if let Some(timeout) = self.write_timeout {
            // Timeout set: use overlapped I/O
            self.write_with_timeout(buf, timeout)
        } else {
            self.write_sync(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Named pipes flush automatically with each WriteFile call
        // No explicit FlushFileBuffers needed for message-mode pipes
        Ok(())
    }
}

impl Drop for NamedPipeStream {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// SAFETY: Windows HANDLE is a kernel object identifier (essentially an index into a
// per-process handle table). HANDLEs can be safely sent between threads as they
// reference kernel objects that are process-global. The kernel handles synchronization.
// This is required because windows-rs HANDLE contains *mut c_void which isn't Send.
unsafe impl Send for NamedPipeStream {}

/// Connect to named pipe at given path (client-side)
///
/// # Arguments
/// - `path`: Named pipe path (e.g., r"\\.\pipe\kodegend\status")
///
/// # Returns
/// Connected NamedPipeStream or IO error
pub fn connect_named_pipe(path: &str) -> io::Result<NamedPipeStream> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_SHARE_READ, OPEN_EXISTING,
    };

    // Convert path to wide string for Windows API
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        use windows::core::PCWSTR;
        CreateFileW(
            PCWSTR::from_raw(wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to connect to named pipe {}: {}", path, e),
        ))?
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Invalid handle when connecting to {}", path),
        ));
    }

    Ok(unsafe { NamedPipeStream::from_handle(handle) })
}

/// Create named pipe server (server-side)
///
/// # Arguments
/// - `path`: Named pipe path (e.g., r"\\.\pipe\kodegend\status")
/// - `max_instances`: Maximum concurrent clients (use 254 for unlimited-like behavior)
///
/// # Returns
/// NamedPipeStream ready to accept connection via ConnectNamedPipe
pub fn create_named_pipe_server(path: &str, max_instances: u32) -> io::Result<NamedPipeStream> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::System::Pipes::{CreateNamedPipeW, NAMED_PIPE_MODE};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;

    // Pipe mode constants
    const PIPE_TYPE_MESSAGE: u32 = 0x00000004;
    const PIPE_READMODE_MESSAGE: u32 = 0x00000002;
    const PIPE_WAIT: u32 = 0x00000000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x00000008;

    // Convert path to wide string
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        use windows::core::PCWSTR;
        CreateNamedPipeW(
            PCWSTR::from_raw(wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            NAMED_PIPE_MODE(PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS),
            max_instances,
            1024 * 1024, // 1MB output buffer
            1024 * 1024, // 1MB input buffer
            0,           // Default timeout
            None,        // Default security
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            format!("Failed to create named pipe {}: {:?}", path, unsafe { windows::Win32::Foundation::GetLastError() }),
        ));
    }

    Ok(unsafe { NamedPipeStream::from_handle(handle) })
}
