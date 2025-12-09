//! Windows Named Pipe wrapper providing Read/Write traits
//!
//! Implements identical interface to UnixStream for cross-platform IPC.

use std::io::{self, Read, Write};
use windows::Win32::Foundation::{HANDLE, CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};

/// Windows Named Pipe stream wrapper
///
/// Provides Read/Write traits over Windows HANDLE for cross-platform compatibility.
/// HANDLE is automatically closed on drop.
pub struct NamedPipeStream {
    handle: HANDLE,
}

impl NamedPipeStream {
    /// Create from raw Windows HANDLE
    ///
    /// # Safety
    /// - Caller must ensure handle is valid and open
    /// - Caller must transfer ownership (handle will be closed on drop)
    pub unsafe fn from_handle(handle: HANDLE) -> Self {
        debug_assert!(handle != INVALID_HANDLE_VALUE);
        Self { handle }
    }

    /// Get raw handle (for low-level operations if needed)
    pub fn as_raw_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Read for NamedPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0u32;

        unsafe {
            ReadFile(
                self.handle,
                Some(buf),
                Some(&mut bytes_read),
                None,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ReadFile failed: {}", e)))?;
        }

        Ok(bytes_read as usize)
    }
}

impl Write for NamedPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0u32;

        unsafe {
            WriteFile(
                self.handle,
                Some(buf),
                Some(&mut bytes_written),
                None,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("WriteFile failed: {}", e)))?;
        }

        Ok(bytes_written as usize)
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
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to create named pipe {}: {:?}", path, unsafe { windows::Win32::Foundation::GetLastError() }),
        ));
    }

    Ok(unsafe { NamedPipeStream::from_handle(handle) })
}
