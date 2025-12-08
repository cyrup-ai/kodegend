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
            .ok()
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
            .ok()
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
        CreateFileW(
            wide.as_ptr(),
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
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE,
        PIPE_TYPE_MESSAGE, PIPE_WAIT, PIPE_REJECT_REMOTE_CLIENTS,
    };

    // Convert path to wide string
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX.0,
            PIPE_TYPE_MESSAGE.0 | PIPE_READMODE_MESSAGE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0,
            max_instances,
            1024 * 1024, // 1MB output buffer
            1024 * 1024, // 1MB input buffer
            0,           // Default timeout
            None,        // Default security
        )
        .map_err(|e| io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to create named pipe {}: {}", path, e),
        ))?
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Invalid handle when creating named pipe {}", path),
        ));
    }

    Ok(unsafe { NamedPipeStream::from_handle(handle) })
}
