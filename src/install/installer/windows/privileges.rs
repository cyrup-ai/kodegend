//! Privilege management for Windows installations.

use std::mem;
use windows::Win32::Security::TOKEN_ELEVATION;

use super::InstallerError;

/// Check if we have sufficient privileges for service operations
pub(crate) fn check_privileges() -> Result<(), InstallerError> {
    use crate::platform::windows::TokenHandle;
    
    // Open current process token - handle auto-closed on drop
    let token = TokenHandle::open_current_process_query()
        .map_err(|_| InstallerError::PermissionDenied)?;

    unsafe {
        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut return_length: u32 = 0;

        windows::Win32::Security::GetTokenInformation(
            token.as_raw(),
            windows::Win32::Security::TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )
        .map_err(|_| InstallerError::PermissionDenied)?;

        if elevation.TokenIsElevated == 0 {
            return Err(InstallerError::PermissionDenied);
        }
    }
    // Token handle automatically closed here

    Ok(())
}
