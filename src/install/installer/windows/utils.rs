//! Utility functions and constants for Windows operations.

use super::InstallerError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

// Constants for zero-allocation buffers
pub(super) const MAX_PATH: usize = 260;
pub(super) const MAX_SERVICE_NAME: usize = 256;
pub(super) const MAX_DESCRIPTION: usize = 512;
pub(super) const MAX_DEPENDENCIES: usize = 1024;

/// Convert string to wide (UTF-16) with zero allocation
#[inline]
pub(super) fn str_to_wide(s: &str, buffer: &mut [u16]) -> Result<(), InstallerError> {
    let wide: Vec<u16> = OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    if wide.len() > buffer.len() {
        return Err(InstallerError::System(format!(
            "String '{}' too long for buffer (max {})",
            s,
            buffer.len()
        )));
    }

    buffer[..wide.len()].copy_from_slice(&wide);
    Ok(())
}

/// Convert string to wide (UTF-16) returning a Vec
#[inline]
pub(crate) fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
