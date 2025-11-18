//! RAII wrappers for Windows handles.
//!
//! This module provides safe, zero-cost abstractions over Windows API handles
//! with automatic cleanup on drop.

use windows::Win32::System::Registry::{HKEY, RegCloseKey};
use windows::Win32::System::Services::{CloseServiceHandle, SC_HANDLE};

/// RAII wrapper for Service Control Manager handle
pub(super) struct ScManagerHandle(pub(super) SC_HANDLE);

impl ScManagerHandle {
    #[inline]
    pub(super) fn handle(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ScManagerHandle {
    #[inline]
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

/// RAII wrapper for Service handle
pub(super) struct ServiceHandle(pub(super) SC_HANDLE);

impl ServiceHandle {
    #[inline]
    pub(super) fn handle(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ServiceHandle {
    #[inline]
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

/// RAII wrapper for Registry key handle
pub(super) struct RegistryHandle(pub(super) HKEY);

impl RegistryHandle {
    #[inline]
    pub(super) fn handle(&self) -> HKEY {
        self.0
    }
}

impl Drop for RegistryHandle {
    #[inline]
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
}
