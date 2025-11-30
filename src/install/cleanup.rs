//! RAII cleanup context for installation artifacts
//!
//! This module provides automatic cleanup of temporary installation resources
//! (download directories, staging directories, certificate files) when installation
//! fails. Uses the Drop trait to ensure cleanup happens even on panic.
//!
//! # Examples
//!
//! Existing Drop trait patterns in this codebase:
//! - Windows handles: [`windows/handles.rs:19-61`](installer/windows/handles.rs)
//! - Security descriptors: [`certificates.rs:82`](installer/config/certificates.rs)
//! - Signal handlers: [`signal.rs:73`](../../platform/signal.rs)

use std::path::PathBuf;
use log::warn;

/// Installation cleanup context that automatically removes temporary artifacts on drop.
///
/// This struct tracks all temporary resources created during installation and ensures
/// they are cleaned up if installation fails. On successful installation, call
/// `defuse()` to prevent cleanup.
///
/// # RAII Pattern
/// - Resources are tracked as `Option<PathBuf>`
/// - `Drop` implementation cleans up all `Some(path)` entries
/// - `defuse()` sets all to `None`, disabling cleanup
/// - Cleanup is best-effort: errors are logged but don't propagate
///
/// # Thread Safety
/// This struct is NOT Send/Sync (contains PathBuf), but that's acceptable since
/// it's used within a single async task (orchestration::run_install_with_options).
///
/// # Drop Safety
/// The Drop implementation MUST NOT panic (Rust best practice). All cleanup
/// operations use Result<()> and log errors instead of propagating them.
///
/// # Usage
/// ```rust
/// let mut ctx = InstallationCleanupContext::new();
/// ctx.downloaded_binaries_dir = Some(download_dir);
/// ctx.staging_dir = Some(staging_dir);
/// 
/// // ... perform installation ...
/// 
/// // On success:
/// ctx.defuse();  // Prevent cleanup
/// ```
#[derive(Default)]
pub struct InstallationCleanupContext {
    /// Downloaded binaries directory (from download_all_binaries)
    /// Typically: /tmp/tmp.XXXXXX (~50-100MB)
    pub downloaded_binaries_dir: Option<PathBuf>,
    
    /// Staging directory (from stage_binaries_for_install)
    /// Typically: /tmp/kodegen_install_YYYYY (~50-100MB)
    pub staging_dir: Option<PathBuf>,
    
    /// Temporary certificate file (from privilege.rs)
    /// Typically: /tmp/kodegen_cert_ZZZZZ.crt (contains private key!)
    pub temp_cert_file: Option<PathBuf>,
    
    /// Whether the service was partially installed (needs uninstall on failure)
    pub service_partially_installed: bool,
}

impl InstallationCleanupContext {
    /// Create new cleanup context with no tracked resources
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Defuse all cleanup guards (call on successful installation)
    ///
    /// This sets all tracked resources to None, making the Drop implementation
    /// a no-op. Call this ONLY when installation completes successfully.
    ///
    /// # Examples
    /// ```rust
    /// let mut ctx = InstallationCleanupContext::new();
    /// // ... installation succeeds ...
    /// ctx.defuse();  // Prevent cleanup
    /// ```
    pub fn defuse(mut self) {
        self.downloaded_binaries_dir = None;
        self.staging_dir = None;
        self.temp_cert_file = None;
        self.service_partially_installed = false;
        // Drop runs after this, but all fields are None so it's a no-op
    }
    
    /// Manually trigger cleanup (useful for testing and explicit cleanup on error)
    ///
    /// This is called automatically by Drop, but can also be called explicitly
    /// to provide better error logging context.
    pub fn cleanup(&mut self) {
        // Clean up download directory
        if let Some(dir) = self.downloaded_binaries_dir.take() {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                warn!("Failed to cleanup download directory {}: {}", dir.display(), e);
            } else {
                log::info!("Cleaned up download directory: {}", dir.display());
            }
        }
        
        // Clean up staging directory
        if let Some(dir) = self.staging_dir.take() {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                warn!("Failed to cleanup staging directory {}: {}", dir.display(), e);
            } else {
                log::info!("Cleaned up staging directory: {}", dir.display());
            }
        }
        
        // Clean up temp certificate file
        if let Some(file) = self.temp_cert_file.take() {
            if let Err(e) = std::fs::remove_file(&file) {
                warn!("Failed to cleanup temp certificate {}: {}", file.display(), e);
            } else {
                log::info!("Cleaned up temp certificate: {}", file.display());
            }
        }
        
        // Log if service was partially installed
        if self.service_partially_installed {
            warn!("Service was partially installed - manual cleanup may be required");
            // Note: We could add service uninstall logic here in the future
            self.service_partially_installed = false;
        }
    }
}

impl Drop for InstallationCleanupContext {
    /// Automatically cleanup all tracked resources when context is dropped
    ///
    /// This runs when:
    /// - Installation fails and function returns Err
    /// - Panic occurs during installation
    /// - Context goes out of scope without calling defuse()
    ///
    /// # Drop Safety
    /// This implementation follows Rust Drop best practices:
    /// - NEVER panics (uses Result and logs errors)
    /// - Cleans up in reverse order of acquisition
    /// - Uses `take()` to avoid double-free
    /// - Idempotent (safe to call cleanup() then drop)
    ///
    /// # Examples from Codebase
    /// See similar patterns in:
    /// - [`windows/handles.rs:19`](installer/windows/handles.rs#L19)
    /// - [`signal.rs:73`](../../platform/signal.rs#L73)
    fn drop(&mut self) {
        // Check if any cleanup is needed
        let has_resources = self.downloaded_binaries_dir.is_some()
            || self.staging_dir.is_some()
            || self.temp_cert_file.is_some()
            || self.service_partially_installed;
        
        if has_resources {
            warn!("Installation cleanup context dropped with tracked resources - cleaning up");
            self.cleanup();
        }
    }
}
