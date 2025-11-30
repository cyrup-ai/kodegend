//! Cross-platform code signature verification
//!
//! This module provides platform-specific signature verification for executables:
//! - Windows: Authenticode via WinVerifyTrust API
//! - macOS: Code signing via codesign command
//! - Linux: GPG signature verification (future)

use std::path::Path;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

/// Verify the code signature of an executable
///
/// This function performs platform-specific signature verification:
/// - **Windows**: Validates Authenticode signature using WinVerifyTrust API,
///   verifies certificate chain, and checks publisher identity
/// - **macOS**: Validates code signature using codesign --verify
/// - **Linux**: Returns Ok (no verification implemented yet)
///
/// # Security Requirements
///
/// - Binary must be signed with valid certificate
/// - Certificate must chain to trusted root
/// - Certificate must not be expired or revoked
/// - Publisher must match expected identity (platform-specific)
///
/// # Errors
///
/// Returns error if:
/// - Binary is unsigned
/// - Signature is invalid or tampered
/// - Certificate is expired, revoked, or untrusted
/// - Publisher doesn't match expected identity
/// - Signature verification API fails
pub fn verify_signature(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        windows::verify_signature(path)
    }

    #[cfg(target_os = "macos")]
    {
        macos::verify_signature(path)
    }

    #[cfg(target_os = "linux")]
    {
        linux::verify_signature(path)
    }
}
