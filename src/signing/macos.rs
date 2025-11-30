//! macOS code signature verification using codesign command
//!
//! This module wraps the macOS codesign utility to verify code signatures
//! on macOS app bundles and executables.

use std::path::Path;
use std::process::Command;

/// Verify macOS code signature using codesign
///
/// This function validates that:
/// - The binary/app bundle has a valid code signature
/// - The signature covers all code and resources (--deep)
/// - The signature meets strict validation rules (--strict)
/// - The binary hasn't been modified since signing
///
/// # Errors
///
/// Returns error if:
/// - Binary is unsigned
/// - Signature is invalid
/// - Binary has been modified after signing
/// - codesign command is not available
pub fn verify_signature(app_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(app_path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Signature verification failed: {}", stderr).into());
    }

    Ok(())
}
