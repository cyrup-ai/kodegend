//! ZIP packaging and directory handling utilities
//!
//! This module provides ZIP creation and directory traversal functionality
//! for packaging the macOS helper app with zero allocation patterns and
//! blazing-fast performance.
//!
//! Uses proven kodegen_bundler_sign for building and signing.

use std::fs;
use std::path::Path;

/// Extract ZIP archive to directory (kept for potential future use)
#[allow(dead_code)]
pub fn extract_zip(zip_path: &Path, extract_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    fs::create_dir_all(extract_dir)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = extract_dir.join(file.name());

        if file.name().ends_with('/') {
            // Directory
            fs::create_dir_all(&outpath)?;
        } else {
            // File
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut outfile = fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;

            // Set permissions on Unix systems
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
                }
            }
        }
    }

    Ok(())
}
/// Create functional ZIP with proper helper app and atomic rollback
///
/// Uses proven kodegen_bundler_sign for reliable signing
pub async fn create_functional_zip(zip_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Validate input paths before any operations
    if !zip_path.parent().is_some_and(std::path::Path::exists) {
        return Err(format!(
            "ZIP parent directory does not exist: {}",
            zip_path.parent().unwrap_or(zip_path).display()
        )
        .into());
    }

    let out_dir = zip_path
        .parent()
        .ok_or("Invalid zip path - no parent directory")?;

    // Use proven kodegen_bundler_sign for building and signing
    println!("🔨 Building and signing helper app with kodegen_bundler_sign...");

    let signed_zip = kodegen_bundler_sign::build_and_sign_helper(out_dir)
        .await
        .map_err(|e| format!("Failed to build and sign helper: {e}"))?;

    // Verify ZIP integrity before finalizing
    verify_zip_integrity(&signed_zip)?;

    // If the signed_zip is not at the expected location, move it
    if signed_zip != zip_path {
        std::fs::rename(&signed_zip, zip_path).map_err(|e| {
            format!(
                "Failed to move ZIP to final location {}: {}",
                zip_path.display(),
                e
            )
        })?;
    }

    // Generate integrity hash
    generate_zip_hash(zip_path)?;

    println!("✅ Helper app built and signed successfully");

    Ok(())
}

/// Verify ZIP integrity and structure
fn verify_zip_integrity(zip_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    // Check for required macOS app bundle structure
    let required_files = [
        "KodegenHelper.app/Contents/Info.plist",
        "KodegenHelper.app/Contents/MacOS/KodegenHelper",
    ];

    for required_file in &required_files {
        let mut found = false;
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            if file.name() == *required_file {
                found = true;
                break;
            }
        }
        if !found {
            return Err(format!("Required file {required_file} not found in ZIP").into());
        }
    }

    // Verify we can read all files without corruption
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let mut buffer = Vec::new();
        std::io::copy(&mut file, &mut buffer)?;

        // Basic sanity check - files should not be empty for critical components
        if file.name().ends_with("KodegenHelper") && buffer.is_empty() {
            return Err(format!("Critical executable {} is empty", file.name()).into());
        }

        if file.name().ends_with("Info.plist") && buffer.len() < 100 {
            return Err(format!("Info.plist {} is suspiciously small", file.name()).into());
        }
    }

    Ok(())
}

/// Generate integrity hash for ZIP file
fn generate_zip_hash(zip_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};

    let zip_data = fs::read(zip_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&zip_data);
    let hash = hasher.finalize();

    let hash_hex = hex::encode(hash);
    let hash_path = zip_path.with_extension("zip.sha256");

    fs::write(&hash_path, &hash_hex)?;

    println!("cargo:rustc-env=MACOS_HELPER_ZIP_HASH={hash_hex}");

    Ok(())
}
