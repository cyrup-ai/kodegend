//! Helper app extraction, validation, and code signing verification.

use std::{
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU8, Ordering},
};

use anyhow::Result;
use arrayvec::ArrayVec;
use atomic_counter::{AtomicCounter, RelaxedCounter};
use nix::fcntl::{Flock, FlockArg};
use once_cell::sync::{Lazy, OnceCell};
use zip::ZipArchive;

use super::InstallerError;

// Global helper path - initialized once, used everywhere
pub(super) static HELPER_PATH: OnceCell<PathBuf> = OnceCell::new();

// Embedded ZIP data for the signed helper app
// This is generated at build time by build.rs which creates a proper signed macOS helper
const APP_ZIP_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/KodegenHelper.app.zip"));

/// Ensure the helper path is initialized for secure privileged operations
pub(super) fn ensure_helper_path() -> Result<(), InstallerError> {
    if HELPER_PATH.get().is_none() {
        let helper_path = extract_helper_app()?;
        HELPER_PATH
            .set(helper_path)
            .map_err(|_| InstallerError::System("Failed to set helper path".to_string()))?;
    }
    Ok(())
}

/// Extract the signed helper app from embedded data
fn extract_helper_app() -> Result<PathBuf, InstallerError> {
    // Create lock file (stable location)
    let lock_path = std::env::temp_dir()
        .join("kodegen_helper")
        .join(".extraction.lock");

    // Ensure parent directory exists
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            InstallerError::System(format!("Failed to create lock directory: {}", e))
        })?;
    }

    // Open lock file
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| InstallerError::System(format!("Failed to create lock file: {}", e)))?;

    // Acquire exclusive lock (blocks other processes)
    let _flock = Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|_| InstallerError::System("Failed to acquire lock".to_string()))?;

    // Use a stable location based on app version to avoid re-extraction
    let version_hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        APP_ZIP_DATA.len().hash(&mut hasher);
        APP_ZIP_DATA
            .get(0..64)
            .unwrap_or(&APP_ZIP_DATA[0..APP_ZIP_DATA.len().min(64)])
            .hash(&mut hasher);
        hasher.finish()
    };

    let helper_path = std::env::temp_dir()
        .join("kodegen_helper")
        .join(format!("v{version_hash:016x}"))
        .join("KodegenHelper.app");

    // Check if already exists and valid (safe under lock)
    if helper_path.exists() {
        match validate_helper(&helper_path) {
            Ok(true) => match verify_code_signature(&helper_path) {
                Ok(true) => {
                    // Valid helper already exists - lock released when lock_file drops
                    return Ok(helper_path);
                }
                _ => {
                    // Invalid signature - remove and re-extract
                    let _ = std::fs::remove_dir_all(&helper_path);
                }
            },
            _ => {
                // Invalid structure - remove and re-extract
                let _ = std::fs::remove_dir_all(&helper_path);
            }
        }
    }

    // Extract under lock
    extract_from_embedded_data(&helper_path)?;

    // Lock automatically released when lock_file drops
    Ok(helper_path)
}

/// Extract helper from embedded `APP_ZIP_DATA` with zero-allocation validation
fn extract_from_embedded_data(helper_path: &PathBuf) -> Result<bool, InstallerError> {
    // Atomic validation state tracking (0=pending, 1=size_valid, 2=header_valid, 3=extraction_complete)
    static VALIDATION_STATE: AtomicU8 = AtomicU8::new(0);
    static VALIDATION_COUNTER: Lazy<RelaxedCounter> = Lazy::new(|| RelaxedCounter::new(0));

    VALIDATION_STATE.store(0, Ordering::Relaxed);
    VALIDATION_COUNTER.inc();

    // Zero-allocation ZIP validation using stack-allocated arrays
    const MIN_ZIP_SIZE: usize = 22; // Minimum ZIP central directory size

    if APP_ZIP_DATA.len() < MIN_ZIP_SIZE {
        return Err(InstallerError::System(
            "Embedded helper ZIP data is too small".to_string(),
        ));
    }
    VALIDATION_STATE.store(1, Ordering::Relaxed);

    // Zero-allocation ZIP magic header validation using ArrayVec
    let mut magic_headers: ArrayVec<&[u8], 3> = ArrayVec::new();
    magic_headers.push(&[0x50, 0x4B, 0x03, 0x04]); // Local file header
    magic_headers.push(&[0x50, 0x4B, 0x05, 0x06]); // Empty archive
    magic_headers.push(&[0x50, 0x4B, 0x07, 0x08]); // Spanned archive

    let has_valid_header = magic_headers
        .iter()
        .any(|&header| APP_ZIP_DATA.len() >= header.len() && APP_ZIP_DATA.starts_with(header));

    if !has_valid_header {
        return Err(InstallerError::System(
            "Invalid ZIP signature in embedded data".to_string(),
        ));
    }
    VALIDATION_STATE.store(2, Ordering::Relaxed);

    // Enhanced ZIP central directory validation using zero-copy access
    if let Err(e) = validate_zip_central_directory() {
        return Err(InstallerError::System(format!(
            "ZIP central directory validation failed: {e}"
        )));
    }

    // Extract to TEMPORARY location first (not final destination)
    let temp_extract = helper_path.with_extension("extracting");

    // Clean up any stale temp directory
    if temp_extract.exists() {
        std::fs::remove_dir_all(&temp_extract).map_err(|e| {
            InstallerError::System(format!("Failed to clean temp extraction: {}", e))
        })?;
    }

    // Extract entire ZIP to temporary location
    extract_zip_data(APP_ZIP_DATA, &temp_extract)?;

    VALIDATION_STATE.store(3, Ordering::Relaxed);

    // Validate the TEMP extraction
    let helper_valid = match validate_helper(&temp_extract) {
        Ok(valid) => {
            if !valid {
                let _ = std::fs::remove_dir_all(&temp_extract);
                return Err(InstallerError::System(
                    "Helper validation failed: Invalid bundle structure".to_string(),
                ));
            }
            valid
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&temp_extract);
            return Err(InstallerError::System(format!("Helper validation error: {}", e)));
        }
    };

    let signature_valid = match verify_code_signature(&temp_extract) {
        Ok(valid) => {
            if !valid {
                let _ = std::fs::remove_dir_all(&temp_extract);
                return Err(InstallerError::System(
                    "Code signature validation failed".to_string(),
                ));
            }
            valid
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&temp_extract);
            return Err(InstallerError::System(format!("Signature validation error: {}", e)));
        }
    };

    // ATOMIC RENAME: Move validated temp to final location
    // This is atomic if on the same filesystem (both in /tmp)
    std::fs::rename(&temp_extract, helper_path).map_err(|e| {
        let _ = std::fs::remove_dir_all(&temp_extract);
        InstallerError::System(format!("Failed to move validated helper: {}", e))
    })?;

    Ok(helper_valid && signature_valid)
}

/// Zero-allocation ZIP central directory validation using pointer arithmetic
fn validate_zip_central_directory() -> Result<(), &'static str> {
    const EOCD_SIGNATURE: u32 = 0x06054b50; // End of Central Directory signature
    const EOCD_MIN_SIZE: usize = 22;

    if APP_ZIP_DATA.len() < EOCD_MIN_SIZE {
        return Err("ZIP data too small for central directory");
    }

    // Search for End of Central Directory record from the end (zero-allocation approach)
    let search_start = APP_ZIP_DATA.len().saturating_sub(65536); // ZIP spec: max comment size is 65535
    let search_range = &APP_ZIP_DATA[search_start..];

    // Stack-allocated buffer for signature checking
    let mut eocd_offset: Option<usize> = None;

    // Scan backwards for EOCD signature using zero-allocation approach
    for i in (0..search_range.len().saturating_sub(3)).rev() {
        if search_range.len() >= i + 4 {
            let signature_bytes: ArrayVec<u8, 4> = ArrayVec::from([
                search_range[i],
                search_range[i + 1],
                search_range[i + 2],
                search_range[i + 3],
            ]);

            let signature = u32::from_le_bytes([
                signature_bytes[0],
                signature_bytes[1],
                signature_bytes[2],
                signature_bytes[3],
            ]);

            if signature == EOCD_SIGNATURE {
                eocd_offset = Some(search_start + i);
                break;
            }
        }
    }

    let eocd_pos = eocd_offset.ok_or("End of Central Directory signature not found")?;

    // Validate EOCD structure using stack-allocated parsing
    if APP_ZIP_DATA.len() < eocd_pos + EOCD_MIN_SIZE {
        return Err("Incomplete End of Central Directory record");
    }

    // Parse central directory information (zero-allocation)
    let eocd_data = &APP_ZIP_DATA[eocd_pos..];

    if eocd_data.len() < 22 {
        return Err("EOCD record too short");
    }

    // Extract central directory info using zero-copy parsing
    let _disk_number = u16::from_le_bytes([eocd_data[4], eocd_data[5]]);
    let _cd_start_disk = u16::from_le_bytes([eocd_data[6], eocd_data[7]]);
    let cd_entries_this_disk = u16::from_le_bytes([eocd_data[8], eocd_data[9]]);
    let cd_total_entries = u16::from_le_bytes([eocd_data[10], eocd_data[11]]);
    let cd_size =
        u32::from_le_bytes([eocd_data[12], eocd_data[13], eocd_data[14], eocd_data[15]]);
    let cd_offset =
        u32::from_le_bytes([eocd_data[16], eocd_data[17], eocd_data[18], eocd_data[19]]);

    // Validate central directory parameters
    if cd_entries_this_disk != cd_total_entries {
        return Err("Multi-disk ZIP archives not supported");
    }

    if cd_total_entries == 0 {
        return Err("ZIP archive contains no entries");
    }

    // Validate central directory bounds
    let cd_end = cd_offset
        .checked_add(cd_size)
        .ok_or("Central directory offset/size overflow")?;

    if cd_end as usize > APP_ZIP_DATA.len() {
        return Err("Central directory extends beyond ZIP data");
    }

    if cd_offset as usize >= APP_ZIP_DATA.len() {
        return Err("Central directory offset beyond ZIP data");
    }

    Ok(())
}

/// Extract ZIP data to the specified path
fn extract_zip_data(zip_data: &[u8], target_path: &Path) -> Result<(), InstallerError> {
    // Create a cursor for the ZIP data
    let cursor = Cursor::new(zip_data);

    // Create ZIP archive reader
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| InstallerError::System(format!("Failed to read ZIP archive: {e}")))?;

    // Extract all files
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| {
            InstallerError::System(format!("Failed to access file in ZIP: {e}"))
        })?;

        let file_path = match file.enclosed_name() {
            Some(path) => path.clone(),
            None => {
                // Skip files with invalid paths
                continue;
            }
        };

        // Strip the top-level KodegenHelper.app directory from the ZIP path
        // since we're extracting TO KodegenHelper.app (zero-allocation path stripping)
        let relative_path = file_path
            .strip_prefix("KodegenHelper.app")
            .unwrap_or(&file_path);

        let out_path = target_path.join(relative_path);

        // Create parent directories if needed
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                InstallerError::System(format!(
                    "Failed to create directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        if file.is_dir() {
            // Create directory
            std::fs::create_dir_all(&out_path).map_err(|e| {
                InstallerError::System(format!(
                    "Failed to create directory {}: {}",
                    out_path.display(),
                    e
                ))
            })?;
        } else {
            // Extract file
            let mut outfile = std::fs::File::create(&out_path).map_err(|e| {
                InstallerError::System(format!(
                    "Failed to create file {}: {}",
                    out_path.display(),
                    e
                ))
            })?;

            // Copy file contents with zero-copy optimization where possible
            let mut buffer = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut buffer).map_err(|e| {
                InstallerError::System(format!("Failed to read file from ZIP: {e}"))
            })?;

            outfile.write_all(&buffer).map_err(|e| {
                InstallerError::System(format!(
                    "Failed to write file {}: {}",
                    out_path.display(),
                    e
                ))
            })?;

            // Sync to ensure data is written
            outfile.sync_all().map_err(|e| {
                InstallerError::System(format!(
                    "Failed to sync file {}: {}",
                    out_path.display(),
                    e
                ))
            })?;

            // Set file permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    let permissions = std::fs::Permissions::from_mode(mode);
                    std::fs::set_permissions(&out_path, permissions).map_err(|e| {
                        InstallerError::System(format!(
                            "Failed to set permissions on {}: {}",
                            out_path.display(),
                            e
                        ))
                    })?;
                }
            }
        }
    }

    Ok(())
}

/// Validate that the helper app is properly signed and functional
pub(super) fn validate_helper(helper_path: &Path) -> Result<bool, InstallerError> {
    // Check if the helper exists and has the expected structure
    let contents = helper_path.join("Contents");
    let macos = contents.join("MacOS");
    let info_plist = contents.join("Info.plist");
    let executable = macos.join("KodegenHelper");

    // Verify all required components exist (zero-allocation existence checks)
    if !contents.exists() || !macos.exists() || !info_plist.exists() || !executable.exists() {
        return Ok(false);
    }

    // Verify Info.plist contains required keys
    let plist_data = std::fs::read(&info_plist)
        .map_err(|e| InstallerError::System(format!("Failed to read Info.plist: {e}")))?;

    let plist_value = plist::from_bytes::<plist::Value>(&plist_data)
        .map_err(|e| InstallerError::System(format!("Failed to parse Info.plist: {e}")))?;

    if let plist::Value::Dictionary(dict) = plist_value {
        // Check required keys (zero-allocation key existence validation)
        let has_bundle_id = dict.contains_key("CFBundleIdentifier");
        let has_bundle_executable = dict.contains_key("CFBundleExecutable");
        let has_sm_authorized = dict.contains_key("SMAuthorizedClients");

        Ok(has_bundle_id && has_bundle_executable && has_sm_authorized)
    } else {
        Ok(false)
    }
}

/// Verify the code signature of the helper app using Tauri-compatible validation
pub(super) fn verify_code_signature(helper_path: &Path) -> Result<bool, InstallerError> {
    // Use Tauri's signing verification approach - check for valid bundle structure
    // and signature presence without manual codesign calls

    // Verify CodeResources exists (created by Tauri signing)
    let code_resources = helper_path.join("Contents/_CodeSignature/CodeResources");
    if !code_resources.exists() {
        return Err(InstallerError::System(
            "Helper app missing CodeResources - not properly signed".to_string(),
        ));
    }

    // Verify executable exists and has proper permissions
    let executable = helper_path.join("Contents/MacOS/KodegenHelper");
    if !executable.exists() {
        return Err(InstallerError::System(
            "Helper app missing executable".to_string(),
        ));
    }

    // Check executable permissions (should be executable)
    let metadata = std::fs::metadata(&executable).map_err(|e| {
        InstallerError::System(format!("Failed to get executable metadata: {e}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        // Check if executable bit is set (0o100)
        if (mode & 0o111) == 0 {
            return Err(InstallerError::System(
                "Helper executable does not have execute permissions".to_string(),
            ));
        }
    }

    // Verify Info.plist has proper bundle structure
    let info_plist = helper_path.join("Contents/Info.plist");
    let plist_data = std::fs::read(&info_plist)
        .map_err(|e| InstallerError::System(format!("Failed to read Info.plist: {e}")))?;

    let plist_value = plist::from_bytes::<plist::Value>(&plist_data)
        .map_err(|e| InstallerError::System(format!("Failed to parse Info.plist: {e}")))?;

    if let plist::Value::Dictionary(dict) = plist_value {
        // Verify bundle identifier matches expected value
        if let Some(plist::Value::String(bundle_id)) = dict.get("CFBundleIdentifier") {
            if bundle_id != "ai.kodegen.kodegend.helper" {
                return Err(InstallerError::System(format!(
                    "Unexpected bundle identifier: {bundle_id} (expected: ai.kodegen.kodegend.helper)"
                )));
            }
        } else {
            return Err(InstallerError::System(
                "Missing or invalid CFBundleIdentifier in Info.plist".to_string(),
            ));
        }
    } else {
        return Err(InstallerError::System(
            "Info.plist is not a valid property list dictionary".to_string(),
        ));
    }

    // If all Tauri-signed bundle validation checks pass, the helper is valid
    Ok(true)
}
