//! Package extraction for different platform formats
//!
//! Handles extracting binaries from .deb, .rpm, .dmg, and .zip packages.
//! Uses pure Rust implementations (no external command-line tools required).

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use tar::Archive;
use flate2::read::GzDecoder;
use super::platform::Platform;

/// Extract binary from .deb package (ar archive → data.tar.gz → usr/bin/)
pub async fn extract_from_deb(
    deb_path: &Path,
    binary_name: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    let temp_dir = tempfile::tempdir()?;

    // Step 1: Extract ar archive using pure Rust ar crate (wrapped in spawn_blocking)
    let temp_dir_path = temp_dir.path().to_path_buf();
    let deb_path_clone = deb_path.to_path_buf();

    tokio::task::spawn_blocking(move || -> Result<()> {
        use ar::Archive;

        let ar_file = std::fs::File::open(&deb_path_clone)
            .context("Failed to open .deb file")?;

        let mut archive = Archive::new(ar_file);

        // Extract all entries from the ar archive
        while let Some(entry_result) = archive.next_entry() {
            let mut entry = entry_result
                .context("Failed to read ar archive entry")?;

            let identifier = entry.header().identifier();
            let entry_name = std::str::from_utf8(identifier)
                .context("Invalid UTF-8 in ar entry name")?
                .to_string();

            let entry_path = temp_dir_path.join(&entry_name);

            let mut output_file = std::fs::File::create(&entry_path)
                .context(format!("Failed to create {}", entry_path.display()))?;

            std::io::copy(&mut entry, &mut output_file)
                .context(format!("Failed to extract {}", entry_name))?;
        }

        Ok(())
    }).await??;

    // Step 2: Extract data.tar.gz
    let data_tar_gz = temp_dir.path().join("data.tar.gz");
    if !tokio::fs::try_exists(&data_tar_gz).await? {
        return Err(anyhow!("data.tar.gz not found in .deb archive"));
    }

    let extract_dir = temp_dir.path().join("extracted");
    tokio::fs::create_dir_all(&extract_dir).await?;

    // Wrap CPU-bound tar extraction in spawn_blocking
    let extract_dir_clone = extract_dir.clone();
    let data_tar_gz_clone = data_tar_gz.clone();
    tokio::task::spawn_blocking(move || {
        let tar_gz_file = std::fs::File::open(&data_tar_gz_clone)?;
        let tar = GzDecoder::new(tar_gz_file);
        let mut archive = Archive::new(tar);
        archive.unpack(&extract_dir_clone)?;
        Ok::<_, anyhow::Error>(())
    }).await??;

    // Step 3: Find binary at usr/bin/{binary_name}
    let binary_path = extract_dir.join("usr/bin").join(binary_name);

    if !tokio::fs::try_exists(&binary_path).await? {
        return Err(anyhow!("Binary {} not found at usr/bin/ in .deb package", binary_name));
    }

    // Copy to persistent output directory
    let final_path = output_dir.join(binary_name);
    tokio::fs::copy(&binary_path, &final_path).await?;

    Ok(final_path)
}

/// Extract binary from .rpm package (rpm2cpio | cpio → usr/bin/)
pub async fn extract_from_rpm(
    rpm_path: &Path,
    binary_name: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    let temp_dir = tempfile::tempdir()?;
    let extract_dir = temp_dir.path().join("extracted");
    tokio::fs::create_dir_all(&extract_dir).await?;

    // Extract RPM using pure Rust: rpm crate for metadata + manual CPIO extraction
    let rpm_path_clone = rpm_path.to_path_buf();
    let binary_name_clone = binary_name.to_string();
    let extract_dir_clone = extract_dir.clone();

    tokio::task::spawn_blocking(move || -> Result<PathBuf> {
        use rpm::{Package, CompressionType};
        use flate2::read::GzDecoder;
        use std::io::{BufReader, Seek, SeekFrom};

        // Step 1: Open RPM package
        let package = Package::open(&rpm_path_clone)
            .context("Failed to open RPM package")?;

        // Step 2: Get payload offset and compression type
        let offsets = package.metadata.get_package_segment_offsets();
        let compressor = package.metadata.get_payload_compressor()
            .context("Failed to determine payload compression")?;

        // Step 3: Seek to payload offset
        let mut rpm_file = std::fs::File::open(&rpm_path_clone)?;
        rpm_file.seek(SeekFrom::Start(offsets.payload))?;

        // Step 4: Decompress based on compression type
        let decompressed_cpio = match compressor {
            CompressionType::Gzip => {
                let mut decoder = GzDecoder::new(BufReader::new(rpm_file));
                let mut buf = Vec::new();
                std::io::copy(&mut decoder, &mut buf)
                    .context("Failed to decompress gzip payload")?;
                buf
            }
            CompressionType::Zstd => {
                use zstd::stream::read::Decoder as ZstdDecoder;
                let mut decoder = ZstdDecoder::new(BufReader::new(rpm_file))?;
                let mut buf = Vec::new();
                std::io::copy(&mut decoder, &mut buf)
                    .context("Failed to decompress zstd payload")?;
                buf
            }
            CompressionType::Xz => {
                use xz2::read::XzDecoder;
                let mut decoder = XzDecoder::new(BufReader::new(rpm_file));
                let mut buf = Vec::new();
                std::io::copy(&mut decoder, &mut buf)
                    .context("Failed to decompress xz payload")?;
                buf
            }
            CompressionType::Bzip2 => {
                use bzip2::read::BzDecoder;
                let mut decoder = BzDecoder::new(BufReader::new(rpm_file));
                let mut buf = Vec::new();
                std::io::copy(&mut decoder, &mut buf)
                    .context("Failed to decompress bzip2 payload")?;
                buf
            }
            CompressionType::None => {
                let mut buf = Vec::new();
                std::io::copy(&mut rpm_file, &mut buf)
                    .context("Failed to read uncompressed payload")?;
                buf
            }
        };

        // Step 5: Extract files from CPIO archive using cpio crate
        // Pattern verified from cpio-rs/examples/extractcpio.rs and cpio-rs/src/newc.rs
        use std::io::Cursor;
        let mut cpio_reader = Cursor::new(decompressed_cpio);

        loop {
            let reader = match cpio::NewcReader::new(cpio_reader) {
                Ok(r) => r,
                Err(_) => break, // End of archive
            };

            if reader.entry().is_trailer() {
                break;
            }

            let entry_name = reader.entry().name();
            let file_size = reader.entry().file_size();

            // Build output path (remove leading ./)
            let rel_path = entry_name.trim_start_matches("./");
            let output_path = extract_dir_clone.join(rel_path);

            // Create parent directories
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Extract file content (skip directories and zero-length files)
            if file_size > 0 {
                let mut output_file = std::fs::File::create(&output_path)
                    .context(format!("Failed to create {}", output_path.display()))?;

                cpio_reader = reader.to_writer(output_file)
                    .context(format!("Failed to extract {}", entry_name))?;
            } else {
                cpio_reader = reader.finish()
                    .context("Failed to skip CPIO entry")?;
            }
        }

        // Step 6: Return path to extracted binary
        let binary_path = extract_dir_clone.join("usr/bin").join(&binary_name_clone);

        if !binary_path.exists() {
            return Err(anyhow!(
                "Binary {} not found at usr/bin/ in RPM package",
                binary_name_clone
            ));
        }

        Ok(binary_path)
    }).await?
}

/// Extract binary from macOS .dmg (pure Rust implementation)
#[allow(unused_variables)]
pub async fn extract_from_dmg(
    dmg_path: &Path,
    binary_name: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    #[cfg(not(target_os = "macos"))]
    {
        return Err(anyhow!("DMG extraction only supported on macOS"));
    }

    #[cfg(target_os = "macos")]
    {
        use apple_dmg::DmgReader;
        use fatfs::{FileSystem, FsOptions};
        use std::io::Cursor;

        let dmg_path_clone = dmg_path.to_path_buf();
        let binary_name_clone = binary_name.to_string();
        let output_dir_clone = output_dir.to_path_buf();

        tokio::task::spawn_blocking(move || -> Result<PathBuf> {
            // Step 1: Open DMG file
            let mut dmg = DmgReader::open(&dmg_path_clone)
                .context("Failed to open DMG file")?;

            // Step 2: Extract FAT32 partition (usually partition index 1)
            // Partition 0 is MBR, Partition 1 is the actual filesystem
            let partition_count = dmg.plist().partitions().len();

            if partition_count < 2 {
                return Err(anyhow!("DMG does not contain expected partitions"));
            }

            let fat32_data = dmg.partition_data(1)
                .context("Failed to extract FAT32 partition from DMG")?;

            // Step 3: Mount FAT32 filesystem in-memory
            let fs = FileSystem::new(
                Cursor::new(fat32_data),
                FsOptions::new()
            ).context("Failed to parse FAT32 filesystem")?;

            // Step 4: Find .app bundle in root directory
            let root = fs.root_dir();
            let mut app_entry = None;

            for entry_result in root.iter() {
                let entry = entry_result
                    .context("Failed to read FAT32 directory entry")?;

                let name = entry.file_name();
                if name.ends_with(".app") || name.ends_with(".APP") {
                    app_entry = Some(name);
                    break;
                }
            }

            let app_name = app_entry
                .ok_or_else(|| anyhow!("No .app bundle found in DMG"))?;

            // Step 5: Navigate to .app/Contents/MacOS/{binary_name}
            let app_dir = root.open_dir(&app_name)
                .context(format!("Failed to open {}", app_name))?;

            let contents_dir = app_dir.open_dir("Contents")
                .context("Failed to open Contents directory in .app bundle")?;

            let macos_dir = contents_dir.open_dir("MacOS")
                .context("Failed to open MacOS directory")?;

            // Step 6: Extract binary file
            let mut binary_file = macos_dir.open_file(&binary_name_clone)
                .context(format!(
                    "Binary {} not found in {}/Contents/MacOS",
                    binary_name_clone, app_name
                ))?;

            // Step 7: Copy to output directory
            let final_path = output_dir_clone.join(&binary_name_clone);
            let mut output_file = std::fs::File::create(&final_path)
                .context("Failed to create output file")?;

            std::io::copy(&mut binary_file, &mut output_file)
                .context("Failed to copy binary from DMG")?;

            // Step 8: Set executable permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &final_path,
                    std::fs::Permissions::from_mode(0o755)
                )?;
            }

            Ok(final_path)
        }).await?
    }
}

/// Extract binary from Windows ZIP archive
pub async fn extract_from_windows_installer(
    installer_path: &Path,
    binary_name: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    use zip::ZipArchive;

    // Wrap entire ZIP extraction in spawn_blocking (CPU-bound operation)
    let installer_path = installer_path.to_path_buf();
    let binary_name = binary_name.to_string();
    let output_dir = output_dir.to_path_buf();

    tokio::task::spawn_blocking(move || {
        // Open ZIP archive
        let zip_file = std::fs::File::open(&installer_path)
            .context("Failed to open Windows ZIP archive")?;

        let mut archive = ZipArchive::new(zip_file)
            .context("Failed to read ZIP archive")?;

        // Expected binary filename
        let exe_name = format!("{}.exe", binary_name);

        // Search for binary in ZIP archive (may be at root or in subdirectory)
        let mut binary_found = false;
        let final_path = output_dir.join(&exe_name);

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)
                .context(format!("Failed to read ZIP entry at index {}", i))?;

            // Get the file name (handles both flat and nested structures)
            let file_name = file.name();

            // Check if this is the binary we're looking for
            // Match either:
            // 1. Exact name: "kodegen.exe"
            // 2. In subdirectory: "bin/kodegen.exe" or "kodegen/kodegen.exe"
            if file_name.ends_with(&exe_name) && !file.is_dir() {
                // Extract binary to output directory
                let mut outfile = std::fs::File::create(&final_path)
                    .context("Failed to create extracted binary file")?;

                std::io::copy(&mut file, &mut outfile)
                    .context("Failed to extract binary from ZIP")?;

                binary_found = true;
                break;
            }
        }

        if !binary_found {
            return Err(anyhow!(
                "Binary {} not found in Windows ZIP archive. Archive contains: {}",
                exe_name,
                (0..archive.len())
                    .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_string()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        // Verify the extracted binary exists and is readable
        if !final_path.exists() {
            return Err(anyhow!("Binary extraction completed but file not found at {}", final_path.display()));
        }

        Ok::<PathBuf, anyhow::Error>(final_path)
    }).await?
}

/// Extract binary from downloaded package (platform-specific dispatcher)
pub async fn extract_binary_from_package(
    package_path: &Path,
    binary_name: &str,
    platform: Platform,
    output_dir: &Path,
) -> Result<PathBuf> {
    match platform {
        Platform::DebianAmd64 => extract_from_deb(package_path, binary_name, output_dir).await,
        Platform::RpmX8664 => extract_from_rpm(package_path, binary_name, output_dir).await,
        Platform::MacOsArm64 | Platform::MacOsX8664 => extract_from_dmg(package_path, binary_name, output_dir).await,
        Platform::WindowsX8664 => extract_from_windows_installer(package_path, binary_name, output_dir).await,
    }
}
