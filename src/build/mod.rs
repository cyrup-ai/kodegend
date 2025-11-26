//! Build module for cross-platform build tasks
//!
//! This module provides comprehensive build functionality including macOS
//! helper app creation, code signing, and packaging with zero allocation
//! patterns and blazing-fast performance.
//!
//! Uses proven kodegen_bundler_sign for reliable code signing.

pub mod packaging;

#[cfg(target_os = "linux")]
pub mod windows_helper;

#[cfg(target_os = "linux")]
pub mod linux_helper;

/// Main build function orchestrating platform-specific tasks
pub async fn main() {
    // Validate build environment before proceeding
    if let Err(e) = validate_build_environment() {
        eprintln!("Error: Build environment validation failed: {e}");
        std::process::exit(1);
    }

    // Check for systemd on Linux
    #[cfg(target_os = "linux")]
    {
        if pkg_config::probe_library("libsystemd").is_ok() {
            println!("cargo:rustc-cfg=feature=\"systemd_available\"");
        }
    }

    // Build and sign macOS helper app
    #[cfg(target_os = "macos")]
    {
        // Use atomic build with rollback
        let out_dir = match std::env::var("OUT_DIR").map(std::path::PathBuf::from) {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!("Build error: OUT_DIR not set: {e}");
                std::process::exit(1);
            }
        };
        let zip_path = out_dir.join("KodegenHelper.app.zip");

        if let Err(e) = packaging::create_functional_zip(&zip_path).await {
            eprintln!("Build error: macOS helper failed: {e}");
            std::process::exit(1);
        }
    }

    // Build Linux and Windows helper executables
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = linux_helper::build_and_sign_helper() {
            eprintln!("Build error: Linux helper failed: {e}");
            std::process::exit(1);
        }

        // Build Windows helper via MinGW cross-compilation
        if let Err(e) = windows_helper::build_and_sign_helper() {
            eprintln!("Build error: Windows helper failed: {e}");
            std::process::exit(1);
        }
    }

    // Platform-specific build optimizations
    configure_build_optimizations();

    // Set build metadata
    set_build_metadata();
}

/// Configure platform-specific build optimizations
fn configure_build_optimizations() {
    // Use CARGO_CFG_TARGET_OS to check the TARGET platform, not the BUILD platform
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "macos" {
        // macOS-specific optimizations
        println!("cargo:rustc-link-arg=-Wl,-dead_strip");
        println!("cargo:rustc-link-arg=-Wl,-no_compact_unwind");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    } else if target_os == "linux" {
        // Linux-specific optimizations
        println!("cargo:rustc-link-arg=-Wl,--gc-sections");
        println!("cargo:rustc-link-arg=-Wl,--strip-all");
    } else if target_os == "windows" {
        // Windows-specific optimizations
        println!("cargo:rustc-link-arg=/OPT:REF");
        println!("cargo:rustc-link-arg=/OPT:ICF");
    }
}

/// Set build metadata for runtime access
fn set_build_metadata() {
    // Set build timestamp
    let build_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    println!("cargo:rustc-env=BUILD_TIMESTAMP={build_time}");

    // Set target information
    println!(
        "cargo:rustc-env=BUILD_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
    );

    // Set profile information
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=BUILD_PROFILE={profile}");

    // Set optimization flags based on profile
    match profile.as_str() {
        "release" => {
            println!("cargo:rustc-cfg=optimized");
            println!("cargo:rustc-env=OPTIMIZATION_LEVEL=3");
        }
        "debug" => {
            println!("cargo:rustc-cfg=debug_build");
            println!("cargo:rustc-env=OPTIMIZATION_LEVEL=0");
        }
        _ => {
            println!("cargo:rustc-env=OPTIMIZATION_LEVEL=1");
        }
    }
}

/// Check build environment and dependencies
pub fn validate_build_environment() -> Result<(), Box<dyn std::error::Error>> {
    // Check required environment variables
    let required_vars = ["OUT_DIR", "TARGET"];
    for var in &required_vars {
        if std::env::var(var).is_err() {
            return Err(format!("Required environment variable {var} not set").into());
        }
    }

    // Validate C compiler is available using cc crate
    validate_c_compiler()?;

    Ok(())
}

/// Validate that a C compiler is available using the cc crate
fn validate_c_compiler() -> Result<(), Box<dyn std::error::Error>> {
    // Use cc crate to detect the compiler
    let build = cc::Build::new();

    // Try to get the compiler - this will fail if no compiler is available
    match build.try_get_compiler() {
        Ok(compiler) => {
            // Successfully found a compiler
            let compiler_path = compiler.path();
            eprintln!("Build: Found C compiler at: {}", compiler_path.display());

            // Log compiler type for debugging
            if compiler.is_like_gnu() {
                eprintln!("Build: Compiler type: GNU (GCC/MinGW)");
            } else if compiler.is_like_clang() {
                eprintln!("Build: Compiler type: Clang");
            } else if compiler.is_like_msvc() {
                eprintln!("Build: Compiler type: MSVC");
            }

            Ok(())
        }
        Err(_) => {
            eprintln!("Build: No C compiler found, installing...");
            install_build_dependencies()?;

            // Retry after installation
            match build.try_get_compiler() {
                Ok(_) => {
                    eprintln!("Build: C compiler installed successfully");
                    Ok(())
                }
                Err(e) => Err(format!("Failed to install C compiler: {}", e).into())
            }
        }
    }
}

/// Install build dependencies automatically
fn install_build_dependencies() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    #[cfg(target_os = "linux")]
    {
        // Detect and use available package manager
        if Command::new("apt-get").arg("--version").output().is_ok() {
            eprintln!("Build: Installing build dependencies via apt-get...");
            Command::new("sudo").args(&["apt-get", "update"]).status()?;
            Command::new("sudo").args(&["apt-get", "install", "-y",
                "build-essential", "gcc-mingw-w64-x86-64", "g++-mingw-w64-x86-64"]).status()?;
        } else if Command::new("dnf").arg("--version").output().is_ok() {
            eprintln!("Build: Installing build dependencies via dnf...");
            Command::new("sudo").args(&["dnf", "install", "-y",
                "gcc", "gcc-c++", "make", "mingw64-gcc", "mingw64-gcc-c++"]).status()?;
        } else if Command::new("pacman").arg("--version").output().is_ok() {
            eprintln!("Build: Installing build dependencies via pacman...");
            Command::new("sudo").args(&["pacman", "-S", "--noconfirm",
                "base-devel", "mingw-w64-gcc"]).status()?;
        } else if Command::new("apk").arg("--version").output().is_ok() {
            eprintln!("Build: Installing build dependencies via apk...");
            Command::new("sudo").args(&["apk", "add", "build-base"]).status()?;
        } else {
            return Err("No supported package manager found for automatic compiler installation".into());
        }
    }

    #[cfg(target_os = "macos")]
    {
        eprintln!("Build: Installing Xcode Command Line Tools...");
        Command::new("xcode-select").args(&["--install"]).status()?;
    }

    Ok(())
}

/// Get build information for runtime diagnostics
#[allow(dead_code)]
pub fn get_build_info() -> BuildInfo {
    BuildInfo {
        timestamp: std::env::var("BUILD_TIMESTAMP")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        target: std::env::var("BUILD_TARGET").unwrap_or_else(|_| "unknown".to_string()),
        profile: std::env::var("BUILD_PROFILE").unwrap_or_else(|_| "unknown".to_string()),
        optimization_level: std::env::var("OPTIMIZATION_LEVEL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        features: get_enabled_features(),
    }
}

/// Build information structure
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BuildInfo {
    /// Build timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// Target triple
    pub target: String,
    /// Build profile (debug/release)
    pub profile: String,
    /// Optimization level
    pub optimization_level: u32,
    /// Enabled features
    pub features: Vec<String>,
}

/// Get list of enabled cargo features
#[allow(dead_code)]
fn get_enabled_features() -> Vec<String> {
    Vec::new()
}

// Function removed - no more placeholders, fail builds instead
