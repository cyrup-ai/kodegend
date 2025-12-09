//! Build module for cross-platform build tasks
//!
//! This module provides build configuration including:
//! - Platform-specific optimization flags
//! - Build metadata (timestamp, target, profile)
//! - Systemd feature detection (Linux)

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

        // Create empty dummy helper for Linux (extracted but never invoked)
        if let Ok(out_dir) = std::env::var("OUT_DIR") {
            let helper_path = std::path::PathBuf::from(&out_dir).join("kodegen-helper");
            if let Err(e) = std::fs::write(&helper_path, b"") {
                eprintln!("Warning: Failed to create dummy helper: {}", e);
            } else {
                // Make executable
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(metadata) = std::fs::metadata(&helper_path) {
                        let mut perms = metadata.permissions();
                        perms.set_mode(0o755);
                        let _ = std::fs::set_permissions(&helper_path, perms);
                    }
                }
            }
        }
    }

    // Build Windows helper executable
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        build_windows_helper();
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
                Err(e) => Err(format!("Failed to install C compiler: {}", e).into()),
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
            Command::new("sudo").args(["apt-get", "update"]).status()?;
            Command::new("sudo")
                .args([
                    "apt-get",
                    "install",
                    "-y",
                    "build-essential",
                    "gcc-mingw-w64-x86-64",
                    "g++-mingw-w64-x86-64",
                ])
                .status()?;
        } else if Command::new("dnf").arg("--version").output().is_ok() {
            eprintln!("Build: Installing build dependencies via dnf...");
            Command::new("sudo")
                .args([
                    "dnf",
                    "install",
                    "-y",
                    "gcc",
                    "gcc-c++",
                    "make",
                    "mingw64-gcc",
                    "mingw64-gcc-c++",
                ])
                .status()?;
        } else if Command::new("pacman").arg("--version").output().is_ok() {
            eprintln!("Build: Installing build dependencies via pacman...");
            Command::new("sudo")
                .args(["pacman", "-S", "--noconfirm", "base-devel", "mingw-w64-gcc"])
                .status()?;
        } else if Command::new("apk").arg("--version").output().is_ok() {
            eprintln!("Build: Installing build dependencies via apk...");
            Command::new("sudo")
                .args(["apk", "add", "build-base"])
                .status()?;
        } else {
            return Err(
                "No supported package manager found for automatic compiler installation".into(),
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        eprintln!("Build: Installing Xcode Command Line Tools...");
        Command::new("xcode-select").args(["--install"]).status()?;
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

/// Build Windows helper executable with UAC manifest
fn build_windows_helper() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    eprintln!("Build: Compiling Windows helper executable...");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let target = env::var("TARGET").unwrap_or_default();

    // Compile helper.c to object file
    let mut cc_build = cc::Build::new();
    cc_build
        .file("src/install/installer/windows/helper/helper.c")
        .warnings(true);

    // Add Windows-specific flags
    if target.contains("gnu") {
        cc_build
            .flag("-municode")
            .flag("-mconsole")
            .flag("-static");
    }

    cc_build.compile("kodegen_helper");

    // Create resource file for manifest embedding
    let manifest_path = "src/install/installer/windows/helper/helper.manifest";
    let rc_file = out_dir.join("helper.rc");
    let res_file = out_dir.join("helper.res");

    // Write .rc file that references the manifest
    std::fs::write(&rc_file, format!("1 24 \"{}\"", manifest_path))
        .expect("Failed to write RC file");

    // Determine windres executable name
    let windres = if cfg!(target_os = "windows") {
        "windres.exe".to_string()
    } else {
        // Cross-compiling: use target-prefixed windres
        format!("{}-w64-mingw32-windres", target.split('-').next().unwrap_or("x86_64"))
    };

    // Compile resource file
    let windres_status = Command::new(&windres)
        .arg(&rc_file)
        .arg("-O")
        .arg("coff")
        .arg("-o")
        .arg(&res_file)
        .status();

    match windres_status {
        Ok(status) if status.success() => {
            eprintln!("Build: Successfully compiled resource file");
        }
        Ok(status) => {
            eprintln!("Warning: windres failed with status: {}", status);
            eprintln!("Continuing without manifest embedding...");
            // Create empty resource file to prevent linker errors
            std::fs::write(&res_file, b"").ok();
        }
        Err(e) => {
            eprintln!("Warning: Failed to run windres ({}): {}", windres, e);
            eprintln!("Continuing without manifest embedding...");
            std::fs::write(&res_file, b"").ok();
        }
    }

    // Link to create final executable
    let helper_exe = out_dir.join("KodegenHelper.exe");
    let obj_file = out_dir.join("libkodegen_helper.a");

    let linker = if cfg!(target_os = "windows") {
        "gcc.exe".to_string()
    } else {
        format!("{}-w64-mingw32-gcc", target.split('-').next().unwrap_or("x86_64"))
    };

    let link_status = Command::new(&linker)
        .arg(&obj_file)
        .arg(&res_file)
        .arg("-o")
        .arg(&helper_exe)
        .arg("-static")
        .arg("-ladvapi32")
        .arg("-lshell32")
        .arg("-municode")
        .arg("-mconsole")
        .status();

    match link_status {
        Ok(status) if status.success() => {
            eprintln!("Build: Successfully built KodegenHelper.exe at {:?}", helper_exe);
        }
        Ok(status) => {
            panic!("Linking KodegenHelper.exe failed with status: {}", status);
        }
        Err(e) => {
            panic!("Failed to run linker ({}): {}", linker, e);
        }
    }

    // Verify the helper was created
    if !helper_exe.exists() {
        panic!("KodegenHelper.exe was not created at {:?}", helper_exe);
    }

    // Tell Cargo to rerun if these files change
    println!("cargo:rerun-if-changed=src/install/installer/windows/helper/helper.c");
    println!("cargo:rerun-if-changed=src/install/installer/windows/helper/helper.manifest");
}
