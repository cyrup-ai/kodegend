//! Platform detection for package format selection

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use std::process::Command;
use log::warn;

/// Platform detection for package format selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    DebianAmd64,      // Ubuntu, Debian (x86_64)
    RpmX8664,         // RHEL, Fedora, CentOS (x86_64)
    MacOsArm64,       // macOS Apple Silicon
    MacOsX8664,       // macOS Intel
    WindowsX8664,     // Windows (x86_64)
}

/// Global cache for platform detection (initialized once, used everywhere)
static PLATFORM_CACHE: OnceCell<Platform> = OnceCell::new();

impl Platform {
    /// Detect current platform (cached after first call)
    pub fn detect() -> Result<Self> {
        PLATFORM_CACHE.get_or_try_init(|| {
            Self::detect_uncached()
        }).copied()
    }

    /// Internal uncached detection - called only once
    fn detect_uncached() -> Result<Self> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") if has_dpkg() => Ok(Platform::DebianAmd64),
            ("linux", "x86_64") if has_rpm() => Ok(Platform::RpmX8664),
            ("linux", arch) => Err(anyhow!("Unsupported Linux architecture: {}", arch)),
            ("macos", "aarch64") => Ok(Platform::MacOsArm64),
            ("macos", "x86_64") => Ok(Platform::MacOsX8664),
            ("windows", "x86_64") => Ok(Platform::WindowsX8664),
            (os, arch) => Err(anyhow!("Unsupported platform: {} {}", os, arch)),
        }
    }

    /// Get file extension for this platform's packages
    pub fn package_extension(&self) -> &'static str {
        match self {
            Platform::DebianAmd64 => "deb",
            Platform::RpmX8664 => "rpm",
            Platform::MacOsArm64 | Platform::MacOsX8664 => "dmg",
            Platform::WindowsX8664 => "zip",
        }
    }
}

/// Check if dpkg is available (Debian-based systems)
fn has_dpkg() -> bool {
    match Command::new("dpkg").arg("--version").output() {
        Ok(output) => output.status.success(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Expected: dpkg not installed (RPM system)
            false
        }
        Err(e) => {
            // Unexpected: permission denied, PATH issues, etc.
            warn!("Failed to check for dpkg: {}", e);
            false
        }
    }
}

/// Check if rpm is available (RHEL-based systems)
fn has_rpm() -> bool {
    match Command::new("rpm").arg("--version").output() {
        Ok(output) => output.status.success(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Expected: rpm not installed (Debian system)
            false
        }
        Err(e) => {
            // Unexpected: permission denied, PATH issues, etc.
            warn!("Failed to check for rpm: {}", e);
            false
        }
    }
}
