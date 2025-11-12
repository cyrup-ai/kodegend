//! Installation progress tracking with download metadata

/// Download phase tracking for individual binary downloads
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadPhase {
    Discovering,  // Fetching latest release from GitHub API
    Downloading,  // Downloading package bytes
    Extracting,   // Extracting binary from package
    Complete,     // Binary extracted and ready
}

/// Metadata for tracking individual binary downloads
#[derive(Debug, Clone)]
pub struct DownloadMetadata {
    /// Binary name being downloaded (e.g., "kodegen", "kodegen-git")
    pub binary_name: String,

    /// Current binary index (1-based, e.g., 3 for third binary)
    pub binary_index: usize,

    /// Total binaries to install (count from crate::binaries::BINARY_COUNT)
    pub _total_binaries: usize,

    /// Bytes downloaded so far
    pub bytes_downloaded: u64,

    /// Total bytes to download (from GitHub asset size)
    pub total_bytes: u64,

    /// Release version discovered (e.g., "v0.4.2")
    #[cfg_attr(not(feature = "gui"), allow(dead_code))]
    pub version: Option<String>,

    /// Download phase: "discovering" | "downloading" | "extracting" | "complete"
    pub phase: DownloadPhase,
}

/// Installation progress tracking
#[derive(Debug, Clone)]
pub struct InstallProgress {
    pub step: String,
    pub progress: f32, // 0.0 to 1.0
    pub message: String,
    pub is_error: bool,

    /// Download-specific metadata (optional, used during binary downloads)
    pub download_metadata: Option<DownloadMetadata>,
}

impl InstallProgress {
    /// Create new progress update with optimized initialization
    pub fn new(step: String, progress: f32, message: String) -> Self {
        Self {
            step,
            progress: progress.clamp(0.0, 1.0),
            message,
            is_error: false,
            download_metadata: None,
        }
    }

    /// Create error progress update
    #[cfg_attr(not(feature = "gui"), allow(dead_code))]
    pub fn error(step: String, message: String) -> Self {
        Self {
            step,
            progress: 0.0,
            message,
            is_error: true,
            download_metadata: None,
        }
    }

    /// Create completion progress update
    pub fn complete(step: String, message: String) -> Self {
        Self {
            step,
            progress: 1.0,
            message,
            is_error: false,
            download_metadata: None,
        }
    }

    /// Create download progress with metadata
    pub fn download(
        binary_name: String,
        binary_index: usize,
        total_binaries: usize,
        bytes_downloaded: u64,
        total_bytes: u64,
        phase: DownloadPhase,
        version: Option<String>,
    ) -> Self {
        // Calculate per-binary progress (0.0 to 1.0)
        let binary_progress = if total_bytes > 0 {
            (bytes_downloaded as f64 / total_bytes as f64) as f32
        } else {
            0.0
        };

        // Calculate overall progress across all binaries
        // Formula: (completed_binaries + current_binary_progress) / total_binaries
        let completed_binaries = binary_index.saturating_sub(1) as f32;
        let overall_progress = (completed_binaries + binary_progress) / total_binaries as f32;

        // Generate human-readable message
        let message = match phase {
            DownloadPhase::Discovering => {
                format!("🔍 Checking latest release for {}...", binary_name)
            }
            DownloadPhase::Downloading => {
                let mb_downloaded = bytes_downloaded as f64 / 1_048_576.0;
                let mb_total = total_bytes as f64 / 1_048_576.0;
                let percent = (binary_progress * 100.0) as u8;
                format!(
                    "📥 Downloading {} ({:.1} MB / {:.1} MB) - {}%",
                    binary_name, mb_downloaded, mb_total, percent
                )
            }
            DownloadPhase::Extracting => {
                format!("📦 Extracting {}...", binary_name)
            }
            DownloadPhase::Complete => {
                format!("✅ {} complete", binary_name)
            }
        };

        Self {
            step: "download".to_string(),
            progress: overall_progress,
            message,
            is_error: false,
            download_metadata: Some(DownloadMetadata {
                binary_name,
                binary_index,
                _total_binaries: total_binaries,
                bytes_downloaded,
                total_bytes,
                version,
                phase,
            }),
        }
    }
}
