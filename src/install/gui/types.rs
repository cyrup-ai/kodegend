//! Type definitions for GUI installation progress tracking

/// Per-binary download status for GUI display
#[derive(Debug, Clone)]
pub struct BinaryDownloadStatus {
    pub name: String,
    pub _index: usize,
    pub status: BinaryStatus,
    pub progress: f32, // 0.0 to 1.0
    pub version: Option<String>,
}

/// Binary download status enum
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryStatus {
    Pending,     // Not started yet
    Discovering, // Checking GitHub release
    Downloading, // Download in progress
    Extracting,  // Extraction in progress
    Complete,    // Finished
}
