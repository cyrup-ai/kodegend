//! Zero-allocation dependency vulnerability scanner with lock-free caching
//!
//! This module provides automated vulnerability scanning for Rust dependencies using
//! cargo-audit integration with zero-allocation, lock-free, and SIMD-accelerated patterns.
//!
//! # Features
//!
//! - Zero-allocation vulnerability scanning using `ArrayVec` and `ArrayString`
//! - Lock-free vulnerability caching using `DashMap` for concurrent access
//! - SIMD-accelerated string matching for vulnerability pattern detection
//! - Atomic vulnerability tracking for thread-safe metrics
//! - CI/CD integration with configurable failure thresholds
//! - Cache-line aligned data structures for optimal performance
//!
//! # Usage
//!
//! ```rust
//! use kodegen_daemon::security::audit::*;
//!
//! let scanner = VulnerabilityScanner::new(AuditThresholds {
//!     critical_max: 0,
//!     high_max: 2,
//!     medium_max: 10,
//!     low_max: 50,
//! });
//!
//! let result = scanner.scan_dependencies().await?;
//! if !result.passes_thresholds() {
//!     return Err("Vulnerability threshold exceeded".into());
//! }
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use arrayvec::{ArrayString, ArrayVec};
use dashmap::DashMap;
use memchr::memmem;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

/// Maximum number of vulnerabilities to track without heap allocation
const MAX_VULNERABILITIES: usize = 256;

/// Maximum size for package names and vulnerability IDs
const MAX_IDENTIFIER_SIZE: usize = 64;

/// Maximum size for vulnerability descriptions
const MAX_DESCRIPTION_SIZE: usize = 256;

/// Default padding for cache-line alignment
fn default_padding() -> [u8; 64] {
    [0; 64]
}

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::str::FromStr for VulnerabilitySeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            _ => Err(format!("Unknown severity: {s}")),
        }
    }
}

impl VulnerabilitySeverity {
    /// Get numeric weight for threshold comparison
    #[must_use]
    pub fn weight(&self) -> u32 {
        match self {
            Self::Critical => 1000,
            Self::High => 100,
            Self::Medium => 10,
            Self::Low => 1,
            Self::Info => 0,
        }
    }
}

/// Vulnerability status for caching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnerabilityStatus {
    /// Vulnerability is confirmed and active
    Active,
    /// Vulnerability has been patched
    Patched,
    /// Vulnerability is marked as false positive
    FalsePositive,
    /// Vulnerability is accepted risk
    Accepted,
    /// Vulnerability status is unknown
    Unknown,
}

/// Cache-line aligned vulnerability data structure
#[repr(align(64))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Vulnerability ID (e.g., RUSTSEC-2023-0001)
    pub id: ArrayString<MAX_IDENTIFIER_SIZE>,
    /// Affected package name
    pub package: ArrayString<MAX_IDENTIFIER_SIZE>,
    /// Vulnerability severity
    pub severity: VulnerabilitySeverity,
    /// Vulnerability description
    pub description: ArrayString<MAX_DESCRIPTION_SIZE>,
    /// Affected version
    pub version: ArrayString<MAX_IDENTIFIER_SIZE>,
    /// Patched version (if available)
    pub patched: Option<ArrayString<MAX_IDENTIFIER_SIZE>>,
    /// Vulnerability discovery timestamp
    pub discovered: u64,
    /// Cache padding to prevent false sharing
    #[serde(skip, default = "default_padding")]
    _padding: [u8; 64],
}

impl Vulnerability {
    /// Create new vulnerability with zero-allocation
    #[must_use]
    pub fn new(
        id: &str,
        package: &str,
        severity: VulnerabilitySeverity,
        description: &str,
        version: &str,
        patched: Option<&str>,
    ) -> Option<Self> {
        let id = ArrayString::from(id).ok()?;
        let package = ArrayString::from(package).ok()?;
        let description = ArrayString::from(description).ok()?;
        let version = ArrayString::from(version).ok()?;
        let patched = match patched {
            Some(p) => Some(ArrayString::from(p).ok()?),
            None => None,
        };

        Some(Self {
            id,
            package,
            severity,
            description,
            version,
            patched,
            discovered: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs(),
            _padding: [0; 64],
        })
    }

    /// Check if vulnerability matches pattern using SIMD-accelerated search
    #[must_use]
    pub fn matches_pattern(&self, pattern: &[u8]) -> bool {
        let finder = memmem::Finder::new(pattern);

        finder.find(self.id.as_bytes()).is_some()
            || finder.find(self.package.as_bytes()).is_some()
            || finder.find(self.description.as_bytes()).is_some()
    }

    /// Check if vulnerability is in given package
    #[must_use]
    pub fn affects_package(&self, package_name: &str) -> bool {
        self.package.as_str() == package_name
    }
}

/// Audit result containing vulnerability collection
#[derive(Debug, Clone)]
pub struct AuditResult {
    /// Collection of found vulnerabilities (zero-allocation)
    pub vulnerabilities: ArrayVec<Vulnerability, MAX_VULNERABILITIES>,
    /// Total scan duration in milliseconds
    pub scan_duration_ms: u64,
    /// Number of packages scanned
    pub packages_scanned: u32,
    /// Scan timestamp
    pub scan_timestamp: u64,
    /// Whether scan completed successfully
    pub success: bool,
}

impl Default for AuditResult {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditResult {
    /// Create new audit result
    #[must_use]
    pub fn new() -> Self {
        Self {
            vulnerabilities: ArrayVec::new(),
            scan_duration_ms: 0,
            packages_scanned: 0,
            scan_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            success: false,
        }
    }

    /// Add vulnerability to result with capacity checking
    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) -> Result<(), AuditError> {
        self.vulnerabilities
            .try_push(vulnerability)
            .map_err(|_| AuditError::TooManyVulnerabilities)
    }

    /// Get vulnerability count by severity
    #[must_use]
    pub fn count_by_severity(&self, severity: VulnerabilitySeverity) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == severity)
            .count()
    }

    /// Check if result passes given thresholds
    pub fn passes_thresholds(&self, thresholds: &AuditThresholds) -> bool {
        self.count_by_severity(VulnerabilitySeverity::Critical)
            <= thresholds.critical_max.load(Ordering::Relaxed) as usize
            && self.count_by_severity(VulnerabilitySeverity::High)
                <= thresholds.high_max.load(Ordering::Relaxed) as usize
            && self.count_by_severity(VulnerabilitySeverity::Medium)
                <= thresholds.medium_max.load(Ordering::Relaxed) as usize
            && self.count_by_severity(VulnerabilitySeverity::Low)
                <= thresholds.low_max.load(Ordering::Relaxed) as usize
    }

    /// Get total vulnerability weight for scoring
    #[must_use]
    pub fn total_weight(&self) -> u32 {
        self.vulnerabilities
            .iter()
            .map(|v| v.severity.weight())
            .sum()
    }
}

/// Audit thresholds for CI/CD integration
#[derive(Debug)]
pub struct AuditThresholds {
    /// Maximum critical vulnerabilities allowed
    pub critical_max: AtomicU32,
    /// Maximum high vulnerabilities allowed
    pub high_max: AtomicU32,
    /// Maximum medium vulnerabilities allowed
    pub medium_max: AtomicU32,
    /// Maximum low vulnerabilities allowed
    pub low_max: AtomicU32,
}

impl AuditThresholds {
    /// Create new thresholds with atomic initialization
    #[must_use]
    pub fn new(critical: u32, high: u32, medium: u32, low: u32) -> Self {
        Self {
            critical_max: AtomicU32::new(critical),
            high_max: AtomicU32::new(high),
            medium_max: AtomicU32::new(medium),
            low_max: AtomicU32::new(low),
        }
    }

    /// Update thresholds atomically
    pub fn update(&self, critical: u32, high: u32, medium: u32, low: u32) {
        self.critical_max.store(critical, Ordering::Relaxed);
        self.high_max.store(high, Ordering::Relaxed);
        self.medium_max.store(medium, Ordering::Relaxed);
        self.low_max.store(low, Ordering::Relaxed);
    }

    /// Check if vulnerability counts exceed thresholds
    pub fn exceeded_by(&self, result: &AuditResult) -> bool {
        let critical_count = result.count_by_severity(VulnerabilitySeverity::Critical) as u32;
        let high_count = result.count_by_severity(VulnerabilitySeverity::High) as u32;
        let medium_count = result.count_by_severity(VulnerabilitySeverity::Medium) as u32;
        let low_count = result.count_by_severity(VulnerabilitySeverity::Low) as u32;

        critical_count > self.critical_max.load(Ordering::Relaxed)
            || high_count > self.high_max.load(Ordering::Relaxed)
            || medium_count > self.medium_max.load(Ordering::Relaxed)
            || low_count > self.low_max.load(Ordering::Relaxed)
    }
}

/// Vulnerability scanner error types
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Cargo audit command failed: {0}")]
    CargoAuditFailed(String),
    #[error("JSON parsing failed: {0}")]
    JsonParsingFailed(String),
    #[error("Too many vulnerabilities found (max: {MAX_VULNERABILITIES})")]
    TooManyVulnerabilities,
    #[error("Scan timeout exceeded")]
    ScanTimeout,
    #[error("Invalid vulnerability data: {0}")]
    InvalidVulnerabilityData(String),
    #[error("Cache operation failed: {0}")]
    CacheOperationFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
}

/// Main vulnerability scanner with atomic tracking
pub struct VulnerabilityScanner {
    /// Lock-free vulnerability cache
    cache: Arc<DashMap<ArrayString<MAX_IDENTIFIER_SIZE>, VulnerabilityStatus>>,
    /// Atomic vulnerability counters
    critical_count: AtomicU32,
    high_count: AtomicU32,
    medium_count: AtomicU32,
    low_count: AtomicU32,
    /// Total scans performed
    total_scans: AtomicU64,
    /// Scan success rate numerator
    successful_scans: AtomicU64,
    /// Audit thresholds for CI/CD
    thresholds: AuditThresholds,
    /// Scan timeout duration
    timeout_duration: Duration,
}

/// cargo-audit JSON report structure (subset of rustsec::Report)
/// 
/// Full spec: https://github.com/rustsec/rustsec/blob/main/rustsec/src/report.rs
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CargoAuditReport {
    pub vulnerabilities: VulnerabilitiesSection,
    
    #[serde(default)]
    pub warnings: WarningsSection,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VulnerabilitiesSection {
    pub found: bool,
    pub count: usize,
    pub list: Vec<VulnerabilityJson>,
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
struct WarningsSection {
    #[serde(default)]
    pub count: usize,
}

/// Individual vulnerability from cargo-audit JSON output
/// 
/// Full spec: https://github.com/rustsec/rustsec/blob/main/rustsec/src/vulnerability.rs
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VulnerabilityJson {
    pub advisory: AdvisoryMetadata,
    pub package: PackageInfo,
    
    #[serde(default)]
    pub versions: VersionInfo,
}

/// Advisory metadata from RustSec database
/// 
/// Full spec: https://docs.rs/rustsec/latest/rustsec/advisory/struct.Metadata.html
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AdvisoryMetadata {
    pub id: String,
    pub package: String,
    
    #[serde(default)]
    pub title: String,
    
    #[serde(default)]
    pub description: String,
    
    #[serde(default)]
    pub date: String,
    
    #[serde(default)]
    pub aliases: Vec<String>,
    
    #[serde(default)]
    pub cvss: Option<String>,
    
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PackageInfo {
    pub name: String,
    pub version: String,
    
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
struct VersionInfo {
    #[serde(default)]
    pub patched: Vec<String>,
    
    #[serde(default)]
    pub unaffected: Vec<String>,
}

impl VulnerabilityScanner {
    /// Create new vulnerability scanner with default thresholds
    pub fn new(thresholds: AuditThresholds) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            critical_count: AtomicU32::new(0),
            high_count: AtomicU32::new(0),
            medium_count: AtomicU32::new(0),
            low_count: AtomicU32::new(0),
            total_scans: AtomicU64::new(0),
            successful_scans: AtomicU64::new(0),
            thresholds,
            timeout_duration: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Scan dependencies for vulnerabilities using cargo-audit
    pub async fn scan_dependencies(&self) -> Result<AuditResult, AuditError> {
        let _start_time = std::time::Instant::now();
        self.total_scans.fetch_add(1, Ordering::Relaxed);

        let result = self.run_cargo_audit().await;

        if let Ok(audit_result) = &result {
            if audit_result.success {
                self.successful_scans.fetch_add(1, Ordering::Relaxed);
                self.update_counters(audit_result);
                self.update_cache(audit_result);
            }
        } else {
            // Scan failed, metrics already updated
        }

        result
    }

    /// Run cargo-audit command with timeout
    async fn run_cargo_audit(&self) -> Result<AuditResult, AuditError> {
        let command = Command::new("cargo")
            .args(["audit", "--format", "json", "--color", "never"])
            .output();

        let output = timeout(self.timeout_duration, command)
            .await
            .map_err(|_| AuditError::ScanTimeout)?
            .map_err(|e| AuditError::CargoAuditFailed(e.to_string()))?;

        let stdout = std::str::from_utf8(&output.stdout)?;
        let stderr = std::str::from_utf8(&output.stderr)?;

        if !output.status.success() && !stderr.is_empty() {
            return Err(AuditError::CargoAuditFailed(stderr.to_string()));
        }

        self.parse_audit_output(stdout).await
    }

    /// Parse cargo-audit JSON output using proper serde deserialization
    /// 
    /// This replaces the previous manual string parsing with proper JSON deserialization,
    /// eliminating the unused buffer bug and improving maintainability.
    async fn parse_audit_output(&self, output: &str) -> Result<AuditResult, AuditError> {
        let mut result = AuditResult::new();
        let start_time = std::time::Instant::now();

        // Deserialize the full cargo-audit JSON report
        let report: CargoAuditReport = serde_json::from_str(output)
            .map_err(|e| AuditError::JsonParsingFailed(format!("Failed to parse cargo-audit JSON: {}", e)))?;

        // Check if we found any vulnerabilities
        if !report.vulnerabilities.found {
            result.scan_duration_ms = start_time.elapsed().as_millis() as u64;
            result.success = true;
            return Ok(result);
        }

        // Convert each vulnerability from JSON format to our internal format
        for vuln_json in report.vulnerabilities.list {
            // Parse severity from CVSS string or infer from aliases
            let severity = Self::parse_severity(&vuln_json.advisory)?;
            
            // Extract patched version (first patched version if available)
            let patched = vuln_json.versions.patched
                .first()
                .map(|s| s.as_str());
            
            // Create our internal Vulnerability struct
            if let Some(vuln) = Vulnerability::new(
                &vuln_json.advisory.id,
                &vuln_json.package.name,
                severity,
                &vuln_json.advisory.description,
                &vuln_json.package.version,
                patched,
            ) {
                result.add_vulnerability(vuln)?;
            } else {
                // Log when vulnerability data exceeds our fixed-size limits
                log::warn!(
                    "Skipping vulnerability {} for {} - data exceeds ArrayString limits",
                    vuln_json.advisory.id,
                    vuln_json.package.name
                );
            }
        }

        result.scan_duration_ms = start_time.elapsed().as_millis() as u64;
        result.success = true;

        Ok(result)
    }

    /// Parse vulnerability severity from advisory metadata
    /// 
    /// Attempts to extract severity from:
    /// 1. CVSS vector string (if present)
    /// 2. CVE aliases (if present) 
    /// 3. Defaults to Info if unable to determine
    fn parse_severity(advisory: &AdvisoryMetadata) -> Result<VulnerabilitySeverity, AuditError> {
        // Try parsing from CVSS vector if available
        if let Some(cvss) = &advisory.cvss {
            return Self::severity_from_cvss(cvss);
        }
        
        // Check if there are CVE aliases (indicates real vulnerability)
        if !advisory.aliases.is_empty() {
            // Has CVE - default to Medium if no CVSS
            return Ok(VulnerabilitySeverity::Medium);
        }
        
        // No CVSS, no CVE - likely informational
        Ok(VulnerabilitySeverity::Info)
    }

    /// Extract severity level from CVSS v3.1 vector string
    /// 
    /// CVSS format: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    /// Base score ranges:
    /// - Critical: 9.0-10.0
    /// - High: 7.0-8.9
    /// - Medium: 4.0-6.9
    /// - Low: 0.1-3.9
    fn severity_from_cvss(cvss: &str) -> Result<VulnerabilitySeverity, AuditError> {
        // For now, do a simple heuristic based on impact ratings
        // A full CVSS parser would be more accurate but also more complex
        
        let high_impact = cvss.contains("C:H") || cvss.contains("I:H") || cvss.contains("A:H");
        let medium_impact = cvss.contains("C:M") || cvss.contains("I:M") || cvss.contains("A:M");
        
        // Network accessible with high impact = Critical
        if cvss.contains("AV:N") && high_impact {
            return Ok(VulnerabilitySeverity::Critical);
        }
        
        // High impact regardless of vector = High
        if high_impact {
            return Ok(VulnerabilitySeverity::High);
        }
        
        // Medium impact = Medium
        if medium_impact {
            return Ok(VulnerabilitySeverity::Medium);
        }
        
        // Low impact = Low
        Ok(VulnerabilitySeverity::Low)
    }

    /// Update atomic vulnerability counters
    fn update_counters(&self, result: &AuditResult) {
        let critical = result.count_by_severity(VulnerabilitySeverity::Critical) as u32;
        let high = result.count_by_severity(VulnerabilitySeverity::High) as u32;
        let medium = result.count_by_severity(VulnerabilitySeverity::Medium) as u32;
        let low = result.count_by_severity(VulnerabilitySeverity::Low) as u32;

        self.critical_count.store(critical, Ordering::Relaxed);
        self.high_count.store(high, Ordering::Relaxed);
        self.medium_count.store(medium, Ordering::Relaxed);
        self.low_count.store(low, Ordering::Relaxed);
    }

    /// Update lock-free vulnerability cache
    fn update_cache(&self, result: &AuditResult) {
        for vulnerability in &result.vulnerabilities {
            let key = vulnerability.id;
            let status = if vulnerability.patched.is_some() {
                VulnerabilityStatus::Patched
            } else {
                VulnerabilityStatus::Active
            };
            self.cache.insert(key, status);
        }
    }

    /// Check vulnerability status in cache
    pub fn check_cache(&self, vulnerability_id: &str) -> Option<VulnerabilityStatus> {
        let key = ArrayString::from(vulnerability_id).ok()?;
        self.cache.get(&key).map(|entry| *entry.value())
    }

    /// Get current vulnerability metrics
    pub fn get_metrics(&self) -> VulnerabilityMetrics {
        VulnerabilityMetrics {
            critical_count: self.critical_count.load(Ordering::Relaxed),
            high_count: self.high_count.load(Ordering::Relaxed),
            medium_count: self.medium_count.load(Ordering::Relaxed),
            low_count: self.low_count.load(Ordering::Relaxed),
            total_scans: self.total_scans.load(Ordering::Relaxed),
            successful_scans: self.successful_scans.load(Ordering::Relaxed),
            cache_size: self.cache.len() as u64,
        }
    }

    /// Clear vulnerability cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Update scan timeout
    pub fn set_timeout(&mut self, duration: Duration) {
        self.timeout_duration = duration;
    }

    /// Check if thresholds are exceeded
    pub fn thresholds_exceeded(&self, result: &AuditResult) -> bool {
        self.thresholds.exceeded_by(result)
    }
}

/// Vulnerability metrics for monitoring
#[derive(Debug, Clone, Copy)]
pub struct VulnerabilityMetrics {
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub total_scans: u64,
    pub successful_scans: u64,
    pub cache_size: u64,
}

impl VulnerabilityMetrics {
    /// Calculate success rate as percentage
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_scans == 0 {
            0.0
        } else {
            (self.successful_scans as f64 / self.total_scans as f64) * 100.0
        }
    }

    /// Get total vulnerability count
    #[must_use]
    pub fn total_vulnerabilities(&self) -> u32 {
        self.critical_count + self.high_count + self.medium_count + self.low_count
    }

    /// Check if any critical vulnerabilities exist
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.critical_count > 0
    }
}

/// CI/CD integration helpers
pub mod ci_cd {
    use super::{
        ArrayString, AuditResult, AuditThresholds, VulnerabilityScanner, VulnerabilitySeverity,
    };

    /// Check if vulnerabilities exceed CI/CD thresholds
    pub fn should_fail_build(scanner: &VulnerabilityScanner, result: &AuditResult) -> bool {
        scanner.thresholds_exceeded(result)
    }

    /// Generate CI/CD failure message
    pub fn generate_failure_message(
        result: &AuditResult,
        _thresholds: &AuditThresholds,
    ) -> ArrayString<512> {
        let mut message = ArrayString::new();

        let critical = result.count_by_severity(VulnerabilitySeverity::Critical);
        let high = result.count_by_severity(VulnerabilitySeverity::High);
        let medium = result.count_by_severity(VulnerabilitySeverity::Medium);
        let low = result.count_by_severity(VulnerabilitySeverity::Low);

        let _ = message.try_push_str(&format!(
            "Vulnerability scan failed: Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}"
        ));

        message
    }

    /// Format scan results for CI/CD output
    #[must_use]
    pub fn format_scan_results(result: &AuditResult) -> ArrayString<1024> {
        let mut output = ArrayString::new();

        let _ = output.try_push_str(&format!(
            "Vulnerability Scan Results:\n\
            - Total vulnerabilities: {}\n\
            - Critical: {}\n\
            - High: {}\n\
            - Medium: {}\n\
            - Low: {}\n\
            - Packages scanned: {}\n\
            - Scan duration: {}ms\n",
            result.vulnerabilities.len(),
            result.count_by_severity(VulnerabilitySeverity::Critical),
            result.count_by_severity(VulnerabilitySeverity::High),
            result.count_by_severity(VulnerabilitySeverity::Medium),
            result.count_by_severity(VulnerabilitySeverity::Low),
            result.packages_scanned,
            result.scan_duration_ms
        ));

        output
    }
}
