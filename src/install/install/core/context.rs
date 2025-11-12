//! Installation context with directory management, certificate generation, and validation

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use log::warn;
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use tokio::sync::mpsc;

use super::certificate::CertificateConfig;
use super::progress::InstallProgress;
use super::service::ServiceConfig;

/// Installation context
#[derive(Debug)]
pub struct InstallContext {
    pub exe_path: PathBuf,
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
    pub log_dir: PathBuf,
    pub cert_dir: PathBuf,
    pub services: Vec<ServiceConfig>,
    pub certificate_config: CertificateConfig,
    pub progress_tx: Option<mpsc::Sender<InstallProgress>>,
    progress_disabled: Arc<AtomicBool>,
}

impl InstallContext {
    /// Create new install context with optimized initialization
    pub fn new(exe_path: PathBuf) -> Self {
        let data_dir = Self::get_data_dir();
        let config_path = data_dir.join("config.toml");
        let log_dir = data_dir.join("logs");
        let cert_dir = data_dir.join("certs");

        Self {
            exe_path,
            config_path,
            data_dir,
            log_dir,
            cert_dir,
            services: Vec::new(),
            certificate_config: CertificateConfig::default(),
            progress_tx: None,
            progress_disabled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get platform-specific data directory (always system-wide for system daemons)
    pub(crate) fn get_data_dir() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/usr/local/var/kodegen")
        }

        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/kodegen")
        }

        #[cfg(target_os = "freebsd")]
        {
            PathBuf::from("/var/db/kodegen")
        }

        #[cfg(target_os = "openbsd")]
        {
            PathBuf::from("/var/db/kodegen")
        }

        #[cfg(target_os = "windows")]
        {
            std::env::var("ProgramData")
                .map(|p| PathBuf::from(p).join("Kodegen"))
                .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData\\Kodegen"))
        }

        #[cfg(not(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "windows"
        )))]
        {
            std::env::temp_dir().join("kodegen")
        }
    }

    /// Add service to installation
    pub fn add_service(&mut self, service: ServiceConfig) {
        self.services.push(service);
    }

    /// Set certificate configuration
    pub fn set_certificate_config(&mut self, config: CertificateConfig) {
        self.certificate_config = config;
    }

    /// Set progress channel
    pub fn set_progress_channel(&mut self, tx: mpsc::Sender<InstallProgress>) {
        self.progress_tx = Some(tx);
    }

    /// Send critical progress update - fails if channel closed
    /// Use for phase transitions (discovery, extraction, completion)
    pub fn send_critical_progress(&self, progress: InstallProgress) -> Result<()> {
        if let Some(ref tx) = self.progress_tx {
            // Check if channel already closed
            if tx.is_closed() {
                return Err(anyhow::anyhow!(
                    "Installation cancelled: progress channel closed (user closed GUI or process crashed)"
                ));
            }

            // try_send for synchronous context (we're in sync fn)
            tx.try_send(progress)
                .map_err(|e| match e {
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        anyhow::anyhow!("Installation cancelled: progress channel closed")
                    }
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        anyhow::anyhow!(
                            "Progress channel full - GUI not consuming updates fast enough"
                        )
                    }
                })?;
        }
        Ok(())
    }

    /// Send non-critical progress update - logs warning and disables on failure
    /// Use for frequent updates (download chunks, extraction progress)
    pub fn send_progress_best_effort(&self, progress: InstallProgress) {
        // Early exit if already disabled
        if self.progress_disabled.load(Ordering::Relaxed) {
            return;
        }

        if let Some(ref tx) = self.progress_tx
            && let Err(e) = tx.try_send(progress)
        {
            match e {
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    warn!(
                        "Progress channel closed (GUI closed or crashed). \
                         Installation will continue without progress updates."
                    );
                    self.progress_disabled.store(true, Ordering::Relaxed);
                }
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    // Channel full - just skip this update, don't disable
                    // This is expected with bounded channels
                }
            }
        }
    }

    /// Send progress update with fast progress reporting
    /// Legacy method - prefer send_critical_progress or send_progress_best_effort
    pub fn send_progress(&self, progress: InstallProgress) {
        self.send_progress_best_effort(progress);
    }

    /// Create necessary directories with optimized directory creation
    pub fn create_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("Failed to create data directory: {:?}", self.data_dir))?;

        fs::create_dir_all(&self.log_dir)
            .with_context(|| format!("Failed to create log directory: {:?}", self.log_dir))?;

        fs::create_dir_all(&self.cert_dir)
            .with_context(|| format!("Failed to create cert directory: {:?}", self.cert_dir))?;

        self.send_progress(InstallProgress::new(
            "directories".to_string(),
            0.2,
            "Created installation directories".to_string(),
        ));

        Ok(())
    }

    /// Generate certificates with optimized certificate generation
    pub fn generate_certificates(&self) -> Result<()> {
        let config = &self.certificate_config;

        // Create CA certificate parameters
        let mut ca_params = CertificateParams::new(vec![config.common_name.clone()])?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &config.common_name);
        dn.push(DnType::OrganizationName, &config.organization);
        dn.push(DnType::CountryName, &config.country);
        ca_params.distinguished_name = dn;

        // Set validity period
        let now = time::OffsetDateTime::now_utc();
        let not_before = now;
        let not_after = now + time::Duration::seconds(i64::from(config.validity_days) * 24 * 3600);
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;

        // Generate CA certificate
        let ca_key_pair =
            rcgen::KeyPair::generate().with_context(|| "Failed to generate CA key pair")?;
        let ca_cert = ca_params
            .clone()
            .self_signed(&ca_key_pair)
            .with_context(|| "Failed to generate CA certificate")?;

        // Save CA certificate and key
        let ca_cert_path = self.cert_dir.join("ca.crt");
        let ca_key_path = self.cert_dir.join("ca.key");

        fs::write(&ca_cert_path, ca_cert.pem())
            .with_context(|| format!("Failed to write CA certificate to {ca_cert_path:?}"))?;

        fs::write(&ca_key_path, ca_key_pair.serialize_pem())
            .with_context(|| format!("Failed to write CA key to {ca_key_path:?}"))?;

        // Generate server certificate
        self.generate_server_certificate(&ca_cert, &ca_params, ca_key_pair)?;

        self.send_progress(InstallProgress::new(
            "certificates".to_string(),
            0.4,
            "Generated SSL certificates".to_string(),
        ));

        Ok(())
    }

    /// Generate server certificate with optimized server cert generation
    fn generate_server_certificate(
        &self,
        _ca_cert: &rcgen::Certificate,
        ca_params: &rcgen::CertificateParams,
        ca_key_pair: rcgen::KeyPair,
    ) -> Result<()> {
        let config = &self.certificate_config;

        // Create server certificate parameters
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()])?;

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "localhost");
        dn.push(DnType::OrganizationName, &config.organization);
        dn.push(DnType::CountryName, &config.country);
        server_params.distinguished_name = dn;

        // Add SAN entries
        for san in &config.san_entries {
            if san.parse::<std::net::IpAddr>().is_ok() {
                server_params
                    .subject_alt_names
                    .push(SanType::IpAddress(san.parse()?));
            } else {
                let ia5_string =
                    Ia5String::try_from(san.as_str()).context("Invalid DNS name in SAN")?;
                server_params
                    .subject_alt_names
                    .push(SanType::DnsName(ia5_string));
            }
        }

        // Set validity period
        let now = time::OffsetDateTime::now_utc();
        let not_before = now;
        let not_after = now + time::Duration::seconds(i64::from(config.validity_days) * 24 * 3600);
        server_params.not_before = not_before;
        server_params.not_after = not_after;

        // Create CA issuer for signing server certificate (rcgen 0.14+ API)
        let ca_issuer = rcgen::Issuer::new(ca_params.clone(), ca_key_pair);

        // Generate server certificate signed by CA
        let server_key_pair =
            rcgen::KeyPair::generate().with_context(|| "Failed to generate server key pair")?;
        let server_cert = server_params
            .signed_by(&server_key_pair, &ca_issuer)
            .with_context(|| "Failed to generate server certificate")?;

        // Save server certificate and key
        let server_cert_path = self.cert_dir.join("server.crt");
        let server_key_path = self.cert_dir.join("server.key");

        fs::write(&server_cert_path, server_cert.pem()).with_context(|| {
            format!("Failed to write server certificate to {server_cert_path:?}")
        })?;

        fs::write(&server_key_path, server_key_pair.serialize_pem())
            .with_context(|| format!("Failed to write server key to {server_key_path:?}"))?;

        Ok(())
    }

    /// Validate installation prerequisites with fast validation
    pub fn validate_prerequisites(&self) -> Result<()> {
        // Check if running as appropriate user - defer actual escalation to end of install
        #[cfg(unix)]
        {
            let uid = unsafe { libc::getuid() };

            if uid != 0 {
                // Don't escalate yet - just validate we CAN escalate later
                // This allows all unprivileged operations (downloads, extraction) to run as user
                if !Self::can_escalate() {
                    return Err(anyhow::anyhow!(
                        "Installation requires sudo privileges. Please ensure sudo is available.\n\
                         Run 'which sudo' to check if sudo is installed."
                    ));
                }
                // Continue running as unprivileged user - privileged ops will be executed at the end
            }
        }

        // Check if executable exists and is executable
        if !self.exe_path.exists() {
            return Err(anyhow::anyhow!("Executable not found: {:?}", self.exe_path));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&self.exe_path)
                .with_context(|| format!("Failed to read metadata for {:?}", self.exe_path))?;

            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(anyhow::anyhow!(
                    "Executable is not executable: {:?}",
                    self.exe_path
                ));
            }
        }

        self.send_progress(InstallProgress::new(
            "validation".to_string(),
            0.1,
            "Validated installation prerequisites".to_string(),
        ));

        Ok(())
    }

    /// Check if privilege escalation is possible (sudo is available)
    /// Does NOT actually escalate - just validates that escalation would be possible
    #[cfg(unix)]
    fn can_escalate() -> bool {
        use std::process::Command;

        // Check if sudo is available
        let sudo_check = Command::new("which")
            .arg("sudo")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        matches!(sudo_check, Ok(status) if status.success())
    }

    #[cfg(not(unix))]
    fn can_escalate() -> bool {
        // On non-Unix platforms, assume elevation is available
        true
    }

    /// Escalate privileges using sudo by re-executing with sudo
    /// NOTE: This function is kept for backward compatibility but is no longer used
    /// in the normal installation flow. Privilege escalation is now deferred until
    /// the end of the installation process.
    #[cfg(unix)]
    #[allow(dead_code)]
    fn escalate_with_sudo() -> Result<()> {
        use std::io::Write;
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        // Get the current executable path and arguments
        let exe_path = std::env::current_exe().context("Failed to get current executable path")?;
        let args: Vec<String> = std::env::args().collect();

        eprintln!("   Current exe: {exe_path:?}");
        eprintln!("   Args: {args:?}");

        // Check if sudo is available
        let sudo_check = Command::new("which")
            .arg("sudo")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        match sudo_check {
            Ok(status) if status.success() => {
                // sudo is available and command succeeded
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "sudo not found - please run as root or install sudo"
                ));
            }
        }

        eprintln!("   Executing: sudo {:?} {:?}", exe_path, &args[1..]);

        // Flush stderr to ensure messages are visible before exec
        let _ = std::io::stderr().flush();

        // Re-execute with sudo using exec to replace the current process
        let err = Command::new("sudo")
            .arg(&exe_path)
            .args(&args[1..]) // Skip the program name
            .exec(); // This replaces the current process and never returns on success

        // If we reach here, exec failed
        Err(anyhow::anyhow!("Failed to exec sudo: {err}"))
    }
}
