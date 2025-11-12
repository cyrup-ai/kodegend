//! Certificate generation and management for Kodegen
//!
//! This module handles TLS certificate generation, validation, and system trust store import
//! for secure MCP server communication.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use log::{info, warn};
use pem;
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use x509_parser;

use super::super::core::InstallContext;

/// Generate wildcard certificate without importing (runs as unprivileged user)
///
/// Certificate import to system trust store is deferred to install_with_elevated_privileges()
/// in main.rs, which executes privileged operations at the end of installation.
///
/// Returns the validated certificate content to eliminate TOCTOU vulnerability.
pub async fn generate_wildcard_certificate_only() -> Result<String> {
    let cert_dir = get_cert_dir();
    let wildcard_cert_path = cert_dir.join("wildcard.pem");

    // Check if wildcard certificate already exists and is valid
    if wildcard_cert_path.exists() {
        // Read existing certificate into memory
        let existing_content = tokio::fs::read_to_string(&wildcard_cert_path)
            .await
            .context("Failed to read existing certificate")?;
        
        // Validate the content
        if let Ok(()) = validate_cert_content(&existing_content) {
            info!("Valid wildcard certificate already exists");
            return Ok(existing_content);  // Return validated content
        }
        info!("Existing wildcard certificate is invalid, regenerating");
    }

    // Ensure certificate directory exists
    tokio::fs::create_dir_all(&cert_dir)
        .await
        .context("Failed to create certificate directory")?;

    info!("Generating Kodegen certificate for mcp.kodegen.ai...");

    // Create certificate parameters for mcp.kodegen.ai
    let mut params = CertificateParams::new(vec!["mcp.kodegen.ai".to_string()])?;

    // Add subject alternative names for local MCP server
    params.subject_alt_names = vec![
        SanType::DnsName(Ia5String::try_from("mcp.kodegen.ai").context("Invalid DNS name")?),
        SanType::DnsName(Ia5String::try_from("localhost").context("Invalid DNS name")?),
        SanType::IpAddress("127.0.0.1".parse()?),
        SanType::IpAddress("::1".parse()?),
    ];

    // Set distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Kodegen");
    dn.push(DnType::CommonName, "mcp.kodegen.ai");
    params.distinguished_name = dn;

    // Set non-expiring validity period (100 years)
    use time::OffsetDateTime;
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::seconds(100 * 365 * 24 * 60 * 60);

    // Generate self-signed certificate with key pair
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to generate certificate")?;

    // Create combined PEM file with certificate and private key
    let combined_pem = format!("{}\n{}", cert.pem(), key_pair.serialize_pem());

    // Write combined PEM file (for future reference)
    tokio::fs::write(&wildcard_cert_path, &combined_pem)
        .await
        .context("Failed to write wildcard certificate")?;

    // Set secure permissions on certificate file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = tokio::fs::metadata(&wildcard_cert_path)
            .await
            .context("Failed to get file metadata")?
            .permissions();
        perms.set_mode(0o600); // Owner read/write only
        tokio::fs::set_permissions(&wildcard_cert_path, perms)
            .await
            .context("Failed to set file permissions")?;
    }

    info!(
        "Kodegen certificate generated successfully at {}",
        wildcard_cert_path.display()
    );

    // Return the validated content (NOT the file path)
    Ok(combined_pem)
}

/// Generate and import wildcard certificate with optimized certificate generation
/// DEPRECATED: Use generate_wildcard_certificate_only() instead
/// This function is kept for backward compatibility but performs privileged operations
#[allow(dead_code)]
pub async fn generate_and_import_wildcard_certificate() -> Result<()> {
    // First generate the certificate
    generate_wildcard_certificate_only().await?;
    
    // Then import it (requires root)
    let cert_path = get_cert_dir().join("wildcard.pem");
    import_certificate_to_system(&cert_path).await?;
    
    Ok(())
}

/// Import certificate to system trust store
pub async fn import_certificate_to_system(cert_path: &Path) -> Result<()> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "macos")] {
            import_certificate_macos(cert_path).await
        } else if #[cfg(target_os = "linux")] {
            import_certificate_linux(cert_path).await
        } else if #[cfg(target_os = "windows")] {
            import_certificate_windows(cert_path).await
        } else {
            warn!("Certificate import not supported on this platform");
            Ok(())
        }
    }
}

/// Import certificate to macOS System keychain
#[cfg(target_os = "macos")]
async fn import_certificate_macos(cert_path: &Path) -> Result<()> {
    info!("Importing certificate to macOS System keychain...");

    // Extract just the certificate part (not private key) for system trust
    let combined_pem = tokio::fs::read_to_string(cert_path)
        .await
        .context("Failed to read certificate file")?;

    // Find the certificate part (everything before the private key)
    let cert_only = if let Some(key_start) = combined_pem.find("-----BEGIN PRIVATE KEY-----") {
        &combined_pem[..key_start]
    } else {
        &combined_pem
    };

    // Write certificate-only file to temp location (use PID for uniqueness)
    let temp_cert =
        std::env::temp_dir().join(format!("kodegen_mcp_cert_{}.crt", std::process::id()));
    tokio::fs::write(&temp_cert, cert_only)
        .await
        .context("Failed to write temp certificate")?;

    // Import to System keychain (requires elevated privileges)
    let output = tokio::process::Command::new("security")
        .args([
            "add-trusted-cert",
            "-d", // Add to admin trust settings
            "-r",
            "trustRoot", // Trust as root certificate
            "-k",
            "/Library/Keychains/System.keychain",
            temp_cert
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid temp cert path"))?,
        ])
        .output()
        .await
        .context("Failed to execute security command")?;

    // Clean up temp file
    let _ = tokio::fs::remove_file(&temp_cert).await;

    if output.status.success() {
        info!("Successfully imported certificate to macOS System keychain");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to import certificate to macOS keychain: {stderr}"
        ))
    }
}

/// Import certificate to Linux system trust store
#[cfg(target_os = "linux")]
async fn import_certificate_linux(cert_path: &Path) -> Result<()> {
    info!("Importing certificate to Linux system trust store...");

    // Extract just the certificate part (not private key)
    let combined_pem = tokio::fs::read_to_string(cert_path)
        .await
        .context("Failed to read certificate file")?;

    let cert_only = if let Some(key_start) = combined_pem.find("-----BEGIN PRIVATE KEY-----") {
        &combined_pem[..key_start]
    } else {
        &combined_pem
    };

    // Copy to system CA certificates directory
    let system_cert_path = "/usr/local/share/ca-certificates/kodegen-mcp.crt";

    // Ensure directory exists
    tokio::fs::create_dir_all("/usr/local/share/ca-certificates")
        .await
        .context("Failed to create ca-certificates directory")?;

    tokio::fs::write(system_cert_path, cert_only)
        .await
        .context("Failed to write certificate to system trust store")?;

    // Update certificate trust store
    let output = tokio::process::Command::new("update-ca-certificates")
        .output()
        .await
        .context("Failed to execute update-ca-certificates")?;

    if output.status.success() {
        info!("Successfully imported certificate to Linux system trust store");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to update certificate trust store: {stderr}"
        ))
    }
}

/// Import certificate to Windows certificate store
#[cfg(target_os = "windows")]
async fn import_certificate_windows(cert_path: &Path) -> Result<()> {
    info!("Importing certificate to Windows certificate store...");

    // Extract just the certificate part (not private key)
    let combined_pem = tokio::fs::read_to_string(cert_path)
        .await
        .context("Failed to read certificate file")?;

    let cert_only = if let Some(key_start) = combined_pem.find("-----BEGIN PRIVATE KEY-----") {
        &combined_pem[..key_start]
    } else {
        &combined_pem
    };

    // Write certificate-only file to temp location (use PID for uniqueness)
    let temp_cert =
        std::env::temp_dir().join(format!("kodegen_mcp_cert_{}.crt", std::process::id()));
    tokio::fs::write(&temp_cert, cert_only)
        .await
        .context("Failed to write temp certificate")?;

    // Import to Trusted Root Certification Authorities store
    let output = tokio::process::Command::new("certutil")
        .args([
            "-addstore",
            "-f",
            "Root",
            temp_cert
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid temp cert path"))?,
        ])
        .output()
        .await
        .context("Failed to execute certutil command")?;

    // Clean up temp file
    let _ = tokio::fs::remove_file(&temp_cert).await;

    if output.status.success() {
        info!("Successfully imported certificate to Windows certificate store");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to import certificate to Windows store: {stderr}"
        ))
    }
}

/// Get certificate directory path with platform-specific logic
fn get_cert_dir() -> PathBuf {
    InstallContext::get_data_dir().join("certs")
}

/// Validate existing wildcard certificate with fast validation
/// 
/// Called internally by validate_cert_content() during certificate generation.
/// Checks X.509 structure, expiration dates, and SAN entries.
#[allow(dead_code)]
pub fn validate_existing_wildcard_cert(cert_path: &Path) -> Result<()> {
    // Read certificate file
    let cert_pem = fs::read_to_string(cert_path).context("Failed to read certificate file")?;
    validate_cert_content(&cert_pem)
}

/// Helper function to validate certificate content
fn validate_cert_content(cert_pem: &str) -> Result<()> {
    // Parse certificate to validate it's well-formed
    let cert_der = pem::parse(cert_pem).context("Failed to parse certificate PEM")?;

    if cert_der.tag() != "CERTIFICATE" {
        return Err(anyhow::anyhow!("Invalid certificate format"));
    }

    // Parse X.509 certificate
    let cert = x509_parser::parse_x509_certificate(cert_der.contents())
        .context("Failed to parse X.509 certificate")?
        .1;

    // Check if certificate is still valid (not expired)
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Failed to get current time")?
        .as_secs();

    let not_after = cert.validity().not_after.timestamp() as u64;

    if now > not_after {
        return Err(anyhow::anyhow!("Certificate has expired"));
    }

    // Check if certificate expires within 30 days
    if now + (30 * 24 * 60 * 60) > not_after {
        warn!("Certificate expires within 30 days, consider regenerating");
    }

    // Validate required SANs are present
    let required_sans = vec![
        "mcp.kodegen.ai",
        "localhost",
        "127.0.0.1",
        "::1",
    ];
    
    let actual_sans = extract_sans_from_cert(&cert)?;
    
    // Check each required SAN is present
    for required_san in &required_sans {
        if !actual_sans.iter().any(|san| san == required_san) {
            return Err(anyhow::anyhow!(
                "Certificate missing required SAN: '{}'",
                required_san
            ));
        }
    }
    
    // Also validate Common Name matches
    let cn = cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("");
    
    if cn != "mcp.kodegen.ai" {
        warn!(
            "Certificate has Common Name '{}' (expected 'mcp.kodegen.ai'), but SANs are correct",
            cn
        );
    }

    Ok(())
}

/// Extract Subject Alternative Names from X.509 certificate
fn extract_sans_from_cert(cert: &x509_parser::certificate::X509Certificate) -> Result<Vec<String>> {
    use x509_parser::extensions::GeneralName;
    
    let mut sans = Vec::new();
    
    // Get SAN extension (returns Option)
    if let Some(san_ext) = cert.subject_alternative_name()? {
        // san_ext.value is &SubjectAlternativeName which has general_names field
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    sans.push(dns.to_string());
                }
                GeneralName::IPAddress(ip_bytes) => {
                    // Parse IP address bytes
                    let ip_str = match ip_bytes.len() {
                        4 => {
                            // IPv4
                            format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])
                        }
                        16 => {
                            // IPv6 - format as compressed notation
                            let ip = std::net::Ipv6Addr::from([
                                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                                ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
                                ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
                                ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15],
                            ]);
                            ip.to_string()
                        }
                        _ => continue, // Skip invalid IP
                    };
                    sans.push(ip_str);
                }
                _ => {} // Ignore other GeneralName types
            }
        }
    }
    
    Ok(sans)
}
