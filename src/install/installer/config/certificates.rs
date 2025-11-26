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

#[cfg(windows)]
use windows::Win32::Security::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SECURITY_DESCRIPTOR,
};
#[cfg(windows)]
use windows::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    SetFileAttributesW, 
    FILE_ATTRIBUTE_HIDDEN,
    FILE_FLAGS_AND_ATTRIBUTES,
};
#[cfg(windows)]
use windows::core::PCWSTR;

/// Set Windows ACL permissions on certificate file
/// 
/// Security policy: Owner read/write only (equivalent to Unix 0o600)
/// - SYSTEM: Full Control (allows Windows services to function)
/// - Administrators: Full Control (allows admin maintenance)
/// - Owner: Read + Write (current user can use certificate)
/// - Everyone else: No access (deny all other users)
///
/// Uses SDDL (Security Descriptor Definition Language) for clarity and maintainability.
#[cfg(windows)]
fn set_windows_certificate_permissions(path: &Path) -> Result<()> {
    use windows::Win32::Security::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW,
        PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_REVISION,
    };
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::core::PCWSTR;
    
    // SDDL string breakdown:
    // D:           - DACL (Discretionary Access Control List)
    // P            - Protected (don't inherit from parent)
    // AI           - Auto-inherit enabled for children
    // (A;;FA;;;SY) - Allow, Full Access, SYSTEM account
    // (A;;FA;;;BA) - Allow, Full Access, Built-in Administrators
    // (A;;FRFW;;;OW) - Allow, File Read + File Write, Owner
    //
    // This matches Unix 0o600: owner can read/write, nobody else
    // SYSTEM and Administrators are Windows equivalents of root
    let sddl = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFW;;;OW)";
    
    // Convert to UTF-16 (Windows native string format)
    let sddl_wide = super::super::windows::utils::to_wide_string(sddl);
    
    // Convert SDDL string to security descriptor
    let mut sd_ptr: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let mut sd_size: u32 = 0;
    
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SECURITY_DESCRIPTOR_REVISION,
            &mut sd_ptr,
            Some(&mut sd_size),
        )
        .context("Failed to convert SDDL string to security descriptor")?;
    }
    
    // Ensure we free the allocated security descriptor
    let _guard = scopeguard::guard(sd_ptr, |sd| {
        if !sd.0.is_null() {
            unsafe { LocalFree(HLOCAL(sd.0 as _)) };
        }
    });
    
    // Apply security descriptor to file
    let path_wide = super::super::windows::utils::to_wide_string(
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid path: non-UTF8 characters"))?,
    );
    
    use windows::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        SE_FILE_OBJECT,
    };
    
    unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,  // Don't change owner
            None,  // Don't change group
            Some(std::mem::transmute(sd_ptr)),  // Set DACL from security descriptor
            None,  // Don't change SACL
        )
        .context("Failed to apply ACL to certificate file")?;
    }
    
    // Defense-in-depth: Mark file as hidden
    // This makes it less likely to be accidentally accessed
    let attributes = FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_HIDDEN.0);
    unsafe {
        SetFileAttributesW(PCWSTR(path_wide.as_ptr()), attributes)
            .context("Failed to set hidden attribute on certificate file")?;
    }
    
    info!("Applied Windows ACL permissions to certificate file: {:?}", path);
    Ok(())
}

/// Generate wildcard certificate without importing (runs as unprivileged user)
///
/// Creates a self-signed certificate with Subject Alternative Names (SANs) for:
/// - mcp.kodegen.ai
/// - *.kodegen.dev
/// - Other Kodegen domains
///
/// Certificate import to system trust store is deferred to install_with_elevated_privileges()
/// in main.rs, which executes privileged operations at the end of installation.
///
/// # Security
///
/// Certificate private key files are protected with restrictive permissions:
/// - Unix: 0o600 (owner read/write only)
/// - Windows: ACL with owner read/write, SYSTEM/Administrators full control
///
/// # Returns
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

    // Set secure permissions on certificate file (owner read/write only)
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
            .context("Failed to set Unix file permissions on certificate")?;
    }

    #[cfg(windows)]
    {
        set_windows_certificate_permissions(&wildcard_cert_path)
            .context("Failed to set Windows ACL permissions on certificate")?;
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

/// Import certificate to macOS System keychain using Security.framework
#[cfg(target_os = "macos")]
async fn import_certificate_macos(cert_path: &Path) -> Result<()> {
    use security_framework::certificate::SecCertificate;
    use security_framework::trust_settings::{TrustSettings, Domain};

    info!("Importing certificate to macOS keychain via Security.framework...");

    // Read certificate file
    let combined_pem = tokio::fs::read_to_string(cert_path)
        .await
        .context("Failed to read certificate file")?;

    // Extract certificate-only part (remove private key if present)
    let cert_only = if let Some(key_start) = combined_pem.find("-----BEGIN PRIVATE KEY-----") {
        &combined_pem[..key_start]
    } else {
        &combined_pem
    };

    // Parse PEM to DER format (reusing existing pem crate)
    let cert_pem_parsed = pem::parse(cert_only)
        .context("Failed to parse certificate PEM format")?;

    if cert_pem_parsed.tag() != "CERTIFICATE" {
        return Err(anyhow::anyhow!("Invalid PEM tag: expected CERTIFICATE, got {}", cert_pem_parsed.tag()));
    }

    let cert_der = cert_pem_parsed.contents();

    // Perform Security.framework operations in blocking task (sync FFI)
    let cert_der_owned = cert_der.to_vec();
    tokio::task::spawn_blocking(move || {
        // Create SecCertificate from DER bytes
        let certificate = SecCertificate::from_der(&cert_der_owned)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate DER: {}", e))?;

        // Import to Admin domain with trust-for-all-purposes
        // Using Admin domain (not System) because it's for locally-administered certificates
        // System domain is reserved for Apple's root certificates
        let trust_settings = TrustSettings::new(Domain::Admin);

        // Verified API from trust_settings.rs:115-139
        // When trust_settings parameter is null, it means "always trust"
        trust_settings
            .set_trust_settings_always(&certificate)
            .map_err(|e| anyhow::anyhow!("Failed to set trust settings: {} (code: {})", e, e.code()))?;

        info!("✓ Certificate imported to macOS Admin trust domain (accessible system-wide)");
        Ok(())
    })
    .await
    .context("Task panicked during certificate import")?
}

/// Import certificate to Linux system trust store
///
/// Uses filesystem operations + update-ca-certificates (Debian/Ubuntu) or
/// update-ca-trust (RHEL/Fedora/Arch). This is the official method as Linux
/// has no standard certificate management API.
#[cfg(target_os = "linux")]
async fn import_certificate_linux(cert_path: &Path) -> Result<()> {
    info!("Importing certificate to Linux system trust store...");

    // Read certificate file
    let combined_pem = tokio::fs::read_to_string(cert_path)
        .await
        .context("Failed to read certificate file")?;

    // Extract certificate-only part (remove private key)
    let cert_only = if let Some(key_start) = combined_pem.find("-----BEGIN PRIVATE KEY-----") {
        &combined_pem[..key_start]
    } else {
        &combined_pem
    };

    // Validate PEM format before copying to system directory (using existing pem crate)
    let cert_pem_parsed = pem::parse(cert_only)
        .context("Failed to parse certificate PEM - file may be corrupted")?;

    if cert_pem_parsed.tag() != "CERTIFICATE" {
        return Err(anyhow::anyhow!(
            "Invalid certificate format: expected CERTIFICATE block, found {}",
            cert_pem_parsed.tag()
        ));
    }

    // Validate X.509 structure (using existing x509-parser crate)
    let (_remainder, x509_cert) = x509_parser::parse_x509_certificate(cert_pem_parsed.contents())
        .map_err(|e| anyhow::anyhow!("Invalid X.509 certificate structure: {}", e))?;

    // Log certificate details for troubleshooting
    info!("Certificate subject: {}", x509_cert.subject());
    info!("Certificate issuer: {}", x509_cert.issuer());
    info!("Certificate valid until: {:?}", x509_cert.validity().not_after);

    // Determine the correct CA update command for this distribution
    let (ca_dir, ca_update_cmd, ca_update_args) = detect_linux_ca_tool().await?;

    // Construct destination path
    let dest_path = ca_dir.join("kodegen-mcp.crt");

    // Ensure CA certificates directory exists
    tokio::fs::create_dir_all(&ca_dir)
        .await
        .with_context(|| format!("Failed to create directory: {}", ca_dir.display()))?;

    // Write certificate to CA directory (requires root)
    tokio::fs::write(&dest_path, cert_only)
        .await
        .with_context(|| format!("Failed to write certificate to {}", dest_path.display()))?;

    // Set correct permissions (644 = rw-r--r--)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o644);
        tokio::fs::set_permissions(&dest_path, perms)
            .await
            .context("Failed to set certificate permissions to 644")?;
    }

    info!("Certificate written to: {}", dest_path.display());
    info!("Running {} to update trust store...", ca_update_cmd);

    // Run distribution-specific CA update command
    let output = tokio::process::Command::new(ca_update_cmd)
        .args(ca_update_args)
        .output()
        .await
        .with_context(|| format!("Failed to execute {}", ca_update_cmd))?;

    if output.status.success() {
        info!("✓ Certificate imported to Linux system trust store");

        // Log stdout for debugging
        if !output.stdout.is_empty() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            info!("CA update output: {}", stdout.trim());
        }

        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(anyhow::anyhow!(
            "{} failed (exit code {}):\nstdout: {}\nstderr: {}",
            ca_update_cmd,
            output.status.code().unwrap_or(-1),
            stdout.trim(),
            stderr.trim()
        ))
    }
}

/// Detect Linux distribution and return appropriate CA directory and update command
#[cfg(target_os = "linux")]
async fn detect_linux_ca_tool() -> Result<(PathBuf, &'static str, Vec<&'static str>)> {
    use std::path::PathBuf;

    // Debian/Ubuntu: /usr/local/share/ca-certificates + update-ca-certificates
    if tokio::fs::metadata("/etc/debian_version").await.is_ok() {
        return Ok((
            PathBuf::from("/usr/local/share/ca-certificates"),
            "update-ca-certificates",
            vec![]  // No additional args
        ));
    }

    // RHEL/Fedora/CentOS: /etc/pki/ca-trust/source/anchors + update-ca-trust
    if tokio::fs::metadata("/etc/redhat-release").await.is_ok()
        || tokio::fs::metadata("/etc/fedora-release").await.is_ok() {
        return Ok((
            PathBuf::from("/etc/pki/ca-trust/source/anchors"),
            "update-ca-trust",
            vec![]  // No additional args
        ));
    }

    // Arch Linux: /etc/ca-certificates/trust-source/anchors + trust extract-compat
    if tokio::fs::metadata("/etc/arch-release").await.is_ok() {
        return Ok((
            PathBuf::from("/etc/ca-certificates/trust-source/anchors"),
            "trust",
            vec!["extract-compat"]  // Arch requires this argument
        ));
    }

    // Fallback to Debian/Ubuntu method (most common)
    warn!("Unknown Linux distribution, using Debian/Ubuntu CA method as fallback");
    Ok((
        PathBuf::from("/usr/local/share/ca-certificates"),
        "update-ca-certificates",
        vec![]
    ))
}

/// Import certificate to Windows Root certificate store using CryptoAPI
#[cfg(target_os = "windows")]
async fn import_certificate_windows(cert_path: &Path) -> Result<()> {
    use windows::Win32::Security::Cryptography::{
        CertOpenStore, CertAddEncodedCertificateToStore, CertCloseStore,
        CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W,
        CERT_SYSTEM_STORE_LOCAL_MACHINE, X509_ASN_ENCODING, PKCS_7_ASN_ENCODING,
        HCERTSTORE,
    };
    use windows::core::{PCWSTR, HSTRING};

    info!("Importing certificate to Windows Root certificate store via CryptoAPI...");

    // Read certificate file
    let combined_pem = tokio::fs::read_to_string(cert_path)
        .await
        .context("Failed to read certificate file")?;

    // Extract certificate-only part (remove private key)
    let cert_only = if let Some(key_start) = combined_pem.find("-----BEGIN PRIVATE KEY-----") {
        &combined_pem[..key_start]
    } else {
        &combined_pem
    };

    // Parse PEM and validate structure (using existing pem crate)
    let cert_pem_parsed = pem::parse(cert_only)
        .context("Failed to parse certificate PEM format")?;

    if cert_pem_parsed.tag() != "CERTIFICATE" {
        return Err(anyhow::anyhow!(
            "Invalid certificate: expected CERTIFICATE block, found {}",
            cert_pem_parsed.tag()
        ));
    }

    let cert_der = cert_pem_parsed.contents().to_vec();

    // Validate X.509 structure before importing (using existing x509-parser crate)
    let (_remainder, x509_cert) = x509_parser::parse_x509_certificate(&cert_der)
        .map_err(|e| anyhow::anyhow!("Invalid X.509 certificate: {}", e))?;

    info!("Certificate subject: {}", x509_cert.subject());
    info!("Certificate issuer: {}", x509_cert.issuer());

    // Perform CryptoAPI operations in blocking task (sync Win32 API)
    tokio::task::spawn_blocking(move || {
        unsafe {
            // Open the Root certificate store for LOCAL_MACHINE
            // CERT_SYSTEM_STORE_LOCAL_MACHINE = system-wide trust (all users)
            let store_name = HSTRING::from("Root");

            let store_handle = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,  // No encoding flags
                None,  // No cryptographic provider
                CERT_SYSTEM_STORE_LOCAL_MACHINE,
                Some(PCWSTR(store_name.as_ptr())),
            )
            .map_err(|e| anyhow::anyhow!(
                "Failed to open Root certificate store (error: {}). Ensure running with Administrator privileges.",
                e
            ))?;

            // Ensure store is always closed (using existing scopeguard crate)
            let _store_guard = scopeguard::guard(store_handle, |handle| {
                let _ = CertCloseStore(handle, 0);
            });

            // Add certificate to Root store
            // Verified from Microsoft docs: CERT_STORE_ADD_REPLACE_EXISTING
            // "If a matching certificate exists, it is deleted and a new certificate is created"
            let result = CertAddEncodedCertificateToStore(
                store_handle,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,  // Standard encoding
                &cert_der,
                CERT_STORE_ADD_REPLACE_EXISTING,  // Replace if exists
                None,  // Don't return certificate context
            );

            match result {
                Ok(_) => {
                    info!("✓ Certificate imported to Windows Root certificate store (LOCAL_MACHINE)");
                    Ok(())
                }
                Err(e) => {
                    Err(anyhow::anyhow!(
                        "Failed to add certificate to Root store: {}. The certificate may already exist or be invalid.",
                        e
                    ))
                }
            }
        }
    })
    .await
    .context("Task panicked during certificate import")?
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
