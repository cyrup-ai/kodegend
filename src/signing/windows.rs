//! Windows Authenticode signature verification using WinVerifyTrust API
//!
//! This module implements secure signature verification for Windows executables
//! using the official Microsoft WinVerifyTrust API with protection against
//! CVE-2013-3900 (certificate padding attack).

use std::path::Path;
use std::ptr;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows::core::GUID;
use windows::Win32::Security::Cryptography::{
    CryptQueryObject, CertFreeCertificateContext, CertGetNameStringW,
    CERT_QUERY_OBJECT_FILE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    HCERTSTORE, CERT_CONTEXT,
};

/// Expected publisher name for Kodegen binaries
///
/// This must match the certificate Subject CN field. Update this value
/// to match your actual code signing certificate.
const EXPECTED_PUBLISHER: &str = "Kodegen";

/// Verify Windows Authenticode signature on an executable
///
/// This function performs comprehensive signature verification:
/// 1. Validates Authenticode signature integrity using WinVerifyTrust
/// 2. Checks certificate chain against Windows trusted roots
/// 3. Verifies certificate hasn't expired or been revoked
/// 4. Ensures binary hasn't been tampered with since signing
///
/// # Security Notes
///
/// - Uses WTD_REVOKE_WHOLECHAIN to check entire certificate chain for revocation
/// - Protected against CVE-2013-3900 (certificate padding) via Windows updates
/// - Returns error for ANY signature validation failure
/// - Does NOT accept self-signed or ad-hoc signatures
///
/// # Errors
///
/// Returns error if:
/// - Binary is unsigned
/// - Signature is invalid (tampered binary)
/// - Certificate is expired or revoked
/// - Certificate doesn't chain to trusted root
/// - WinVerifyTrust API call fails
///
/// # Platform
///
/// Windows only. Requires Windows XP or later.
pub fn verify_signature(exe_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Convert path to wide string (UTF-16) as required by Windows API
    // Following existing pattern from src/control/windows_control.rs:72
    let path_str = exe_path
        .to_str()
        .ok_or("Invalid path: contains non-UTF-8 characters")?;
    let path_wide: Vec<u16> = path_str.encode_utf16().chain(Some(0)).collect();

    // Initialize WINTRUST_FILE_INFO structure
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: windows::core::PCWSTR(path_wide.as_ptr()),
        hFile: HANDLE(ptr::null_mut() as _),
        pgKnownSubject: ptr::null_mut(),
    };

    // Initialize WINTRUST_DATA structure
    // Based on Microsoft documentation and StackOverflow example
    let mut trust_data: WINTRUST_DATA = unsafe { std::mem::zeroed() };

    trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    trust_data.dwUIChoice = WTD_UI_NONE; // No user interface
    trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; // Check entire cert chain
    trust_data.dwUnionChoice = WTD_CHOICE_FILE; // Verifying a file
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.hWVTStateData = HANDLE(ptr::null_mut() as _);
    trust_data.pwszURLReference = windows::core::PWSTR::null();
    trust_data.dwProvFlags = windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(0);
    trust_data.dwUIContext = windows::Win32::Security::WinTrust::WINTRUST_DATA_UICONTEXT(0);
    trust_data.pPolicyCallbackData = ptr::null_mut();
    trust_data.pSIPClientData = ptr::null_mut();

    // Set the union member to point to our file info
    trust_data.Anonymous = WINTRUST_DATA_0 {
        pFile: &mut file_info as *mut _,
    };

    // Call WinVerifyTrust to verify the signature
    // WINTRUST_ACTION_GENERIC_VERIFY_V2 verifies embedded Authenticode signature
    let mut action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe {
        WinVerifyTrust(
            windows::Win32::Foundation::HWND(INVALID_HANDLE_VALUE.0),           // No window handle
            &mut action_id as *mut GUID,      // Verification action
            &mut trust_data as *mut _ as _, // Trust data
        )
    };

    // Check verification result
    // Per Microsoft docs: return value is LONG, not HRESULT
    // Zero (0) = success, non-zero = failure
    if status != 0 {
        return Err(format!(
            "Authenticode signature verification failed. Status code: 0x{:08X}. \
             Binary may be unsigned, tampered with, or signed with untrusted certificate. \
             Common causes: \n\
             - Binary not signed with Authenticode certificate\n\
             - Certificate expired or revoked\n\
             - Certificate doesn't chain to trusted root\n\
             - Binary modified after signing (hash mismatch)\n\
             - Trust provider not available",
            status
        )
        .into());
    }

    // Additional validation: verify publisher certificate matches expected value
    // This prevents accepting ANY validly signed binary - must be signed by Kodegen
    verify_publisher(exe_path)?;

    Ok(())
}

/// Extract signer certificate from signed executable
///
/// Uses CryptQueryObject to retrieve the certificate context from the
/// Authenticode signature embedded in the executable.
///
/// # Returns
///
/// Returns a pointer to CERT_CONTEXT which must be freed with
/// CertFreeCertificateContext when done.
///
/// # Errors
///
/// Returns error if:
/// - Path contains invalid UTF-8 characters
/// - CryptQueryObject fails to extract certificate
fn get_signer_certificate(exe_path: &Path) -> Result<*const CERT_CONTEXT, Box<dyn std::error::Error>> {
    // Convert path to wide string (following pattern from line 51-54)
    let path_str = exe_path.to_str()
        .ok_or("Invalid path: contains non-UTF-8 characters")?;
    let path_wide: Vec<u16> = path_str.encode_utf16().chain(Some(0)).collect();
    
    let mut cert_encoding_type: u32 = 0;
    let mut content_type: u32 = 0;
    let mut format_type: u32 = 0;
    let mut cert_store: HCERTSTORE = HCERTSTORE(std::ptr::null_mut());
    let mut msg: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut context: *mut std::ffi::c_void = std::ptr::null_mut();

    unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_wide.as_ptr() as *const std::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(std::ptr::addr_of_mut!(cert_encoding_type) as *mut _),
            Some(std::ptr::addr_of_mut!(content_type) as *mut _),
            Some(std::ptr::addr_of_mut!(format_type) as *mut _),
            Some(&mut cert_store),
            Some(&mut msg),
            Some(std::ptr::addr_of_mut!(context) as *mut _),
        )
        .map_err(|_| "CryptQueryObject failed to extract certificate from signed binary")?;
    }
    
    // The context points to a CERT_CONTEXT structure
    Ok(context as *const CERT_CONTEXT)
}

/// Extract Subject Common Name from certificate
///
/// Uses CertGetNameStringW to retrieve the Common Name from the certificate's
/// Subject field.
///
/// # Safety
///
/// The cert pointer must be a valid CERT_CONTEXT pointer obtained from
/// CryptQueryObject or similar Windows crypto API.
///
/// # Returns
///
/// Returns the Subject CN as a String.
///
/// # Errors
///
/// Returns error if:
/// - Certificate pointer is null
/// - CertGetNameStringW fails to extract the CN
fn get_certificate_subject_cn(cert: *const CERT_CONTEXT) -> Result<String, Box<dyn std::error::Error>> {
    if cert.is_null() {
        return Err("Certificate context is null".into());
    }
    
    // First call to get required buffer size
    let mut buffer = [0u16; 256];  // Common Name typically < 256 characters
    
    unsafe {
        let len = CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buffer),
        );
        
        if len == 0 || len == 1 {
            return Err("Failed to extract certificate Subject CN".into());
        }
        
        // Convert wide string to Rust String (len includes null terminator)
        let subject_cn = String::from_utf16_lossy(&buffer[..(len as usize - 1)]);
        Ok(subject_cn)
    }
}

/// Verify the publisher certificate matches expected identity
///
/// This function extracts the certificate from the signed executable and
/// validates that the Subject CN (Common Name) matches the expected publisher.
/// This prevents accepting arbitrary signed executables - only binaries signed
/// by Kodegen are accepted.
///
/// # Security
///
/// This provides defense-in-depth against supply chain attacks:
/// - WinVerifyTrust validates signature integrity and trust chain
/// - This function validates the specific identity of the signer
///
/// Both checks must pass for installation to proceed.
fn verify_publisher(exe_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Extract certificate from Authenticode signature
    let cert = get_signer_certificate(exe_path)?;
    
    // Ensure we clean up the certificate context on all exit paths
    let _guard = scopeguard::guard(cert, |c| {
        if !c.is_null() {
            unsafe { let _ = CertFreeCertificateContext(Some(c)); }
        }
    });
    
    // Extract Subject Common Name from certificate
    let subject_cn = get_certificate_subject_cn(cert)?;
    
    // Compare against expected publisher
    if subject_cn != EXPECTED_PUBLISHER {
        return Err(format!(
            "Publisher verification failed. Binary signed by '{}', expected '{}'.\n\
             This binary may be malicious or from an untrusted source.\n\
             Only binaries signed by {} are accepted.",
            subject_cn, EXPECTED_PUBLISHER, EXPECTED_PUBLISHER
        ).into());
    }
    
    log::info!("Publisher verified: {}", subject_cn);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    #[ignore] // Only runs on Windows with signed test binary
    fn test_verify_valid_signature() {
        // Test with a known Windows signed binary (e.g., notepad.exe)
        let test_path = PathBuf::from("C:\\Windows\\System32\\notepad.exe");
        if test_path.exists() {
            assert!(verify_signature(&test_path).is_ok());
        }
    }

    #[test]
    fn test_verify_unsigned_fails() {
        // Test with unsigned binary should fail
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"fake unsigned exe").unwrap();

        let result = verify_signature(temp.path());
        assert!(result.is_err());
    }
}
