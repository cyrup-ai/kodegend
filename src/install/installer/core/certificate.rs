//! Certificate generation configuration

/// Certificate generation configuration
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    /// Common Name for certificate (used in context.rs:197, 282)
    pub common_name: String,
    /// Organization name (used in context.rs:204, 284)
    pub organization: String,
    /// Country code (used in context.rs:205, 285)
    pub country: String,
    /// Certificate validity in days (used in context.rs:211, 302)
    pub validity_days: u32,
    /// RSA key size in bits (reserved for future use)
    #[allow(dead_code)]
    pub key_size: usize,
    /// Subject Alternative Names (used in context.rs:289-299)
    pub san_entries: Vec<String>,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            common_name: "Kodegen Local CA".to_string(),
            organization: "Kodegen".to_string(),
            country: "US".to_string(),
            validity_days: 365,
            key_size: 2048,
            san_entries: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
        }
    }
}

impl CertificateConfig {
    /// Create new certificate config with optimized defaults
    #[allow(dead_code)]  // Used in config/installer.rs:38 - false positive
    pub fn new(common_name: String) -> Self {
        Self {
            common_name,
            ..Default::default()
        }
    }

    /// Add SAN entry with zero allocation
    #[allow(dead_code)]  // Used in config/installer.rs:43-46 - false positive
    pub fn add_san(mut self, san: String) -> Self {
        self.san_entries.push(san);
        self
    }

    /// Set validity period
    #[allow(dead_code)]  // Used in config/installer.rs:41 - false positive
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Set organization
    #[allow(dead_code)]  // Used in config/installer.rs:39 - false positive
    pub fn organization(mut self, org: String) -> Self {
        self.organization = org;
        self
    }

    /// Set country
    #[allow(dead_code)]  // Used in config/installer.rs:40 - false positive
    pub fn country(mut self, country: String) -> Self {
        self.country = country;
        self
    }

    /// Set key size
    #[allow(dead_code)]  // Used in config/installer.rs:42 - false positive
    pub fn key_size(mut self, size: usize) -> Self {
        self.key_size = size;
        self
    }
}
