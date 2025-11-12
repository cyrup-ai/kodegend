//! Certificate generation configuration

/// Certificate generation configuration
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    pub common_name: String,
    pub organization: String,
    pub country: String,
    pub validity_days: u32,
    pub key_size: usize,
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
    pub fn new(common_name: String) -> Self {
        Self {
            common_name,
            ..Default::default()
        }
    }

    /// Add SAN entry with zero allocation
    pub fn add_san(mut self, san: String) -> Self {
        self.san_entries.push(san);
        self
    }

    /// Set validity period
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Set organization
    pub fn organization(mut self, org: String) -> Self {
        self.organization = org;
        self
    }

    /// Set country
    pub fn country(mut self, country: String) -> Self {
        self.country = country;
        self
    }

    /// Set key size
    pub fn key_size(mut self, size: usize) -> Self {
        self.key_size = size;
        self
    }
}
