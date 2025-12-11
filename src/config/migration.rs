use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use super::ServiceConfig;

// ============================================================================
// MULTI-FORMAT CONFIG SUPPORT
// ============================================================================

/// Supported configuration file formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigFormat {
    Toml,
    Json,
    Yaml,
}

impl ConfigFormat {
    /// Detect format from file extension with content-based fallback
    ///
    /// # Detection Strategy
    /// 1. **Extension-based** (primary): .toml, .json, .yaml, .yml
    /// 2. **Content-based** (fallback): Parse first non-whitespace character
    ///    - `{` or `[` → JSON
    ///    - Otherwise → TOML (most permissive parser)
    ///
    /// # Why TOML as default?
    /// TOML is the most permissive parser and least likely to fail on
    /// ambiguous content. YAML is strict about indentation, JSON requires
    /// braces. TOML can parse simple key=value pairs without structure.
    fn detect(path: &Path, content: &str) -> Result<Self> {
        // Try extension first
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            match ext.to_lowercase().as_str() {
                "toml" => return Ok(ConfigFormat::Toml),
                "json" => return Ok(ConfigFormat::Json),
                "yaml" | "yml" => return Ok(ConfigFormat::Yaml),
                _ => {} // Fall through to content detection
            }
        }

        // Fallback: content-based detection
        let trimmed = content.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            log::info!("Detected JSON format from content (starts with {{ or [)");
            Ok(ConfigFormat::Json)
        } else {
            // Default to TOML (most permissive)
            log::info!("Detected TOML format (default fallback)");
            Ok(ConfigFormat::Toml)
        }
    }

    /// Parse content as format-agnostic value for version detection
    ///
    /// Parses the config into a generic key-value structure to detect the version field
    /// before full deserialization into ServiceConfig.
    fn parse_raw(&self, content: &str, path: &Path) -> Result<serde_json::Value> {
        match self {
            ConfigFormat::Toml => {
                let toml_val: toml::Value = toml::from_str(content)
                    .with_context(|| format!("TOML parse error in {}", path.display()))?;
                // Convert TOML to JSON for uniform handling
                let json_str = serde_json::to_string(&toml_val)
                    .context("Failed to convert TOML to JSON")?;
                serde_json::from_str(&json_str)
                    .context("Failed to parse converted TOML")
            }
            
            ConfigFormat::Json => serde_json::from_str(content)
                .with_context(|| format!("JSON parse error in {}", path.display())),
            
            ConfigFormat::Yaml => {
                let yaml_val: serde_json::Value = serde_yaml_ng::from_str(content)
                    .with_context(|| format!("YAML parse error in {}", path.display()))?;
                Ok(yaml_val)
            }
        }
    }

    /// Parse content using format-specific deserializer
    ///
    /// # Error Handling
    /// All parsers return detailed error messages including:
    /// - Line/column numbers for syntax errors
    /// - Expected vs actual types for schema mismatches
    /// - Field name for missing required fields
    fn parse<T: serde::de::DeserializeOwned>(&self, content: &str, path: &Path) -> Result<T> {
        match self {
            ConfigFormat::Toml => toml::from_str(content)
                .with_context(|| format!("TOML parse error in {}", path.display())),
            
            ConfigFormat::Json => serde_json::from_str(content)
                .with_context(|| format!("JSON parse error in {}", path.display())),
            
            ConfigFormat::Yaml => serde_yaml_ng::from_str(content)
                .with_context(|| format!("YAML parse error in {}", path.display())),
        }
    }
}

/// Config schema version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigVersion {
    /// V1: Original format with restart_delay_s and auto_restart
    V1,
    /// V2: Current format with RestartPolicy struct
    V2,
}

/// Detect config version from raw config value (format-agnostic)
/// 
/// # Detection Logic
/// - Missing `version` field → V1 (backward compatibility)
/// - `version = 1` → V1 (explicit)
/// - `version = 2` → V2 (current)
/// - Other values → Error (future-proofing)
fn detect_version(raw: &serde_json::Value) -> Result<ConfigVersion> {
    match raw.get("version") {
        None => {
            // No version field = legacy v1 config
            log::info!("Config has no version field, treating as v1 (legacy format)");
            Ok(ConfigVersion::V1)
        }
        Some(v) => match v.as_u64() {
            Some(1) => Ok(ConfigVersion::V1),
            Some(2) => Ok(ConfigVersion::V2),
            Some(other) => {
                anyhow::bail!(
                    "Unsupported config version: {}. This daemon supports versions 1-2.",
                    other
                );
            }
            None => {
                anyhow::bail!("Config version field must be an integer, got: {:?}", v);
            }
        },
    }
}

/// Load config with automatic format detection and migration support
/// 
/// # Multi-Format Support
/// Automatically detects and parses TOML, JSON, and YAML formats based on:
/// 1. File extension (.toml, .json, .yaml, .yml)
/// 2. Content analysis (fallback)
/// 
/// # Migration Flow
/// 1. Read raw file content
/// 2. Detect format (extension or content-based)
/// 3. Parse as generic value to detect version
/// 4. If v1 detected:
///    - Backup original file to .v1.bak
///    - Apply v1 → v2 transformations
///    - Write migrated config back to disk
///    - Parse as v2 ServiceConfig
/// 5. If v2 detected:
///    - Parse directly as ServiceConfig
/// 
/// # File Modifications
/// - V1 configs are MODIFIED IN PLACE after backup
/// - V2 configs are NOT modified
pub fn load_with_migration<P: AsRef<Path>>(path: P) -> Result<ServiceConfig> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    // Auto-detect format from extension and content
    let format = ConfigFormat::detect(path, &content)?;
    log::info!("Loading config from {} ({:?} format)", path.display(), format);

    // Parse as format-agnostic value to detect version
    let raw = format.parse_raw(&content, path)?;

    let version = detect_version(&raw)?;

    match version {
        ConfigVersion::V1 => {
            log::warn!(
                "Detected v1 config format at {}. Migrating to v2...",
                path.display()
            );
            migrate_v1_to_v2(path, format, &content)
        }
        ConfigVersion::V2 => {
            // Already v2, parse directly using detected format
            format.parse(&content, path)
        }
    }
}

/// Migrate v1 config to v2
/// 
/// # Multi-Format Support
/// Accepts configs in any format (TOML, JSON, YAML) and migrates to v2.
/// The migrated config is written in the same format as the original.
/// 
/// # V1 → V2 Changes
/// 
/// **Service-level changes** (in each [[services]] entry):
/// - `restart_delay_s` (seconds) → `restart_policy.initial_delay_ms` (milliseconds)
/// - `auto_restart = true` → `restart_policy.max_attempts = 5`
/// - `auto_restart = false` → `restart_policy.max_attempts = 0`
/// 
/// **Top-level changes:**
/// - Add `version = 2`
/// 
/// # Backup Strategy
/// - Original file copied to `{path}.v1.bak` before modification
/// - If backup already exists, it is NOT overwritten (preserves original)
fn migrate_v1_to_v2(path: &Path, format: ConfigFormat, content: &str) -> Result<ServiceConfig> {
    // ════════════════════════════════════════════════════════════════════
    // Step 1: Create Backup
    // ════════════════════════════════════════════════════════════════════
    
    let backup_ext = match format {
        ConfigFormat::Toml => "toml.v1.bak",
        ConfigFormat::Json => "json.v1.bak",
        ConfigFormat::Yaml => "yaml.v1.bak",
    };
    
    let backup_path = if let Some(parent) = path.parent() {
        let file_name = path.file_name()
            .ok_or_else(|| anyhow::anyhow!("Config path has no filename: {}", path.display()))?;
        parent.join(format!("{}.{}", file_name.to_string_lossy(), backup_ext))
    } else {
        path.with_extension(backup_ext)
    };
    
    // Only create backup if it doesn't already exist (preserve original)
    if !backup_path.exists() {
        fs::copy(path, &backup_path).with_context(|| {
            format!(
                "Failed to create v1 backup: {} → {}",
                path.display(),
                backup_path.display()
            )
        })?;
        log::info!("✓ Created v1 config backup: {}", backup_path.display());
    } else {
        log::info!(
            "Backup already exists (preserving original): {}",
            backup_path.display()
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // Step 2: Parse and Apply Transformations
    // ════════════════════════════════════════════════════════════════════

    // Parse into generic JSON value for manipulation
    let mut raw = format.parse_raw(content, path)?;
    
    let obj = raw
        .as_object_mut()
        .context("Config root must be an object")?;

    // Add version = 2
    obj.insert("version".to_string(), serde_json::Value::Number(2.into()));

    // Migrate each service definition
    if let Some(services_value) = obj.get_mut("services") {
        let services_array = services_value
            .as_array_mut()
            .context("services must be an array")?;

        for (idx, service) in services_array.iter_mut().enumerate() {
            let service_obj = service
                .as_object_mut()
                .with_context(|| format!("services[{}] must be an object", idx))?;

            migrate_service_definition_json(service_obj, idx)?;
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // Step 3: Write Migrated Config (in original format)
    // ════════════════════════════════════════════════════════════════════

    let migrated_content = match format {
        ConfigFormat::Toml => {
            // Convert JSON → TOML
            let toml_val: toml::Value = serde_json::from_value(raw.clone())
                .context("Failed to convert migrated config to TOML")?;
            toml::to_string_pretty(&toml_val)
                .context("Failed to serialize migrated config to TOML")?
        }
        ConfigFormat::Json => {
            serde_json::to_string_pretty(&raw)
                .context("Failed to serialize migrated config to JSON")?
        }
        ConfigFormat::Yaml => {
            serde_yaml_ng::to_string(&raw)
                .context("Failed to serialize migrated config to YAML")?
        }
    };

    fs::write(path, &migrated_content).with_context(|| {
        format!(
            "Failed to write migrated config to: {}",
            path.display()
        )
    })?;

    log::info!("✓ Successfully migrated config to v2: {}", path.display());

    // ════════════════════════════════════════════════════════════════════
    // Step 4: Parse as V2 ServiceConfig
    // ════════════════════════════════════════════════════════════════════

    format.parse(&migrated_content, path)
}

/// Migrate a single service definition from v1 to v2 (JSON format)
/// 
/// This is the JSON equivalent of migrate_service_definition(), working with
/// serde_json::Map instead of toml::value::Table.
/// 
/// # Transformations
/// 
/// **Before (v1):**
/// ```json
/// {
///   "name": "my-service",
///   "auto_restart": true,
///   "restart_delay_s": 5
/// }
/// ```
/// 
/// **After (v2):**
/// ```json
/// {
///   "name": "my-service",
///   "restart_policy": {
///     "max_attempts": 5,
///     "initial_delay_ms": 5000,
///     "max_delay_ms": 60000,
///     "backoff_multiplier": 2.0,
///     "success_window_secs": 60
///   }
/// }
/// ```
fn migrate_service_definition_json(
    service: &mut serde_json::Map<String, serde_json::Value>,
    service_idx: usize,
) -> Result<()> {
    let service_name = service
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "<unnamed>".to_string());

    // ════════════════════════════════════════════════════════════════════
    // Extract V1 Fields
    // ════════════════════════════════════════════════════════════════════

    let auto_restart = service
        .get("auto_restart")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let restart_delay_s = service
        .get("restart_delay_s")
        .and_then(|v| v.as_u64())
        .unwrap_or(1); // Default to 1 second if not specified

    // Log deprecation warnings
    if service.contains_key("restart_delay_s") {
        log::warn!(
            "Service '{}' (services[{}]): Field 'restart_delay_s' is deprecated. \
             Migrating to 'restart_policy.initial_delay_ms'.",
            service_name,
            service_idx
        );
    }

    if service.contains_key("auto_restart") {
        log::warn!(
            "Service '{}' (services[{}]): Field 'auto_restart' is deprecated. \
             Migrating to 'restart_policy.max_attempts'.",
            service_name,
            service_idx
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // Build V2 restart_policy
    // ════════════════════════════════════════════════════════════════════

    let max_attempts = if auto_restart { 5 } else { 0 };
    let initial_delay_ms = restart_delay_s * 1000; // Convert seconds to milliseconds

    let mut restart_policy = serde_json::Map::new();
    restart_policy.insert(
        "max_attempts".to_string(),
        serde_json::Value::Number(max_attempts.into()),
    );
    restart_policy.insert(
        "initial_delay_ms".to_string(),
        serde_json::Value::Number(initial_delay_ms.into()),
    );
    restart_policy.insert(
        "max_delay_ms".to_string(),
        serde_json::Value::Number(60_000.into()),
    );
    restart_policy.insert(
        "backoff_multiplier".to_string(),
        serde_json::json!(2.0),
    );
    restart_policy.insert(
        "success_window_secs".to_string(),
        serde_json::Value::Number(60.into()),
    );

    // ════════════════════════════════════════════════════════════════════
    // Update Service Object
    // ════════════════════════════════════════════════════════════════════

    // Remove deprecated fields
    service.remove("auto_restart");
    service.remove("restart_delay_s");

    // Insert new restart_policy
    service.insert(
        "restart_policy".to_string(),
        serde_json::Value::Object(restart_policy),
    );

    log::info!(
        "✓ Migrated service '{}': auto_restart={} + restart_delay_s={}s → restart_policy",
        service_name,
        auto_restart,
        restart_delay_s
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_version_v1_missing_field() {
        let json_str = r#"{
            "services_dir": "/etc/kodegend/services"
        }"#;
        let raw: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(detect_version(&raw).unwrap(), ConfigVersion::V1);
    }

    #[test]
    fn test_detect_version_v1_explicit() {
        let json_str = r#"{
            "version": 1,
            "services_dir": "/etc/kodegend/services"
        }"#;
        let raw: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(detect_version(&raw).unwrap(), ConfigVersion::V1);
    }

    #[test]
    fn test_detect_version_v2() {
        let json_str = r#"{
            "version": 2,
            "services_dir": "/etc/kodegend/services"
        }"#;
        let raw: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(detect_version(&raw).unwrap(), ConfigVersion::V2);
    }

    #[test]
    fn test_detect_version_future_version_fails() {
        let json_str = r#"{
            "version": 99,
            "services_dir": "/etc/kodegend/services"
        }"#;
        let raw: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert!(detect_version(&raw).is_err());
    }
}
