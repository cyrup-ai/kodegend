//! Multi-source configuration merging with precedence chain
//!
//! Implements industry-standard config layering:
//! 1. Built-in defaults (ServiceConfig::default())
//! 2. System config (/etc/kodegend/kodegend.toml)
//! 3. User config (~/.config/kodegen/kodegend/kodegend.toml)
//! 4. CLI flags (--log-dir, --mcp-bind, etc.)
//!
//! Merge strategy follows Docker Compose precedence:
//! - Scalars: Higher priority replaces lower
//! - Arrays: Higher priority replaces entire array
//! - Objects: Deep merge field-by-field

use std::path::PathBuf;
use std::fs;
use anyhow::{Context, Result};
use serde_json::Value;
use crate::config::ServiceConfig;
use crate::platform;

/// Multi-source configuration loader with precedence chain
pub struct ConfigLoader {
    /// Config file search paths (ordered lowest to highest priority)
    search_paths: Vec<PathBuf>,
}

impl ConfigLoader {
    /// Create loader with standard search paths based on privilege level
    pub fn new() -> Self {
        let mut paths = Vec::new();
        
        // System config (lowest priority file source)
        // Only search system config if running elevated
        if platform::is_elevated() {
            let system_path = platform::system_config_dir().join("kodegend.toml");
            paths.push(system_path);
        }
        
        // User config (higher priority than system)
        let user_path = platform::user_config_dir().join("kodegend.toml");
        paths.push(user_path);
        
        Self { search_paths: paths }
    }
    
    /// Load and merge configs from all sources
    ///
    /// Precedence (lowest to highest):
    /// 1. ServiceConfig::default() (built-in defaults)
    /// 2. System config (if elevated)
    /// 3. User config
    /// 4. CLI overrides (applied by caller after this returns)
    ///
    /// # Returns
    /// Merged ServiceConfig with all found configs applied in precedence order
    pub fn load_merged(&self) -> Result<ServiceConfig> {
        // Start with built-in defaults as JSON
        let default_config = ServiceConfig::default();
        let mut merged = serde_json::to_value(&default_config)
            .context("Failed to serialize default config")?;
        
        // Load and merge each config file in order (lowest to highest priority)
        for path in &self.search_paths {
            if path.exists() {
                log::info!("Loading config layer: {}", path.display());
                
                let content = fs::read_to_string(path)
                    .with_context(|| format!("Failed to read config: {}", path.display()))?;
                
                let toml_value: toml::Value = toml::from_str(&content)
                    .with_context(|| format!("Failed to parse TOML: {}", path.display()))?;
                
                let json_value = toml_to_json(toml_value);
                merged = deep_merge(merged, json_value);
            } else {
                log::debug!("Config file not found (skipping): {}", path.display());
            }
        }
        
        // Convert merged JSON back to ServiceConfig
        let mut config: ServiceConfig = serde_json::from_value(merged)
            .context("Failed to deserialize merged config")?;
        
        // Canonicalize paths relative to user config directory
        // (Paths are already absolute from built-in defaults, but may be relative in overrides)
        let base_dir = platform::user_config_dir();
        config.canonicalize_paths(&base_dir)?;
        
        Ok(config)
    }
    
    /// Load merged config with CLI overrides applied
    ///
    /// # Arguments
    /// * `cli_overrides` - JSON object with CLI flag overrides (e.g., {"log_dir": "/custom/logs"})
    pub fn load_with_overrides(&self, cli_overrides: Value) -> Result<ServiceConfig> {
        let mut merged = serde_json::to_value(&self.load_merged()?)
            .context("Failed to serialize merged config")?;
        
        // Apply CLI overrides (highest priority)
        merged = deep_merge(merged, cli_overrides);
        
        let config: ServiceConfig = serde_json::from_value(merged)
            .context("Failed to deserialize config with overrides")?;
        
        Ok(config)
    }
}

/// Deep merge two JSON values with overlay precedence
///
/// # Strategy
/// - **Objects**: Recursively merge keys (overlay wins on conflict)
/// - **Arrays**: Overlay replaces entire array (no append)
/// - **Scalars**: Overlay replaces base
/// - **Null**: Overlay null replaces base (explicit unset)
///
/// # Example
/// ```rust
/// let base = json!({"log_dir": "/var/log", "services": []});
/// let overlay = json!({"log_dir": "/custom/log"});
/// let merged = deep_merge(base, overlay);
/// // Result: {"log_dir": "/custom/log", "services": []}
/// ```
pub fn deep_merge(base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Object(mut base_map), Value::Object(overlay_map)) => {
            // Deep merge objects field-by-field
            for (key, value) in overlay_map {
                base_map.insert(
                    key.clone(),
                    match base_map.get(&key) {
                        Some(base_value) => deep_merge(base_value.clone(), value),
                        None => value,
                    },
                );
            }
            Value::Object(base_map)
        }
        // For all non-object types: overlay wins (includes arrays, scalars, null)
        (_, overlay) => overlay,
    }
}

/// Convert TOML Value to JSON Value
///
/// Required because serde_json and toml use different Value types.
/// This conversion is lossless for all TOML types supported by ServiceConfig.
///
/// # Implementation Note
/// Uses serde's Value-to-Value conversion via intermediate serialization.
/// This is the standard pattern used by config management crates.
pub fn toml_to_json(toml_value: toml::Value) -> Value {
    // Serialize TOML value to JSON string, then parse as JSON Value
    // This is more reliable than manual type conversion
    match serde_json::to_value(&toml_value) {
        Ok(json) => json,
        Err(e) => {
            log::error!("TOML to JSON conversion failed: {}", e);
            Value::Null
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_deep_merge_scalars() {
        let base = json!({"log_dir": "/var/log"});
        let overlay = json!({"log_dir": "/custom"});
        let result = deep_merge(base, overlay);
        assert_eq!(result["log_dir"], "/custom");
    }
    
    #[test]
    fn test_deep_merge_objects() {
        let base = json!({"a": {"x": 1, "y": 2}});
        let overlay = json!({"a": {"y": 3, "z": 4}});
        let result = deep_merge(base, overlay);
        assert_eq!(result["a"]["x"], 1); // preserved from base
        assert_eq!(result["a"]["y"], 3); // overridden
        assert_eq!(result["a"]["z"], 4); // added
    }
    
    #[test]
    fn test_deep_merge_arrays_replace() {
        let base = json!({"services": ["a", "b"]});
        let overlay = json!({"services": ["c"]});
        let result = deep_merge(base, overlay);
        assert_eq!(result["services"], json!(["c"])); // replaced, not merged
    }
}
