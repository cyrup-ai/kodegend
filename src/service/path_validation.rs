use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};
use std::env;
use log::warn;

/// Validates and normalizes a working directory path.
///
/// Performs the following transformations and validations:
/// 1. Expands tilde (~) to home directory
/// 2. Expands environment variables ($VAR, ${VAR})
/// 3. Converts to absolute path
/// 4. Canonicalizes (resolves symlinks, normalizes .. and .)
/// 5. Validates existence
/// 6. Validates it's actually a directory (not a file)
/// 7. Validates read access
///
/// # Arguments
/// * `raw_path` - Raw path string from config (e.g., "~/app", "$HOME/data")
/// * `service_name` - Service name for error messages
///
/// # Returns
/// * `Ok(PathBuf)` - Validated and normalized absolute path
/// * `Err` - Detailed error with context about what failed
///
/// # Example
/// ```rust
/// let validated = validate_and_normalize_working_dir("~/my-app", "my-service")?;
/// // Returns: PathBuf("/home/user/my-app") with all validations passed
/// ```
pub fn validate_and_normalize_working_dir(
    raw_path: &str,
    service_name: &str,
) -> Result<PathBuf> {
    // Step 1: Expand tilde (~) to home directory
    let after_tilde = expand_tilde(raw_path)?;
    
    // Step 2: Expand environment variables ($VAR, ${VAR})
    let after_env = expand_env_vars(&after_tilde)?;
    
    // Step 3: Convert to absolute path (if relative, resolve against cwd)
    let absolute = if Path::new(&after_env).is_absolute() {
        PathBuf::from(&after_env)
    } else {
        // Relative path - resolve against current working directory
        let cwd = env::current_dir()
            .context("Failed to get current working directory")?;
        cwd.join(&after_env)
    };
    
    // Step 4: Validate existence BEFORE canonicalization
    // This gives better error messages for non-existent paths
    if !absolute.exists() {
        return Err(anyhow!(
            "Working directory does not exist for service '{}'\n\
             \n\
             Configured as:  {}\n\
             Expanded to:    {}\n\
             \n\
             Create the directory with: mkdir -p \"{}\"",
            service_name,
            raw_path,
            absolute.display(),
            absolute.display()
        ));
    }
    
    // Step 5: Validate it's actually a directory (not a file)
    if !absolute.is_dir() {
        return Err(anyhow!(
            "Working directory path is not a directory for service '{}'\n\
             \n\
             Configured as:  {}\n\
             Resolved to:    {}\n\
             Type:           {}\n\
             \n\
             The path exists but is a file, not a directory.",
            service_name,
            raw_path,
            absolute.display(),
            if absolute.is_file() { "file" } else { "other" }
        ));
    }
    
    // Step 6: Validate read access by attempting to read directory
    std::fs::read_dir(&absolute)
        .with_context(|| format!(
            "Cannot access working directory for service '{}'\n\
             \n\
             Configured as:  {}\n\
             Resolved to:    {}\n\
             \n\
             Check permissions: ls -ld \"{}\"",
            service_name,
            raw_path,
            absolute.display(),
            absolute.display()
        ))?;
    
    // Step 7: Canonicalize (resolve symlinks, normalize .. and .)
    // This is done AFTER validation to provide better error messages
    let canonical = absolute.canonicalize()
        .with_context(|| format!(
            "Failed to canonicalize working directory for service '{}': {}",
            service_name,
            absolute.display()
        ))?;
    
    Ok(canonical)
}

/// Expands tilde (~) to home directory
///
/// # Patterns supported
/// - `~` → home directory
/// - `~/path` → home directory + path
/// - `~user/path` → NOT SUPPORTED (would require user lookup)
///
/// # Implementation
/// Uses `dirs::home_dir()` which checks:
/// - Unix: $HOME environment variable, then getpwuid_r()
/// - Windows: %USERPROFILE%, then FOLDERID_Profile
///
/// # Reference
/// Pattern from [kodegen-tools-filesystem/src/validation.rs](../../kodegen-tools-filesystem/src/validation.rs#L24-L31)
fn expand_tilde(path: &str) -> Result<String> {
    if path == "~" {
        // Exact match: ~ → home directory
        let home = dirs::home_dir()
            .ok_or_else(|| anyhow!("HOME directory not found"))?;
        Ok(home.to_string_lossy().to_string())
    } else if path.starts_with("~/") {
        // Prefix match: ~/path → home/path
        let home = dirs::home_dir()
            .ok_or_else(|| anyhow!("HOME directory not found"))?;
        Ok(home.join(&path[2..]).to_string_lossy().to_string())
    } else {
        // No tilde - return as-is
        Ok(path.to_string())
    }
}

/// Expands environment variables in path
///
/// # Patterns supported
/// - `$VAR` → value of VAR
/// - `${VAR}` → value of VAR
/// - `$$` → literal `$` (escape sequence)
/// - Mixed: `/home/$USER/app` → `/home/john/app`
///
/// # Implementation
/// Simple string replacement without shell parsing (no quotes, escapes, etc.)
/// This is intentionally basic to avoid security issues with shell injection.
///
/// # Example
/// ```rust
/// env::set_var("USER", "john");
/// env::set_var("HOME", "/home/john");
/// assert_eq!(expand_env_vars("$HOME/$USER/app")?, "/home/john/john/app");
/// assert_eq!(expand_env_vars("${HOME}/data")?, "/home/john/data");
/// assert_eq!(expand_env_vars("$$LITERAL")?, "$LITERAL");
/// ```
fn expand_env_vars(path: &str) -> Result<String> {
    let mut result = String::new();
    let mut chars = path.chars().peekable();
    
    while let Some(ch) = chars.next() {
        if ch == '$' {
            // Check for $$ escape sequence (literal $)
            if chars.peek() == Some(&'$') {
                chars.next(); // Consume second $
                result.push('$');
                continue;
            }
            
            // Check for ${VAR} syntax
            if chars.peek() == Some(&'{') {
                chars.next(); // Consume {
                let var_name: String = chars
                    .by_ref()
                    .take_while(|&c| c != '}')
                    .collect();
                
                if var_name.is_empty() {
                    warn!("Empty variable name in path: ${{}}");
                    result.push_str("${}");
                } else {
                    match env::var(&var_name) {
                        Ok(value) => result.push_str(&value),
                        Err(_) => {
                            // Variable not set - keep as-is and warn
                            warn!("Environment variable not set: {}", var_name);
                            result.push_str(&format!("${{{}}}", var_name));
                        }
                    }
                }
            } else {
                // $VAR syntax (alphanumeric + underscore)
                let var_name: String = chars
                    .by_ref()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                
                if var_name.is_empty() {
                    // Lone $ not followed by variable name
                    result.push('$');
                } else {
                    match env::var(&var_name) {
                        Ok(value) => result.push_str(&value),
                        Err(_) => {
                            // Variable not set - keep as-is and warn
                            warn!("Environment variable not set: {}", var_name);
                            result.push_str(&format!("${}", var_name));
                        }
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    
    Ok(result)
}
