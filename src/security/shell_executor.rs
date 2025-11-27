use anyhow::Result;
use extism::convert::Json;
use extism::{PluginBuilder, UserData, ValType, host_fn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use std::process::Stdio;
use std::time::Duration;

// ============================================================================
// REQUEST/RESPONSE STRUCTURES
// ============================================================================

/// Request for safe shell execution (recommended)
#[derive(Debug, Deserialize, Serialize)]
pub struct ShellExecuteSafeRequest {
    pub program: String,
    pub args: Vec<String>,
}

/// Request for legacy string-based shell execution (restricted)
#[derive(Debug, Deserialize, Serialize)]
pub struct ShellExecuteRequest {
    pub command: String,
}

/// Unified response for both execution methods
#[derive(Debug, Serialize, Deserialize)]
pub struct ShellExecuteResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub is_error: bool,
}

/// Configuration for shell executor - passed via extism UserData
#[derive(Debug, Clone)]
pub struct ShellExecutorConfig {
    pub allowed_commands: Vec<String>,
    pub allowed_programs: Vec<String>,
    pub max_command_length: usize,
    pub timeout_seconds: u64,
}

impl Default for ShellExecutorConfig {
    fn default() -> Self {
        Self {
            // Empty defaults = block everything (secure by default)
            allowed_commands: Vec::new(),
            allowed_programs: Vec::new(),
            max_command_length: 8192,
            timeout_seconds: 30,
        }
    }
}

// ============================================================================
// SHELL EXECUTOR - SECURE IMPLEMENTATION
// ============================================================================

pub struct ShellExecutor {
    timeout_duration: Duration,
    
    // For execute() - legacy string-based API
    blocked_patterns: Vec<(&'static str, Regex)>,
    allowed_commands: Vec<String>,
    
    // For execute_safe() - parsed argument API
    allowed_programs: Vec<String>,
    
    // Security settings
    max_command_length: usize,
    #[allow(dead_code)]
    allow_environment_vars: bool,
}

impl ShellExecutor {
    /// Create executor with explicit whitelist (recommended)
    #[must_use]
    pub fn new_with_whitelist(
        allowed_commands: Vec<String>,
        allowed_programs: Vec<String>,
    ) -> Self {
        Self {
            timeout_duration: Duration::from_secs(30),
            blocked_patterns: Self::create_security_patterns(),
            allowed_commands,
            allowed_programs,
            max_command_length: 8192,
            allow_environment_vars: false,
        }
    }
    
    /// Create executor that ONLY allows execute_safe() (most secure)
    #[must_use]
    pub fn new_safe_only(allowed_programs: Vec<String>) -> Self {
        Self {
            timeout_duration: Duration::from_secs(30),
            blocked_patterns: Vec::new(),
            allowed_commands: Vec::new(), // Empty = block all string commands
            allowed_programs,
            max_command_length: 8192,
            allow_environment_vars: false,
        }
    }
    
    /// Create from configuration (for extism host functions)
    #[must_use]
    pub fn from_config(config: ShellExecutorConfig) -> Self {
        Self {
            timeout_duration: Duration::from_secs(config.timeout_seconds),
            blocked_patterns: Self::create_security_patterns(),
            allowed_commands: config.allowed_commands,
            allowed_programs: config.allowed_programs,
            max_command_length: config.max_command_length,
            allow_environment_vars: false,
        }
    }

    /// Create comprehensive security patterns for command validation
    /// 
    /// Returns a vector of (pattern_name, compiled_regex) tuples.
    /// Pattern names are used in error messages for debugging.
    fn create_security_patterns() -> Vec<(&'static str, Regex)> {
        let patterns = [
            // ================================================================
            // COMMAND CHAINING (CRITICAL) - Block ALL chaining operators
            // ================================================================
            ("semicolon", r";"),
            ("pipe", r"\|(?!\|)"),           // Single pipe (but not ||)
            ("double_pipe", r"\|\|"),         // OR operator
            ("ampersand_bg", r"&(?!&|>)"),   // Background (but not && or &>)
            ("double_ampersand", r"&&"),      // AND operator
            
            // ================================================================
            // REDIRECTS - Block ALL file redirection
            // ================================================================
            ("redirect_stdout", r">(?!>)"),   // Stdout redirect (but not >>)
            ("redirect_stdin", r"<"),         // Stdin redirect
            ("redirect_append", r">>"),       // Append redirect
            ("redirect_stderr", r"2>"),       // Stderr redirect
            ("redirect_stderr_stdout", r"&>"), // Both streams
            ("redirect_merge", r"2>&1"),      // Merge stderr to stdout
            ("redirect_fd", r"\d+>"),         // File descriptor redirect
            
            // ================================================================
            // COMMAND SUBSTITUTION - Block ALL substitution forms
            // ================================================================
            ("backticks", r"`"),              // Legacy command substitution
            ("cmd_subst_paren", r"\$\("),     // Modern command substitution
            ("var_expansion", r"\$\{"),       // Variable expansion
            ("dollar_var", r"\$[A-Za-z_]"),   // Simple variable reference
            
            // ================================================================
            // DANGEROUS COMMANDS - Block entirely regardless of args
            // ================================================================
            
            // File operations (destructive)
            ("rm_command", r"(?:^|\s)rm(?:\s|$)"),
            ("dd_command", r"(?:^|\s)dd(?:\s|$)"),
            ("shred_command", r"(?:^|\s)shred(?:\s|$)"),
            
            // Filesystem operations
            ("mkfs_command", r"(?:^|\s)mkfs"),
            ("fdisk_command", r"(?:^|\s)fdisk"),
            ("parted_command", r"(?:^|\s)parted"),
            ("mount_command", r"(?:^|\s)mount(?:\s|$)"),
            ("umount_command", r"(?:^|\s)umount(?:\s|$)"),
            
            // Privilege escalation
            ("sudo_command", r"(?:^|\s)sudo(?:\s|$)"),
            ("su_command", r"(?:^|\s)su(?:\s|$)"),
            ("doas_command", r"(?:^|\s)doas(?:\s|$)"),
            
            // Process control
            ("kill_command", r"(?:^|\s)kill(?:\s|$)"),
            ("killall_command", r"(?:^|\s)killall(?:\s|$)"),
            ("pkill_command", r"(?:^|\s)pkill(?:\s|$)"),
            
            // Permission changes
            ("chmod_command", r"(?:^|\s)chmod(?:\s|$)"),
            ("chown_command", r"(?:^|\s)chown(?:\s|$)"),
            ("chgrp_command", r"(?:^|\s)chgrp(?:\s|$)"),
            
            // System modification
            ("reboot_command", r"(?:^|\s)reboot(?:\s|$)"),
            ("shutdown_command", r"(?:^|\s)shutdown(?:\s|$)"),
            ("init_command", r"(?:^|\s)init(?:\s|$)"),
            ("systemctl_command", r"(?:^|\s)systemctl(?:\s|$)"),
            
            // Package management
            ("apt_command", r"(?:^|\s)apt(?:-get|-cache)?(?:\s|$)"),
            ("yum_command", r"(?:^|\s)yum(?:\s|$)"),
            ("dnf_command", r"(?:^|\s)dnf(?:\s|$)"),
            ("pacman_command", r"(?:^|\s)pacman(?:\s|$)"),
            
            // ================================================================
            // PATH TRAVERSAL
            // ================================================================
            ("dot_dot_slash", r"\.\./"),
            ("dot_dot_backslash", r"\.\.\\"),
            
            // ================================================================
            // SPECIAL CHARACTERS & CONTROL CODES
            // ================================================================
            ("newline", r"\n"),
            ("carriage_return", r"\r"),
            ("null_byte", r"\x00"),
            ("tab_char", r"\t"),
            
            // ================================================================
            // SHELL SPECIFIC
            // ================================================================
            ("bash_brace_expansion", r"\{[^}]*,"),  // Brace expansion
            ("globstar", r"\*\*"),                   // Recursive glob
        ];
        
        patterns.iter()
            .filter_map(|(name, pattern)| {
                match Regex::new(pattern) {
                    Ok(re) => Some((*name, re)),
                    Err(e) => {
                        eprintln!("Failed to compile pattern '{}': {}", name, e);
                        None
                    }
                }
            })
            .collect()
    }

    /// Validate command string with defense-in-depth layers
    /// 
    /// This validation is used for the legacy execute() method only.
    /// The execute_safe() method does not need string validation as it
    /// bypasses the shell entirely.
    fn validate_command(&self, cmd: &str) -> Result<(), String> {
        // ====================================================================
        // LAYER 1: Basic sanity checks
        // ====================================================================
        
        if cmd.is_empty() {
            return Err("Empty command".to_string());
        }
        
        if cmd.len() > self.max_command_length {
            return Err(format!(
                "Command exceeds maximum length of {} bytes", 
                self.max_command_length
            ));
        }
        
        // ====================================================================
        // LAYER 2: Control character validation
        // ====================================================================
        
        // Check for dangerous control characters
        // Allow only printable ASCII and space, reject all control chars
        for (idx, c) in cmd.chars().enumerate() {
            if c.is_control() && c != ' ' {
                return Err(format!(
                    "Command contains forbidden control character at position {}: {:?} (U+{:04X})",
                    idx, c, c as u32
                ));
            }
        }
        
        // ====================================================================
        // LAYER 3: Blocked pattern matching (comprehensive)
        // ====================================================================
        
        for (name, pattern) in &self.blocked_patterns {
            if pattern.is_match(cmd) {
                return Err(format!(
                    "Command blocked by security policy: '{}' pattern matched", 
                    name
                ));
            }
        }
        
        // ====================================================================
        // LAYER 4: Whitelist enforcement (MANDATORY)
        // ====================================================================
        
        // Extract base command (first whitespace-delimited token)
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Command contains only whitespace".to_string());
        }
        
        let base_cmd = match parts.first() {
            Some(cmd) => *cmd,
            None => return Err("Command contains only whitespace".to_string()),
        };
        
        // Check against whitelist
        if self.allowed_commands.is_empty() {
            return Err(
                "No commands allowed: whitelist is empty. Use execute_safe() instead.".to_string()
            );
        }
        
        if !self.allowed_commands.contains(&base_cmd.to_string()) {
            return Err(format!(
                "Command '{}' not in whitelist. Allowed commands: {:?}",
                base_cmd, self.allowed_commands
            ));
        }
        
        // ====================================================================
        // LAYER 5: Argument validation
        // ====================================================================
        
        // Validate each argument doesn't contain path traversal
        for arg in &parts[1..] {
            if arg.contains("../") || arg.contains("..\\") {
                return Err(format!(
                    "Argument contains path traversal: '{}'", arg
                ));
            }
        }
        
        Ok(())
    }

    /// Execute command safely WITHOUT shell (RECOMMENDED METHOD)
    /// 
    /// This method executes a program directly with arguments, bypassing
    /// the shell entirely. This makes it inherently immune to command
    /// injection attacks.
    /// 
    /// # Arguments
    /// * `program` - The program to execute (must be in allowed_programs list)
    /// * `args` - Array of arguments to pass to the program
    /// 
    /// # Security
    /// This method is INJECTION-PROOF because:
    /// - No shell interpreter is used
    /// - Arguments are passed directly via execve() on Unix
    /// - No metacharacter interpretation occurs
    /// 
    /// # Example
    /// ```rust
    /// let executor = ShellExecutor::new_safe_only(vec!["ls".to_string()]);
    /// let response = executor.execute_safe("ls", &["-la".to_string()]).await;
    /// ```
    pub async fn execute_safe(
        &self,
        program: &str,
        args: &[String],
    ) -> ShellExecuteResponse {
        // ================================================================
        // VALIDATION: Check program against whitelist
        // ================================================================
        
        if self.allowed_programs.is_empty() {
            return ShellExecuteResponse {
                stdout: String::new(),
                stderr: "No programs allowed: whitelist is empty".to_string(),
                exit_code: Some(1),
                is_error: true,
            };
        }
        
        if !self.allowed_programs.contains(&program.to_string()) {
            return ShellExecuteResponse {
                stdout: String::new(),
                stderr: format!(
                    "Program '{}' not in allowed list. Allowed programs: {:?}",
                    program, self.allowed_programs
                ),
                exit_code: Some(1),
                is_error: true,
            };
        }
        
        // ================================================================
        // EXECUTION: Direct program execution (NO SHELL)
        // ================================================================
        
        let child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()  // Clear environment for additional security
            .spawn();
        
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                return ShellExecuteResponse {
                    stdout: String::new(),
                    stderr: format!("Failed to spawn process: {}", e),
                    exit_code: Some(1),
                    is_error: true,
                };
            }
        };
        
        // ================================================================
        // TIMEOUT: Wait with timeout, kill if exceeded
        // ================================================================
        
        let status = tokio::select! {
            result = child.wait() => {
                match result {
                    Ok(status) => status,
                    Err(e) => {
                        return ShellExecuteResponse {
                            stdout: String::new(),
                            stderr: format!("Process execution failed: {}", e),
                            exit_code: Some(1),
                            is_error: true,
                        };
                    }
                }
            }
            _ = tokio::time::sleep(self.timeout_duration) => {
                let _ = child.kill().await;
                return ShellExecuteResponse {
                    stdout: String::new(),
                    stderr: format!(
                        "Command execution timeout ({}s)", 
                        self.timeout_duration.as_secs()
                    ),
                    exit_code: Some(124),
                    is_error: true,
                };
            }
        };
        
        // ================================================================
        // OUTPUT: Capture stdout and stderr
        // ================================================================
        
        use tokio::io::AsyncReadExt;
        let mut stdout_data = Vec::new();
        let mut stderr_data = Vec::new();
        
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_end(&mut stdout_data).await;
        }
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_end(&mut stderr_data).await;
        }
        
        ShellExecuteResponse {
            stdout: String::from_utf8_lossy(&stdout_data).to_string(),
            stderr: String::from_utf8_lossy(&stderr_data).to_string(),
            exit_code: status.code(),
            is_error: !status.success(),
        }
    }

    /// Execute command string via shell (LEGACY METHOD - USE WITH CAUTION)
    /// 
    /// This method executes a command string via `sh -c`, which is inherently
    /// risky. It applies multiple layers of validation but cannot be made
    /// completely secure. Use execute_safe() instead whenever possible.
    /// 
    /// # Security Notice
    /// This method uses `sh -c` and is vulnerable to:
    /// - Shell metacharacter exploitation (despite filtering)
    /// - Novel bypass techniques
    /// - Zero-day shell interpreter bugs
    /// 
    /// Only use this method if:
    /// - You need shell features (pipes, globs, etc.)
    /// - You have a tightly controlled whitelist
    /// - You understand the residual risk
    pub async fn execute(&self, command: &str) -> ShellExecuteResponse {
        // ================================================================
        // VALIDATION: Multi-layer security checks
        // ================================================================
        
        if let Err(e) = self.validate_command(command) {
            return ShellExecuteResponse {
                stdout: String::new(),
                stderr: format!("Command validation failed: {}", e),
                exit_code: Some(1),
                is_error: true,
            };
        }
        
        // ================================================================
        // EXECUTION: Via shell (sh -c)
        // ================================================================
        
        let child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()  // Clear environment to prevent $VAR expansion
            .spawn();
        
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                return ShellExecuteResponse {
                    stdout: String::new(),
                    stderr: format!("Failed to spawn process: {}", e),
                    exit_code: Some(1),
                    is_error: true,
                };
            }
        };
        
        // ================================================================
        // TIMEOUT: Same timeout logic as execute_safe()
        // ================================================================
        
        let status = tokio::select! {
            result = child.wait() => {
                match result {
                    Ok(status) => status,
                    Err(e) => {
                        return ShellExecuteResponse {
                            stdout: String::new(),
                            stderr: format!("Process execution failed: {}", e),
                            exit_code: Some(1),
                            is_error: true,
                        };
                    }
                }
            }
            _ = tokio::time::sleep(self.timeout_duration) => {
                let _ = child.kill().await;
                return ShellExecuteResponse {
                    stdout: String::new(),
                    stderr: format!(
                        "Command execution timeout ({}s)", 
                        self.timeout_duration.as_secs()
                    ),
                    exit_code: Some(124),
                    is_error: true,
                };
            }
        };
        
        // ================================================================
        // OUTPUT: Capture stdout and stderr
        // ================================================================
        
        use tokio::io::AsyncReadExt;
        let mut stdout_data = Vec::new();
        let mut stderr_data = Vec::new();
        
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_end(&mut stdout_data).await;
        }
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_end(&mut stderr_data).await;
        }
        
        ShellExecuteResponse {
            stdout: String::from_utf8_lossy(&stdout_data).to_string(),
            stderr: String::from_utf8_lossy(&stderr_data).to_string(),
            exit_code: status.code(),
            is_error: !status.success(),
        }
    }
}

// ============================================================================
// EXTISM HOST FUNCTIONS
// ============================================================================

// Host function for SAFE execution (RECOMMENDED)
// This host function provides the secure execute_safe() method to plugins.
// It accepts a program name and argument array, executes without shell.
host_fn!(
    shell_execute_safe(
        _config: ShellExecutorConfig; 
        request: Json<ShellExecuteSafeRequest>
    ) -> Json<ShellExecuteResponse> {
        // TEMPORARY: Use default empty configuration for safety
        // TODO: Find correct way to access UserData<ShellExecutorConfig>
        let executor = ShellExecutor::new_safe_only(Vec::new());
        
        let response = tokio::runtime::Handle::current().block_on(
            executor.execute_safe(&request.0.program, &request.0.args)
        );
        
        Ok(Json(response))
    }
);

// Host function for LEGACY string execution (RESTRICTED)
// This host function provides the legacy execute() method to plugins.
// It accepts a command string and applies heavy validation before executing
// via shell. Use shell_execute_safe() instead whenever possible.
host_fn!(
    shell_execute(
        _config: ShellExecutorConfig; 
        request: Json<ShellExecuteRequest>
    ) -> Json<ShellExecuteResponse> {
        // TEMPORARY: Use default empty configuration for safety
        // TODO: Find correct way to access UserData<ShellExecutorConfig>
        let executor = ShellExecutor::new_with_whitelist(Vec::new(), Vec::new());
        
        let response = tokio::runtime::Handle::current().block_on(
            executor.execute(&request.0.command)
        );
        
        Ok(Json(response))
    }
);

/// Register both host functions with PluginBuilder
/// 
/// # Arguments
/// * `builder` - The extism PluginBuilder
/// * `config` - Security configuration (whitelists, timeouts, etc.)
/// 
/// # Returns
/// Updated PluginBuilder with both host functions registered
/// 
/// # Example
/// ```rust
/// let config = ShellExecutorConfig {
///     allowed_commands: vec!["echo".to_string()],
///     allowed_programs: vec!["ls".to_string(), "cat".to_string()],
///     max_command_length: 8192,
///     timeout_seconds: 30,
/// };
/// 
/// let builder = PluginBuilder::new_with_module(wasm_module);
/// let builder = register_shell_host_functions(builder, config);
/// ```
pub fn register_shell_host_functions(
    builder: PluginBuilder,
    config: ShellExecutorConfig,
) -> PluginBuilder {
    builder
        // Register SAFE method (recommended)
        .with_function(
            "shell_execute_safe",
            [ValType::I64],
            [ValType::I64],
            UserData::new(config.clone()),
            shell_execute_safe,
        )
        // Register LEGACY method (restricted)
        .with_function(
            "shell_execute",
            [ValType::I64],
            [ValType::I64],
            UserData::new(config),
            shell_execute,
        )
}
