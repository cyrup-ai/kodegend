//! Status query protocol for kodegend daemon
//!
//! Provides Unix socket-based IPC for querying service status from CLI.
//! Uses length-prefixed JSON messages for simplicity and extensibility.

use std::io::{Read, Write};
use std::time::Duration;

use crate::security::audit::{AuditResult, Vulnerability, VulnerabilitySeverity};

// Re-export all wire protocol types from kodegend-protocol-ipc
pub use kodegend_protocol_ipc::*;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
use crate::platform::windows::named_pipe::NamedPipeStream;

/// Wire protocol: length-prefixed JSON
/// Format: [4-byte little-endian length][JSON payload]
///
/// Maximum message size is 1MB to prevent DoS attacks
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

#[cfg(unix)]
pub fn send_message<T: serde::Serialize>(stream: &mut UnixStream, msg: &T) -> anyhow::Result<()> {
    send_message_impl(stream, msg)
}

#[cfg(windows)]
pub fn send_message<T: serde::Serialize>(stream: &mut NamedPipeStream, msg: &T) -> anyhow::Result<()> {
    send_message_impl(stream, msg)
}

/// Internal implementation (platform-agnostic via Read+Write traits)
fn send_message_impl<T: serde::Serialize, S: Write>(stream: &mut S, msg: &T) -> anyhow::Result<()> {
    use anyhow::Context;

    let json = serde_json::to_vec(msg)
        .context("Failed to serialize message")?;

    if json.len() > MAX_MESSAGE_SIZE {
        anyhow::bail!("Message too large: {} bytes (max: {})", json.len(), MAX_MESSAGE_SIZE);
    }

    let len = (json.len() as u32).to_le_bytes();
    stream.write_all(&len)
        .context("Failed to write message length")?;
    stream.write_all(&json)
        .context("Failed to write message payload")?;
    stream.flush()
        .context("Failed to flush stream")?;
    Ok(())
}

#[cfg(unix)]
pub fn recv_message<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> anyhow::Result<T> {
    recv_message_impl(stream)
}

#[cfg(windows)]
pub fn recv_message<T: serde::de::DeserializeOwned>(stream: &mut NamedPipeStream) -> anyhow::Result<T> {
    recv_message_impl(stream)
}

/// Internal implementation (platform-agnostic via Read+Write traits)
fn recv_message_impl<T: serde::de::DeserializeOwned, S: Read>(stream: &mut S) -> anyhow::Result<T> {
    use anyhow::Context;

    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)
        .context("Failed to read message length")?;

    let len = u32::from_le_bytes(len_bytes) as usize;

    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("Message too large: {} bytes (max: {})", len, MAX_MESSAGE_SIZE);
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)
        .context("Failed to read message payload")?;

    serde_json::from_slice(&buf)
        .context("Failed to deserialize message")
}

/// Format a duration for human-readable display
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        let mins = secs / 60;
        let rem_secs = secs % 60;
        if rem_secs == 0 {
            format!("{}m", mins)
        } else {
            format!("{}m{}s", mins, rem_secs)
        }
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h{}m", hours, mins)
        }
    }
}

/// Query and filter vulnerabilities from an audit result
/// 
/// Uses SIMD-accelerated pattern matching via `Vulnerability::matches_pattern()`
/// and exact package matching via `Vulnerability::affects_package()`.
/// 
/// # Arguments
/// 
/// * `result` - The audit result containing vulnerabilities to filter
/// * `filter` - Optional pattern to search in ID, package name, or description
/// * `package` - Optional exact package name match
/// * `critical_only` - If true, only return Critical and High severity vulnerabilities
/// 
/// # Returns
/// 
/// A vector of cloned vulnerabilities matching all specified criteria
pub fn query_vulnerabilities(
    result: &AuditResult,
    filter: Option<&str>,
    package: Option<&str>,
    critical_only: bool,
) -> Vec<Vulnerability> {
    result.vulnerabilities
        .iter()
        .filter(|v| {
            // Filter by severity if requested
            let severity_match = if critical_only {
                matches!(v.severity, VulnerabilitySeverity::Critical | VulnerabilitySeverity::High)
            } else {
                true
            };
            
            // Filter by SIMD-accelerated pattern search if provided
            let pattern_match = if let Some(pattern) = filter {
                v.matches_pattern(pattern.as_bytes())
            } else {
                true
            };
            
            // Filter by exact package name if provided
            let package_match = if let Some(pkg) = package {
                v.affects_package(pkg)
            } else {
                true
            };
            
            severity_match && pattern_match && package_match
        })
        .cloned()
        .collect()
}
