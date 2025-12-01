//! Independent hosts file configuration
//!
//! This module provides functions to check if mcp.kodegen.ai is configured in /etc/hosts.
//! The actual hosts file modification is handled by privilege.rs during elevated installation.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

const HOSTS_ENTRY: &str = "127.0.0.1 mcp.kodegen.ai";

/// Get platform-specific hosts file path
fn get_hosts_file_path() -> &'static Path {
    #[cfg(unix)]
    {
        Path::new("/etc/hosts")
    }

    #[cfg(windows)]
    {
        Path::new(r"C:\Windows\System32\drivers\etc\hosts")
    }
}

/// Check if the hosts file entry exists
pub fn hosts_entry_exists() -> bool {
    let hosts_path = get_hosts_file_path();

    match File::open(hosts_path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            reader
                .lines()
                .map_while(Result::ok)
                .any(|line| line.contains(HOSTS_ENTRY))
        }
        Err(_) => false,
    }
}
