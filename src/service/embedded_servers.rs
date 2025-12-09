use anyhow::{Context, Result};
use kodegen_server_http::ServerHandle;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::config::CategoryServerConfig;

/// Handle to an embedded HTTP server running in background tasks
pub struct EmbeddedServer {
    pub name: String,
    #[allow(dead_code)]
    pub port: u16,
    pub server_handle: ServerHandle,
}

impl EmbeddedServer {
    /// Gracefully shutdown this embedded server
    pub async fn shutdown(self, timeout: Duration) -> Result<()> {
        log::info!("Shutting down {} server", self.name);

        // Trigger graceful shutdown
        self.server_handle.cancel();

        // Wait for completion with timeout
        match self.server_handle.wait_for_completion(timeout).await {
            Ok(()) => {
                log::info!("{} server shutdown successfully", self.name);
                Ok(())
            }
            Err(e) => {
                log::error!("{} server shutdown error: {}", self.name, e);
                Err(anyhow::anyhow!("{} shutdown failed: {}", self.name, e))
            }
        }
    }
}

/// Start all configured category servers as embedded HTTP servers
///
/// Each server runs in background Tokio tasks (spawned by serve_with_tls).
/// Returns Vec<EmbeddedServer> containing ServerHandles for graceful shutdown.
///
/// Fails fast: if any server fails to start, all previously started servers
/// are shutdown gracefully and an error is returned.
#[allow(dead_code)]
pub async fn start_all_servers(
    configs: Vec<CategoryServerConfig>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> Result<Vec<EmbeddedServer>> {
    let mut servers = Vec::new();

    log::info!("Starting {} embedded HTTP servers", configs.len());

    for config in configs {
        if !config.enabled {
            log::info!("Skipping disabled server: {}", config.name);
            continue;
        }

        let start_time = Instant::now();
        log::info!("Preparing {} server on port {}", config.name, config.port);

        // Clean up port and immediately reserve it (eliminates TOCTOU race)
        let listener = match super::port_cleanup::cleanup_and_reserve_port(config.port).await {
            Ok(listener) => {
                let addr = listener
                    .local_addr()
                    .map_err(|e| anyhow::anyhow!("Failed to get listener address: {}", e))?;
                log::info!(
                    "✓ Port {} reserved for {} server ({})",
                    config.port,
                    config.name,
                    addr
                );
                listener
            }
            Err(e) => {
                let elapsed = start_time.elapsed();
                let rollback_count = servers.len();
                
                log::error!(
                    "✗ Failed to reserve port {} for {} server after {:?}: {:#}",
                    config.port,
                    config.name,
                    elapsed,
                    e
                );

                if rollback_count > 0 {
                    log::warn!("Rolling back {} previously started server(s)", rollback_count);
                }
                rollback_servers(servers).await;
                log::info!("Rollback complete ({} server(s) stopped)", rollback_count);

                return Err(e).context(format!(
                    "Failed to reserve port {} for {} server (rolled back {} servers)",
                    config.port, config.name, rollback_count
                ));
            }
        };

        // Start server with pre-bound listener (non-blocking - returns ServerHandle immediately)
        // The listener is consumed by the server, maintaining the port binding
        match start_server_with_listener(&config.name, listener, tls_cert.clone(), tls_key.clone())
            .await
        {
            Ok(server_handle) => {
                let elapsed = start_time.elapsed();
                log::info!(
                    "✓ Started {} server on port {} in {:?}",
                    config.name,
                    config.port,
                    elapsed
                );
                servers.push(EmbeddedServer {
                    name: config.name.clone(),
                    port: config.port,
                    server_handle,
                });
            }
            Err(e) => {
                let elapsed = start_time.elapsed();
                let rollback_count = servers.len();
                
                log::error!(
                    "✗ Failed to start {} server on port {} after {:?}: {:#}",
                    config.name,
                    config.port,
                    elapsed,
                    e
                );

                if rollback_count > 0 {
                    log::warn!("Rolling back {} previously started server(s)", rollback_count);
                }
                rollback_servers(servers).await;
                log::info!("Rollback complete ({} server(s) stopped)", rollback_count);

                return Err(e).context(format!(
                    "Failed to start {} server on port {} (rolled back {} servers)",
                    config.name, config.port, rollback_count
                ));
            }
        }
    }

    log::info!("All {} servers started successfully", servers.len());
    Ok(servers)
}

/// Route to appropriate tool package's start_server() function
pub async fn start_server(
    category: &str,
    addr: SocketAddr,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> Result<ServerHandle> {
    log::debug!("Starting embedded {} server on {}", category, addr);

    match category {
        name if name == kodegen_config::CATEGORY_FILESYSTEM.name => kodegen_tools_filesystem::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_TERMINAL.name => kodegen_tools_terminal::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_PROCESS.name => kodegen_tools_process::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_SEQUENTIAL_THINKING.name => {
            kodegen_tools_sequential_thinking::start_server(addr, tls_cert, tls_key).await
        }
        name if name == kodegen_config::CATEGORY_CITESCRAPE.name => kodegen_tools_citescrape::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_PROMPT.name => kodegen_tools_prompt::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_INTROSPECTION.name => kodegen_tools_introspection::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_GIT.name => kodegen_tools_git::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_GITHUB.name => kodegen_tools_github::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_DATABASE.name => kodegen_tools_database::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_BROWSER.name => kodegen_tools_browser::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_REASONER.name => kodegen_tools_reasoner::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_CLAUDE_AGENT.name => kodegen_claude_agent::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_CANDLE_AGENT.name => kodegen_candle_agent::start_server(addr, tls_cert, tls_key).await,
        name if name == kodegen_config::CATEGORY_CONFIG.name => kodegen_tools_config::start_server(addr, tls_cert, tls_key).await,
        _ => Err(anyhow::anyhow!("Unknown server category: {}", category)),
    }
}

/// Route to appropriate tool package's server startup using pre-bound listener
///
/// This variant accepts a pre-bound TcpListener to eliminate TOCTOU races.
/// The listener is passed through to `create_http_server_with_listener()`.
///
/// # Arguments
/// * `category` - Server category name (e.g., "filesystem", "git")
/// * `listener` - Pre-bound TcpListener (port already reserved)
/// * `tls_cert` - Optional path to TLS certificate
/// * `tls_key` - Optional path to TLS private key
///
/// # Returns
/// ServerHandle for graceful shutdown, or error if startup fails
async fn start_server_with_listener(
    category: &str,
    listener: tokio::net::TcpListener,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> Result<ServerHandle> {
    let addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("Failed to get listener address: {}", e))?;

    log::debug!(
        "Starting {} server on {} with pre-bound listener",
        category,
        addr
    );

    // Build TLS config tuple
    let tls_config = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => Some((cert, key)),
        _ => None,
    };

    // Route to appropriate tool package
    // Each package will need to add a `start_server_with_listener()` function
    // that calls `create_http_server_with_listener()` instead of `create_http_server()`
    match category {
        name if name == kodegen_config::CATEGORY_FILESYSTEM.name => {
            kodegen_tools_filesystem::start_server_with_listener(listener, tls_config).await
        }
        name if name == kodegen_config::CATEGORY_TERMINAL.name => {
            kodegen_tools_terminal::start_server_with_listener(listener, tls_config).await
        }
        name if name == kodegen_config::CATEGORY_PROCESS.name => kodegen_tools_process::start_server_with_listener(listener, tls_config).await,
        name if name == kodegen_config::CATEGORY_SEQUENTIAL_THINKING.name => {
            kodegen_tools_sequential_thinking::start_server_with_listener(listener, tls_config)
                .await
        }
        name if name == kodegen_config::CATEGORY_CITESCRAPE.name => {
            kodegen_tools_citescrape::start_server_with_listener(listener, tls_config).await
        }
        name if name == kodegen_config::CATEGORY_PROMPT.name => kodegen_tools_prompt::start_server_with_listener(listener, tls_config).await,
        name if name == kodegen_config::CATEGORY_INTROSPECTION.name => {
            kodegen_tools_introspection::start_server_with_listener(listener, tls_config).await
        }
        name if name == kodegen_config::CATEGORY_GIT.name => kodegen_tools_git::start_server_with_listener(listener, tls_config).await,
        name if name == kodegen_config::CATEGORY_GITHUB.name => kodegen_tools_github::start_server_with_listener(listener, tls_config).await,
        name if name == kodegen_config::CATEGORY_DATABASE.name => {
            kodegen_tools_database::start_server_with_listener(listener, tls_config).await
        }
        name if name == kodegen_config::CATEGORY_BROWSER.name => kodegen_tools_browser::start_server_with_listener(listener, tls_config).await,
        name if name == kodegen_config::CATEGORY_REASONER.name => {
            kodegen_tools_reasoner::start_server_with_listener(listener, tls_config).await
        }
        name if name == kodegen_config::CATEGORY_CLAUDE_AGENT.name => {
            kodegen_claude_agent::start_server_with_listener(listener, tls_config).await
        }
        name if name == kodegen_config::CATEGORY_CANDLE_AGENT.name => {
            kodegen_candle_agent::start_server_with_listener(listener, tls_config).await
        }
        name if name == kodegen_config::CATEGORY_CONFIG.name => kodegen_tools_config::start_server_with_listener(listener, tls_config).await,
        _ => Err(anyhow::anyhow!("Unknown server category: {}", category)),
    }
}

/// Rollback: gracefully shutdown all servers that were started
#[allow(dead_code)]
async fn rollback_servers(servers: Vec<EmbeddedServer>) {
    let count = servers.len();
    if count == 0 {
        log::debug!("No servers to rollback");
        return;
    }

    let timeout = Duration::from_secs(10);
    let mut success_count = 0;
    let mut failed: Vec<(String, String)> = Vec::new();

    for server in servers {
        let server_name = server.name.clone();
        let server_port = server.port;
        log::info!("Rolling back {} server (port {})", server_name, server_port);

        match server.shutdown(timeout).await {
            Ok(()) => {
                success_count += 1;
                log::info!("✓ Rolled back {} successfully", server_name);
            }
            Err(e) => {
                let err_msg = format!("{:#}", e);
                log::error!("✗ Failed to rollback {} (port {}): {}", server_name, server_port, err_msg);
                failed.push((server_name, err_msg));
            }
        }
    }

    if failed.is_empty() {
        log::info!("Rollback complete: {}/{} servers stopped successfully", success_count, count);
    } else {
        log::error!(
            "Rollback complete with errors: {}/{} successful, {} failed ({})",
            success_count,
            count,
            failed.len(),
            failed.iter()
                .map(|(name, err)| format!("{}: {}", name, err))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
}

/// Gracefully shutdown all embedded servers
pub async fn shutdown_all_servers(servers: Vec<EmbeddedServer>) -> Result<()> {
    use futures::future::join_all;

    let count = servers.len();
    log::info!("Shutting down {} embedded servers", count);

    let timeout = Duration::from_secs(30);

    // Create shutdown futures for all servers with error collection
    // Each future returns Option<String>: Some(error_msg) on failure, None on success
    let shutdown_futures = servers.into_iter().map(|server| {
        let server_name = server.name.clone();
        async move {
            if let Err(e) = server.shutdown(timeout).await {
                let msg = format!("{} shutdown error: {}", server_name, e);
                log::error!("{}", msg);
                Some(msg) // Return error message
            } else {
                None // Success - no error
            }
        }
    });

    // Execute all shutdowns concurrently and collect results
    let results = join_all(shutdown_futures).await;

    // Extract errors using flatten (idiomatic Rust for Option iteration)
    let errors: Vec<String> = results.into_iter().flatten().collect();

    if !errors.is_empty() {
        return Err(anyhow::anyhow!(
            "Shutdown completed with {} errors: {}",
            errors.len(),
            errors.join("; ")
        ));
    }

    log::info!("All {} servers stopped successfully", count);
    Ok(())
}
