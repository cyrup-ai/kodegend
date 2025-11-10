use anyhow::{Context, Result};
use kodegen_server_http::ServerHandle;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::CategoryServerConfig;

/// Handle to an embedded HTTP server running in background tasks
pub struct EmbeddedServer {
    pub name: String,
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
        
        let addr: SocketAddr = format!("127.0.0.1:{}", config.port)
            .parse()
            .context("Invalid socket address")?;
        
        log::info!("Starting {} server on {}", config.name, addr);
        
        // Start server (non-blocking - returns ServerHandle immediately)
        match start_server(&config.name, addr, tls_cert.clone(), tls_key.clone()).await {
            Ok(server_handle) => {
                log::info!("✓ Started {} server on port {}", config.name, config.port);
                servers.push(EmbeddedServer {
                    name: config.name.clone(),
                    port: config.port,
                    server_handle,
                });
            }
            Err(e) => {
                log::error!("✗ Failed to start {} server: {}", config.name, e);
                
                // Rollback: shutdown all previously started servers
                rollback_servers(servers).await;
                
                return Err(e).context(format!("Failed to start {} server", config.name));
            }
        }
    }
    
    log::info!("All {} servers started successfully", servers.len());
    Ok(servers)
}

/// Route to appropriate tool package's start_server() function
async fn start_server(
    category: &str,
    addr: SocketAddr,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> Result<ServerHandle> {
    log::debug!("Starting embedded {} server on {}", category, addr);
    
    match category {
        "filesystem" => kodegen_tools_filesystem::start_server(addr, tls_cert, tls_key).await,
        "terminal" => kodegen_tools_terminal::start_server(addr, tls_cert, tls_key).await,
        "process" => kodegen_tools_process::start_server(addr, tls_cert, tls_key).await,
        "sequential-thinking" => kodegen_tools_sequential_thinking::start_server(addr, tls_cert, tls_key).await,
        "citescrape" => kodegen_tools_citescrape::start_server(addr, tls_cert, tls_key).await,
        "prompt" => kodegen_tools_prompt::start_server(addr, tls_cert, tls_key).await,
        "introspection" => kodegen_tools_introspection::start_server(addr, tls_cert, tls_key).await,
        "git" => kodegen_tools_git::start_server(addr, tls_cert, tls_key).await,
        "github" => kodegen_tools_github::start_server(addr, tls_cert, tls_key).await,
        "database" => kodegen_tools_database::start_server(addr, tls_cert, tls_key).await,
        "browser" => kodegen_tools_browser::start_server(addr, tls_cert, tls_key).await,
        "config" => kodegen_tools_config::start_server(addr, tls_cert, tls_key).await,
        "reasoner" => kodegen_tools_reasoner::start_server(addr, tls_cert, tls_key).await,
        "claude-agent" => kodegen_claude_agent::start_server(addr, tls_cert, tls_key).await,
        "candle-agent" => kodegen_candle_agent::start_server(addr, tls_cert, tls_key).await,
        _ => Err(anyhow::anyhow!("Unknown server category: {}", category)),
    }
}

/// Rollback: gracefully shutdown all servers that were started
async fn rollback_servers(servers: Vec<EmbeddedServer>) {
    let count = servers.len();
    log::warn!("Rolling back {} previously started servers", count);
    
    let timeout = Duration::from_secs(10);
    
    for server in servers {
        log::info!("Rolling back {} server", server.name);
        if let Err(e) = server.shutdown(timeout).await {
            log::error!("Failed to rollback {}: {}", server.name, e);
        }
    }
    
    log::warn!("Rollback complete");
}

/// Gracefully shutdown all embedded servers
pub async fn shutdown_all_servers(servers: Vec<EmbeddedServer>) -> Result<()> {
    let count = servers.len();
    log::info!("Shutting down {} embedded servers", count);
    
    let timeout = Duration::from_secs(30);
    let mut errors = Vec::new();
    
    for server in servers {
        if let Err(e) = server.shutdown(timeout).await {
            let msg = format!("{} shutdown error: {}", server.name, e);
            log::error!("{}", msg);
            errors.push(msg);
        }
    }
    
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
