//! Service configuration and management for Kodegen installation
//!
//! This module handles service definition creation, configuration, and platform-specific
//! service setup for the Kodegen daemon.

use anyhow::Result;

use super::super::core::{InstallContext, InstallProgress, ServiceConfig};
use super::super::InstallerBuilder;

/// Configure services for the installer with optimized service configuration
pub fn configure_services(context: &mut InstallContext, _auto_start: bool) -> Result<()> {
    // Configure autoconfig service
    let autoconfig_service = ServiceConfig::new(
        "kodegen-autoconfig".to_string(),
        "internal:autoconfig".to_string(), // Special command handled internally
    )
    .description("Automatic MCP client configuration service".to_string())
    .env("RUST_LOG".to_string(), "info".to_string())
    .auto_restart(true)
    .depends_on("kodegen_daemon".to_string());

    context.add_service(autoconfig_service);

    context.send_progress(InstallProgress::new(
        "services".to_string(),
        0.6,
        "Configured system services".to_string(),
    ));

    Ok(())
}

/// Build installer configuration with platform-specific settings
pub fn build_installer_config(
    context: &InstallContext,
    auto_start: bool,
) -> Result<InstallerBuilder> {
    let mut installer = InstallerBuilder::new("kodegend", context.exe_path.clone())
        .description("kodegen Service Manager")
        .args([
            "run",
            "--foreground",
            "--config",
            &context.config_path.to_string_lossy(),
        ])
        .env("RUST_LOG", "info")
        .auto_restart(true)
        .network(true)
        .auto_start(auto_start);

    // Add configured services
    for service in &context.services {
        installer = installer.service(convert_to_service_definition(service)?);
    }

    // Platform-specific user/group settings
    #[cfg(target_os = "linux")]
    let installer = {
        if let Some(_group) = nix::unistd::Group::from_name("cyops")? {
            installer.group("cyops")
        } else {
            installer
        }
    };

    // On macOS, run as root with wheel group for system daemon privileges
    #[cfg(target_os = "macos")]
    let installer = installer.user("root").group("wheel");

    Ok(installer)
}

/// Convert `ServiceConfig` to service definition with optimized conversion
fn convert_to_service_definition(
    service: &ServiceConfig,
) -> Result<crate::config::ServiceDefinition> {
    let mut env_vars = std::collections::HashMap::new();
    for (key, value) in &service.env_vars {
        env_vars.insert(key.clone(), value.clone());
    }

    // Add default RUST_LOG if not present
    if !env_vars.contains_key("RUST_LOG") {
        env_vars.insert("RUST_LOG".to_string(), "info".to_string());
    }

    // Build command with args concatenated
    let full_command = if service.args.is_empty() {
        service.command.clone()
    } else {
        format!("{} {}", service.command, service.args.join(" "))
    };

    // Create health check configuration based on service type
    let health_check = match service.name.as_str() {
        "kodegen-autoconfig" => Some(crate::config::HealthCheckConfig {
            check_type: "tcp".to_string(),
            target: "127.0.0.1:8443".to_string(),
            interval_secs: 300, // Check every 5 minutes
            timeout_secs: 30,
            retries: 3,
            expected_response: None,
            on_failure: vec![],
        }),
        _ => None,
    };

    Ok(crate::config::ServiceDefinition {
        name: service.name.clone(),
        description: Some(service.description.clone()),
        command: full_command,
        working_dir: service
            .working_dir
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        env_vars,
        auto_restart: service.auto_restart,
        user: service.user.clone(),
        group: service.group.clone(),
        restart_delay_s: Some(10),
        depends_on: service.dependencies.clone(),
        health_check,
        log_rotation: None,
        watch_dirs: Vec::new(),
        ephemeral_dir: None,
        service_type: Some(match service.name.as_str() {
            "kodegen-autoconfig" => "autoconfig".to_string(),
            _ => "service".to_string(),
        }),
        memfs: None,
    })
}
