//! kodegend - Cross-platform process supervision and daemon management
//!
//! This crate provides lightweight, production-ready daemon management
//! with crossbeam channels for wait-free message passing.

pub mod cli_output;
pub mod config;
pub mod constants;
pub mod daemon;
pub mod install;
pub mod ipc;
pub mod lifecycle;
pub mod manager;
pub mod platform;
pub mod security;
pub mod service;
pub mod signing;
pub mod state_machine;
pub mod status;

// Re-export main types for convenience
pub use config::{HealthCheckConfig, LogRotationConfig, ServiceConfig, ServiceDefinition};
pub use daemon::daemonise;
pub use ipc::{Cmd, Evt};
pub use manager::ServiceManager;
pub use security::{AuditResult, AuditThresholds, VulnerabilityMetrics, VulnerabilityScanner};
pub use state_machine::{Action, Event, State, Transition};
