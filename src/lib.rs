//! Kodegend library - daemon infrastructure for KODEGEN.ᴀɪ
//!
//! This library provides the daemon service manager, configuration,
//! installation, and platform abstraction layers.

pub mod cli;
pub mod cli_output;
pub mod config;
pub mod constants;
pub mod control;
pub mod daemon;
pub mod install;
pub mod ipc;
pub mod lifecycle;
pub mod logging;
pub mod manager;
pub mod panic_handler;
pub mod platform;
pub mod security;
pub mod service;
pub mod signing;
pub mod state_machine;
pub mod status;
