//! Security module for Kodegen daemon
//!
//! This module provides comprehensive security functionality including:
//! - Zero-allocation vulnerability scanning
//! - Lock-free security metrics
//! - SIMD-accelerated pattern matching
//! - CI/CD integration for security validation
//! - Config file permission validation

pub mod audit;
pub mod config_permissions;
