use std::borrow::Cow;
use std::sync::Arc;
use std::fmt;

use chrono::{DateTime, Utc};

/// Service state for IPC event reporting
///
/// Represents the runtime state of a managed service or the manager itself.
/// Used in `Evt::State` for type-safe state communication between workers and manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is being started
    Starting,
    /// Service is actively running
    Running,
    /// Service is being stopped
    Stopping,
    /// Service has stopped (generic state)
    Stopped,
    /// Service stopped gracefully via clean shutdown
    StoppedClean,
    /// Service stopped unexpectedly due to crash
    StoppedCrash,
    /// Manager completed a service restart operation
    RestartedService,
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Stopping => write!(f, "stopping"),
            Self::Stopped => write!(f, "stopped"),
            Self::StoppedClean => write!(f, "stopped-clean"),
            Self::StoppedCrash => write!(f, "stopped-crash"),
            Self::RestartedService => write!(f, "restarted-service"),
        }
    }
}

/// Commands sent *to* a worker thread.
#[derive(Debug)]
pub enum Cmd {
    /// Start the service
    /// correlation_id: Used to match Evt::State responses
    Start { correlation_id: u64 },

    /// Stop the service
    /// correlation_id: Used to match Evt::State responses
    Stop { correlation_id: u64 },

    /// Restart the service (stop + start)
    /// correlation_id: Used to match Evt::State responses
    Restart { correlation_id: u64 },

    /// Shutdown worker thread
    /// No correlation_id: This is a fire-and-forget broadcast command
    Shutdown,

    /// Periodic health probe
    /// correlation_id: Used to match Evt::Health responses
    TickHealth { correlation_id: u64 },

    /// Periodic log rotation
    /// correlation_id: Used to match Evt::LogRotate responses
    TickLogRotate { correlation_id: u64 },
}

/// Events emitted *from* workers back to the manager.
#[derive(Debug, Clone)]
pub enum Evt {
    State {
        service: Arc<str>,
        state: ServiceState,
        ts: DateTime<Utc>,
        pid: Option<u32>,
        /// Present if this state change was triggered by a command
        /// None for spontaneous events (crashes, etc.)
        correlation_id: Option<u64>,
    },
    Health {
        service: Arc<str>,
        healthy: bool,
        ts: DateTime<Utc>,
        /// Correlation ID from the TickHealth command that triggered this
        correlation_id: u64,
    },
    LogRotate {
        service: Arc<str>,
        ts: DateTime<Utc>,
        /// Correlation ID from the TickLogRotate command that triggered this
        correlation_id: u64,
    },
    Fatal {
        service: Arc<str>,
        msg: Cow<'static, str>,
        ts: DateTime<Utc>,
        // No correlation_id: Fatal events are always spontaneous
    },
}
