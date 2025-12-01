//! Status cache for reducing redundant daemon status checks
//!
//! Provides thread-safe caching with TTL and manual invalidation.
//! Used by all platform-specific control implementations.

use crate::daemon::ServiceStatus;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Default cache TTL: 300ms
///
/// This balances freshness (user expects <1s updates) vs performance.
/// Chosen based on human perception thresholds and typical daemon operation latency.
///
/// References:
/// - Jakob Nielsen's 0.1/1.0/10.0 second response time limits
/// - RAIL performance model: 100ms for instant feedback
const DEFAULT_TTL_MS: u64 = 300;

/// Cached status value with timestamp
#[derive(Debug, Clone)]
struct CacheEntry {
    value: ServiceStatus,
    timestamp: Instant,
}

/// Thread-safe status cache with TTL
pub struct StatusCache {
    cache: Mutex<Option<CacheEntry>>,
    ttl: Duration,
}

impl StatusCache {
    /// Create new cache with default TTL
    pub const fn new() -> Self {
        Self {
            cache: Mutex::new(None),
            ttl: Duration::from_millis(DEFAULT_TTL_MS),
        }
    }

    /// Create cache with custom TTL
    pub const fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(None),
            ttl,
        }
    }

    /// Get cached status if still fresh
    ///
    /// Returns:
    /// - `Some(ServiceStatus)`: Cached value is still valid
    /// - `None`: Cache is empty or expired
    pub fn get(&self) -> Option<ServiceStatus> {
        let cache = self.cache.lock().unwrap();
        
        if let Some(entry) = &*cache {
            if entry.timestamp.elapsed() < self.ttl {
                return Some(entry.value.clone());
            }
        }
        
        None
    }

    /// Store new status value in cache
    pub fn set(&self, value: ServiceStatus) {
        let mut cache = self.cache.lock().unwrap();
        *cache = Some(CacheEntry {
            value,
            timestamp: Instant::now(),
        });
    }

    /// Invalidate cache (force next get() to return None)
    ///
    /// Call this when performing state-changing operations:
    /// - start_daemon()
    /// - stop_daemon()
    /// - restart_daemon()
    pub fn invalidate(&self) {
        let mut cache = self.cache.lock().unwrap();
        *cache = None;
    }
}

/// Global cache instance using OnceLock for initialization
///
/// Pattern from Rust std library cookbook:
/// https://doc.rust-lang.org/std/sync/struct.OnceLock.html
///
/// OnceLock provides:
/// - Thread-safe one-time initialization
/// - Lock-free reads after first write
/// - No runtime overhead after initialization
pub fn global_cache() -> &'static StatusCache {
    static CACHE: OnceLock<StatusCache> = OnceLock::new();
    CACHE.get_or_init(|| StatusCache::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_cache_expiration() {
        let cache = StatusCache::with_ttl(Duration::from_millis(50));
        
        // Set initial value
        let status = ServiceStatus::Running { pid: 12345 };
        cache.set(status.clone());
        assert_eq!(cache.get(), Some(status));
        
        // Wait for expiration
        thread::sleep(Duration::from_millis(60));
        assert_eq!(cache.get(), None);
    }

    #[test]
    fn test_cache_invalidation() {
        let cache = StatusCache::new();
        
        let status = ServiceStatus::Stopped;
        cache.set(status.clone());
        assert_eq!(cache.get(), Some(status));
        
        cache.invalidate();
        assert_eq!(cache.get(), None);
    }
}
