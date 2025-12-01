//! Async task wrapper for channel-based async coordination
//!
//! This module provides async task abstractions using Tokio oneshot channels
//! for zero-allocation coordination. Replaces the previous enum-based design
//! with a more efficient channel-based approach aligned with kodegen-tools-git/github.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

// ============================================================================
// AsyncTask - Single-result async operation
// ============================================================================

/// A handle to an asynchronous task that produces a single result.
///
/// Uses oneshot channel internally for efficient one-time communication.
/// Replaces the previous Pin<Box<dyn Future>> enum-based design.
pub struct AsyncTask<T> {
    rx: oneshot::Receiver<T>,
}

impl<T> AsyncTask<T>
where
    T: Send + 'static,
{
    /// Create from oneshot receiver (for advanced use).
    #[inline]
    #[must_use]
    pub fn new(rx: oneshot::Receiver<T>) -> Self {
        Self { rx }
    }

    /// Spawn a blocking operation on a background thread.
    ///
    /// Maintains API compatibility with existing code while using
    /// channel-based coordination internally.
    #[inline]
    #[allow(dead_code)] // API preserved for future use
    pub fn spawn<F>(f: F) -> Self
    where
        F: FnOnce() -> T + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _ = tx.send(f());
        });
        Self::new(rx)
    }

    /// Spawn an async operation.
    ///
    /// For operations that are already async and don't need `spawn_blocking`.
    #[inline]
    pub fn spawn_async<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn(async move {
            let _ = tx.send(future.await);
        });
        Self::new(rx)
    }

    /// Construct from a future (for backward compatibility with installer.rs).
    ///
    /// This method preserves the existing API: `AsyncTask::from_future(async { ... })`
    /// while using the new channel-based implementation internally.
    #[inline]
    pub fn from_future<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
    {
        Self::spawn_async(future)
    }
}

impl<T> Future for AsyncTask<T> {
    type Output = Result<T, oneshot::error::RecvError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.rx).poll(cx)
    }
}

// ============================================================================
// Combinator Methods for Result<T, E>
// ============================================================================

impl<T, E> AsyncTask<Result<T, E>>
where
    T: Send + 'static,
    E: Send + 'static,
{
    /// Map the success value with fast mapping.
    ///
    /// Maintains compatibility with installer.rs usage: `.map(|ctx| { ... })`
    #[allow(dead_code)] // Used in config/installer.rs - false positive due to cross-module detection
    pub fn map<U, F>(self, f: F) -> AsyncTask<Result<U, E>>
    where
        F: FnOnce(T) -> U + Send + 'static,
        U: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn(async move {
            let result = match self.await {
                Ok(Ok(value)) => Ok(f(value)),
                Ok(Err(err)) => Err(err),
                Err(_recv_err) => {
                    // Channel closed - should never happen in normal operation
                    // Return early without sending (tx will be dropped, rx will get RecvError)
                    return;
                }
            };
            let _ = tx.send(result);
        });
        AsyncTask::new(rx)
    }

    /// Map the error value with fast error mapping.
    ///
    /// Maintains compatibility with installer.rs usage: `.map_err(|e| { ... })`
    #[allow(dead_code)] // Used in config/installer.rs - false positive due to cross-module detection
    pub fn map_err<F, G>(self, f: F) -> AsyncTask<Result<T, G>>
    where
        F: FnOnce(E) -> G + Send + 'static,
        G: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn(async move {
            let result = match self.await {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(err)) => Err(f(err)),
                Err(_recv_err) => return,
            };
            let _ = tx.send(result);
        });
        AsyncTask::new(rx)
    }

    /// Chain another async operation with optimized chaining.
    ///
    /// Maintains compatibility with installer.rs usage: `.and_then(|ctx| async move { ... })`
    #[allow(dead_code)] // Used in config/installer.rs - false positive due to cross-module detection
    pub fn and_then<U, F, Fut>(self, f: F) -> AsyncTask<Result<U, E>>
    where
        F: FnOnce(T) -> Fut + Send + 'static,
        Fut: Future<Output = Result<U, E>> + Send + 'static,
        U: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn(async move {
            let result = match self.await {
                Ok(Ok(value)) => f(value).await,
                Ok(Err(err)) => Err(err),
                Err(_recv_err) => return,
            };
            let _ = tx.send(result);
        });
        AsyncTask::new(rx)
    }

    /// Convert this async task into a Result after completion (for compatibility).
    #[allow(dead_code)]
    pub async fn into_result(self) -> Result<T, E> {
        match self.await {
            Ok(result) => result,
            Err(_) => panic!("AsyncTask channel closed unexpectedly"),
        }
    }
}
