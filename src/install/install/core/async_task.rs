//! Async task wrapper for boxing futures with combinator chaining

use std::pin::Pin;

/// Async task wrapper for boxing futures with combinator chaining
pub enum AsyncTask<T> {
    FutureVariant(Pin<Box<dyn std::future::Future<Output = T> + Send + 'static>>),
}

impl<T> AsyncTask<T> {
    /// Construct from a future with optimized boxing
    pub fn from_future<F>(fut: F) -> Self
    where
        F: std::future::Future<Output = T> + Send + 'static,
    {
        AsyncTask::FutureVariant(Box::pin(fut))
    }
}

impl<T> std::future::Future for AsyncTask<T> {
    type Output = T;

    /// Poll the async task with optimized polling
    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Simplified: only FutureVariant exists
        let AsyncTask::FutureVariant(fut) = &mut *self;
        fut.as_mut().poll(cx)
    }
}

impl<T, E> AsyncTask<Result<T, E>> {
    /// Convert this async task into a Result after completion with optimized error handling
    #[allow(dead_code)]
    pub async fn into_result(self) -> Result<T, E> {
        self.await
    }

    /// Map the success value with fast mapping
    pub fn map<U, F>(self, f: F) -> AsyncTask<Result<U, E>>
    where
        F: FnOnce(T) -> U + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
        U: Send + 'static,
    {
        // Simplified: only FutureVariant exists
        let AsyncTask::FutureVariant(fut) = self;
        AsyncTask::from_future(async move {
            match fut.await {
                Ok(value) => Ok(f(value)),
                Err(err) => Err(err),
            }
        })
    }

    /// Map the error value with fast error mapping
    pub fn map_err<F, G>(self, f: F) -> AsyncTask<Result<T, G>>
    where
        F: FnOnce(E) -> G + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
        G: Send + 'static,
    {
        // Simplified: only FutureVariant exists
        let AsyncTask::FutureVariant(fut) = self;
        AsyncTask::from_future(async move {
            match fut.await {
                Ok(value) => Ok(value),
                Err(err) => Err(f(err)),
            }
        })
    }

    /// Chain another async operation with optimized chaining
    pub fn and_then<U, F, Fut>(self, f: F) -> AsyncTask<Result<U, E>>
    where
        F: FnOnce(T) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<U, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
        U: Send + 'static,
    {
        // Simplified: only FutureVariant exists
        let AsyncTask::FutureVariant(fut) = self;
        AsyncTask::from_future(async move {
            match fut.await {
                Ok(value) => f(value).await,
                Err(err) => Err(err),
            }
        })
    }
}
