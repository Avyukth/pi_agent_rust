//! HTTP operations whose owner survives request construction and streaming.
//!
//! Binding does not create new authority. Transport polling, including idle
//! timeout registration and response-body reads, happens under the captured
//! context rather than the task that happens to poll it. Cancellation stops
//! further polling and drops the transport; it cannot undo a request already
//! accepted by the remote server.

use super::AgentCx;
use crate::error::{Error, Result};
use crate::http::client::{Client, RequestBuilder, Response};
use futures::{Future, Stream, StreamExt, TryStreamExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(25);
const DEFAULT_BODY_LIMIT: usize = 50 * 1024 * 1024;
type ByteStream = Pin<Box<dyn Stream<Item = std::io::Result<Vec<u8>>> + Send>>;

fn check_access(owner: &AgentCx) -> std::io::Result<()> {
    if !owner.capabilities().io || !owner.capabilities().time {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "agent HTTP operations require I/O and timer capabilities",
        ));
    }
    owner.checkpoint().map_err(|_| cancelled())
}

fn cancelled() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "agent HTTP operation cancelled; remote side effects may already have occurred",
    )
}

// Foreign transports do not necessarily register a cancellation waker with
// asupersync. This timer wakes a silent operation without busy polling or
// spawning a detached task. Each sleep registers under this exact owner.
async fn cancellation(owner: AgentCx) {
    loop {
        if owner.checkpoint().is_err() {
            return;
        }
        owner.time().sleep(CANCEL_POLL_INTERVAL).await;
    }
}

/// A reusable HTTP client carrying an explicit request owner.
/// Cloning it retains that owner; it never captures the cloning task's context.
#[derive(Clone)]
pub struct AgentHttpClient {
    owner: AgentCx,
    client: Client,
}

impl AgentHttpClient {
    pub(super) fn new(owner: AgentCx, client: Client) -> Self {
        Self { owner, client }
    }

    #[must_use]
    pub fn get(&self, url: &str) -> AgentHttpRequest<'_> {
        self.bind(self.client.get(url))
    }

    #[must_use]
    pub fn post(&self, url: &str) -> AgentHttpRequest<'_> {
        self.bind(self.client.post(url))
    }

    #[must_use]
    pub fn delete(&self, url: &str) -> AgentHttpRequest<'_> {
        self.bind(self.client.delete(url))
    }

    fn bind<'a>(&'a self, request: RequestBuilder<'a>) -> AgentHttpRequest<'a> {
        AgentHttpRequest { owner: &self.owner, request }
    }
}

/// A request builder with no escape hatch that discards its context.
pub struct AgentHttpRequest<'a> {
    owner: &'a AgentCx,
    request: RequestBuilder<'a>,
}

impl AgentHttpRequest<'_> {
    #[must_use]
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.request = self.request.header(key, value);
        self
    }

    pub fn try_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        self.request = self.request.try_header(key, value)?;
        Ok(self)
    }

    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.request = self.request.body(body);
        self
    }

    pub fn json<T: serde::Serialize>(mut self, payload: &T) -> Result<Self> {
        self.request = self.request.json(payload)?;
        Ok(self)
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.request = self.request.timeout(timeout);
        self
    }

    /// Disable the transport timeout, not the owner's cancellation boundary.
    #[must_use]
    pub fn no_timeout(mut self) -> Self {
        self.request = self.request.no_timeout();
        self
    }

    pub async fn send(self) -> Result<AgentHttpResponse> {
        check_access(self.owner)?;
        let owner = self.owner.clone();
        let operation = Box::pin(owner.with_current(self.request.send()));
        let cancellation = Box::pin(cancellation(owner.clone()));
        let response = match futures::future::select(operation, cancellation).await {
            futures::future::Either::Left((response, _)) => response?,
            futures::future::Either::Right(((), _)) => return Err(cancelled().into()),
        };
        // Cancellation may have raced the response headers. Drop the response
        // rather than handing an already-cancelled transport to another task.
        check_access(&owner)?;
        Ok(AgentHttpResponse { owner, response })
    }
}

/// Metadata and a body that retain the same owner as their request.
pub struct AgentHttpResponse {
    owner: AgentCx,
    response: Response,
}

impl AgentHttpResponse {
    #[must_use]
    pub fn status(&self) -> u16 {
        self.response.status()
    }

    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        self.response.headers()
    }

    #[must_use]
    pub fn bytes_stream(self) -> ByteStream {
        Box::pin(OwnedBody::new(self.owner, self.response.bytes_stream()))
    }

    pub async fn bytes_limited(self, limit: usize) -> Result<Vec<u8>> {
        self.bytes_stream()
            .try_fold(Vec::new(), |mut bytes, chunk| async move {
                if chunk.len() > limit.saturating_sub(bytes.len()) {
                    return Err(std::io::Error::other("response body too large"));
                }
                bytes.extend_from_slice(&chunk);
                Ok(bytes)
            })
            .await
            .map_err(Error::from)
    }

    pub async fn text_limited(self, limit: usize) -> Result<String> {
        let bytes = self.bytes_limited(limit).await?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub async fn text(self) -> Result<String> {
        self.text_limited(DEFAULT_BODY_LIMIT).await
    }
}

struct OwnedBody {
    owner: AgentCx,
    stream: Option<ByteStream>,
    cancellation: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl OwnedBody {
    fn new(owner: AgentCx, stream: ByteStream) -> Self {
        let cancellation = Box::pin(cancellation(owner.clone()));
        Self { owner, stream: Some(stream), cancellation }
    }
}

impl Stream for OwnedBody {
    type Item = std::io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.stream.is_none() {
            return Poll::Ready(None);
        }
        let _guard = this.owner.cx().clone().set_current_restricted();
        if let Err(error) = check_access(&this.owner) {
            this.stream.take();
            return Poll::Ready(Some(Err(error)));
        }
        if this.cancellation.as_mut().poll(task).is_ready() {
            this.stream.take();
            return Poll::Ready(Some(Err(cancelled())));
        }
        let result = this.stream.as_mut().expect("active stream").as_mut().poll_next(task);
        if matches!(result, Poll::Ready(None | Some(Err(_)))) {
            // Fusing errors also closes the socket immediately; consumers that
            // poll after a timeout must not receive an infinite error sequence.
            this.stream.take();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::{Budget, Cx};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn denied_owner_cannot_borrow_the_callers_http_authority() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let owner = AgentCx::from_cx(
            runtime.request_cx_with_budget(Budget::new())
                .restrict::<asupersync::cx::cap::None>().set_current_restricted().previous()
        );
        drop(owner);
    }

    #[test]
    fn cancelled_request_is_rejected_before_url_parsing_or_dispatch() {
        let owner = AgentCx::for_request();
        owner.cancel_with(asupersync::types::CancelKind::User, Some("test cancellation"));
        let client = AgentHttpClient::new(owner, Client::new());
        let error = futures::executor::block_on(client.get("not a URL").no_timeout().send())
            .err().expect("cancelled request");
        assert!(error.to_string().contains("cancelled"));
        assert!(!error.to_string().contains("not a URL"));
    }

    struct ObservedStream {
        owner_budget: Budget,
        polled: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
        fail: bool,
    }

    impl Stream for ObservedStream {
        type Item = std::io::Result<Vec<u8>>;
        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert_eq!(Cx::current().expect("owner installed").budget(), self.owner_budget);
            self.polled.store(true, Ordering::SeqCst);
            if self.fail {
                Poll::Ready(Some(Err(std::io::Error::other("transport failed"))))
            } else {
                Poll::Pending
            }
        }
    }

    impl Drop for ObservedStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn body_error_releases_transport_and_is_emitted_only_once() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let budget = Budget::new().with_poll_quota(123);
        let owner = AgentCx::from_cx(runtime.request_cx_with_budget(budget));
        let polled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let mut body = OwnedBody::new(owner, Box::pin(ObservedStream {
            owner_budget: budget, polled: Arc::clone(&polled),
            dropped: Arc::clone(&dropped), fail: true,
        }));
        runtime.block_on(async {
            let caller = Cx::current().unwrap();
            assert!(body.next().await.unwrap().is_err());
            assert!(polled.load(Ordering::SeqCst));
            assert!(dropped.load(Ordering::SeqCst));
            assert!(body.next().await.is_none());
            assert_eq!(Cx::current().unwrap().budget(), caller.budget());
        });
    }

    #[test]
    fn cancellation_wakes_an_idle_body_without_incoming_bytes() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let budget = Budget::new().with_poll_quota(1000);
        let owner = AgentCx::from_cx(runtime.request_cx_with_budget(budget));
        let polled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let mut body = OwnedBody::new(owner.clone(), Box::pin(ObservedStream {
            owner_budget: budget, polled: Arc::clone(&polled),
            dropped: Arc::clone(&dropped), fail: false,
        }));
        runtime.block_on(async {
            let cancel_owner = async {
                owner.time().sleep(Duration::from_millis(1)).await;
                assert!(polled.load(Ordering::SeqCst));
                owner.cancel_with(asupersync::types::CancelKind::User, Some("idle cancellation"));
            };
            let (item, ()) = futures::join!(body.next(), cancel_owner);
            assert_eq!(item.unwrap().unwrap_err().kind(), std::io::ErrorKind::Interrupted);
            assert!(dropped.load(Ordering::SeqCst));
            assert!(body.next().await.is_none());
        });
    }
}
