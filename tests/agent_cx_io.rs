//! Public scoped-I/O regressions through real loopback sockets and providers.
//! These fixtures never use remote credentials or external network services.

#![recursion_limit = "1024"]

use asupersync::Budget;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use futures::StreamExt;
use futures::channel::oneshot;
use pi::agent_cx::AgentCx;
use pi::http::client::Client;
use pi::model::{Message, StreamEvent, UserContent, UserMessage};
use pi::provider::{Context as ProviderContext, Provider, StreamOptions};
use pi::providers::anthropic::AnthropicProvider;
use pi::providers::vertex::VertexProvider;
use serde_json::json;
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

struct CapturedRequest {
    first_line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn read_request(socket: &mut TcpStream) -> io::Result<CapturedRequest> {
    let mut wire = Vec::new();
    let boundary = loop {
        if let Some(index) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if wire.len() > 64 * 1024 {
            return Err(io::Error::other("fixture request headers exceeded their bound"));
        }
        let mut chunk = [0_u8; 4096];
        let length = socket.read(&mut chunk)?;
        if length == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        wire.extend_from_slice(&chunk[..length]);
    };
    let head = std::str::from_utf8(&wire[..boundary])
        .map_err(|_| io::Error::other("invalid fixture request headers"))?;
    let mut lines = head.lines();
    let first_line = lines.next().unwrap_or_default().to_string();
    let headers: BTreeMap<_, _> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    let length = match headers.get("content-length") {
        Some(length) => length.parse::<usize>()
            .map_err(|_| io::Error::other("invalid fixture content length"))?,
        None => 0,
    };
    if length > 64 * 1024 {
        return Err(io::Error::other("fixture request body exceeded its bound"));
    }
    let mut body = wire[boundary..].to_vec();
    while body.len() < length {
        let mut chunk = [0_u8; 4096];
        let remaining = (length - body.len()).min(chunk.len());
        let count = socket.read(&mut chunk[..remaining])?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        body.extend_from_slice(&chunk[..count]);
    }
    body.truncate(length);
    Ok(CapturedRequest { first_line, headers, body })
}

fn peer_closed(socket: &mut TcpStream) -> io::Result<()> {
    let mut byte = [0_u8; 1];
    match socket.read(&mut byte) {
        Ok(0) => Ok(()),
        Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe) => Ok(()),
        Ok(_) => Err(io::Error::other("unexpected data after fixture request")),
        Err(error) => Err(error),
    }
}

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<CapturedRequest>>>,
}

impl Server {
    fn start(
        handler: impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut socket = loop {
                if stopped.load(Ordering::SeqCst) || Instant::now() >= deadline {
                    return Err(io::Error::other("fixture stopped before accepting a request"));
                }
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
            let request = read_request(&mut socket)?;
            handler(&mut socket)?;
            Ok(request)
        });
        Self { address, stop, worker: Some(worker) }
    }

    fn url(&self) -> String {
        format!("http://{}/fixture", self.address)
    }

    fn finish(mut self) -> CapturedRequest {
        self.worker.take().unwrap().join().expect("fixture thread panicked")
            .expect("fixture request/response failed")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn runtime() -> Runtime {
    RuntimeBuilder::current_thread().build().unwrap()
}

fn owner(runtime: &Runtime) -> AgentCx {
    AgentCx::from_cx(runtime.request_cx_with_budget(Budget::new()))
}

async fn under_owner<F: Future>(owner: &AgentCx, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        let _guard = owner.cx().clone().set_current_restricted();
        future.as_mut().poll(task)
    }).await
}

fn context() -> ProviderContext<'static> {
    ProviderContext::owned(None, vec![Message::User(UserMessage {
        content: UserContent::Text("Respond with a short answer".to_string()),
        timestamp: 0,
    })], Vec::new())
}

#[test]
fn configured_request_preserves_headers_payload_and_exact_response_bytes() {
    let server = Server::start(|socket| {
        socket.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 4\r\nX-Fixture: retained\r\nConnection: close\r\n\r\n")?;
        socket.write_all(&[0, 255, 10, 128])?;
        socket.flush()
    });
    let runtime = runtime();
    let owner = owner(&runtime);
    let raw = Client::new();
    let payload = json!({"message":"kept intact"});
    let request = raw.post(&server.url())
        .header("Authorization", "Bearer fixture-only")
        .header("X-Configured", "retained")
        .no_timeout()
        .json(&payload).unwrap();
    let scoped = owner.http().request(request);
    runtime.block_on(async {
        let response = scoped.send().await.unwrap();
        assert_eq!(response.status(), 201);
        assert!(response.headers().iter().any(|(key, value)| {
            key.eq_ignore_ascii_case("x-fixture") && value == "retained"
        }));
        assert_eq!(response.bytes_limited(4).await.unwrap(), [0, 255, 10, 128]);
    });
    let captured = server.finish();
    assert_eq!(captured.first_line, "POST /fixture HTTP/1.1");
    assert_eq!(captured.headers["authorization"], "Bearer fixture-only");
    assert_eq!(captured.headers["x-configured"], "retained");
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&captured.body).unwrap(), payload);
}

#[test]
fn cloned_client_observes_owner_cancellation_before_any_socket_is_opened() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = runtime();
    let owner = owner(&runtime);
    let client = owner.http().bind(&Client::new()).clone();
    owner.cancel_with(asupersync::types::CancelKind::User, Some("before dispatch"));
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let error = runtime.block_on(client.get(&url).no_timeout().send())
        .err().expect("cancelled request");
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(listener.accept().err().unwrap().kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn owner_cancellation_interrupts_silent_response_headers() {
    let (received, ready) = oneshot::channel();
    let server = Server::start(move |socket| {
        received.send(()).map_err(|_| io::Error::other("missing cancellation observer"))?;
        peer_closed(socket)
    });
    let runtime = runtime();
    let owner = owner(&runtime);
    let client = owner.http().client();
    runtime.block_on(async {
        let cancel = async {
            ready.await.unwrap();
            owner.cancel_with(asupersync::types::CancelKind::User, Some("waiting for headers"));
        };
        let (response, ()) = futures::join!(client.get(&server.url()).no_timeout().send(), cancel);
        let error = response.err().expect("cancelled header wait");
        assert!(error.to_string().contains("cancelled"));
    });
    server.finish();
}

#[test]
fn owner_cancellation_closes_a_silent_body_and_fuses_the_error() {
    let server = Server::start(|socket| {
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx")?;
        socket.flush()?;
        peer_closed(socket)
    });
    let runtime = runtime();
    let owner = owner(&runtime);
    let client = owner.http().client();
    runtime.block_on(async {
        let response = client.get(&server.url()).no_timeout().send().await.unwrap();
        let mut body = response.bytes_stream();
        assert_eq!(body.next().await.unwrap().unwrap(), b"x");
        let consumer = asupersync::Cx::current().unwrap();
        owner.cancel_with(asupersync::types::CancelKind::User, Some("body cancellation"));
        let error = body.next().await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(body.next().await.is_none());
        assert!(body.next().await.is_none());
        assert!(!consumer.is_cancel_requested());
    });
    server.finish();
}

#[test]
fn dropping_a_body_and_exceeding_its_limit_both_release_the_transport() {
    for collect in [false, true] {
        let server = Server::start(|socket| {
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n1234")?;
            socket.flush()?;
            peer_closed(socket)
        });
        let runtime = runtime();
        let owner = owner(&runtime);
        let client = owner.http().client();
        runtime.block_on(async {
            let response = client.get(&server.url()).no_timeout().send().await.unwrap();
            if collect {
                let error = response.bytes_limited(2).await.unwrap_err();
                assert!(error.to_string().contains("too large"));
            } else {
                drop(response.bytes_stream());
            }
        });
        server.finish();
    }
}

#[test]
fn native_anthropic_body_keeps_its_owner_when_consumed_by_another_task_context() {
    let server = Server::start(|socket| {
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")?;
        for event in [
            json!({"type":"message_start","message":{"usage":{"input_tokens":1}}}),
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}),
        ] {
            write!(socket, "data: {event}\n\n")?;
        }
        socket.flush()?;
        peer_closed(socket)
    });
    let runtime = runtime();
    let owner = owner(&runtime);
    let provider = AnthropicProvider::new("claude-test").with_base_url(server.url());
    let options = StreamOptions {
        api_key: Some("sk-ant-api03-fixture-only".to_string()),
        ..StreamOptions::default()
    };
    runtime.block_on(async {
        let context = context();
        let mut stream = under_owner(&owner, provider.stream(&context, &options)).await.unwrap();
        loop {
            match stream.next().await.expect("text before cancellation").unwrap() {
                StreamEvent::TextDelta { delta, .. } => {
                    assert_eq!(delta, "partial");
                    break;
                }
                StreamEvent::Done { .. } | StreamEvent::Error { .. } => panic!("premature terminal"),
                _ => {}
            }
        }
        owner.cancel_with(asupersync::types::CancelKind::User, Some("cancel original owner"));
        let error = stream.next().await.unwrap().unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(stream.next().await.is_none());
    });
    server.finish();
}

#[test]
fn vertex_claude_dispatch_keeps_owner_cancellation_before_headers_arrive() {
    let (received, ready) = oneshot::channel();
    let server = Server::start(move |socket| {
        received.send(()).map_err(|_| io::Error::other("missing cancellation observer"))?;
        peer_closed(socket)
    });
    let runtime = runtime();
    let owner = owner(&runtime);
    let provider = VertexProvider::new("claude-test")
        .with_project("fixture-project")
        .with_publisher("anthropic")
        .with_endpoint_url(server.url());
    let options = StreamOptions {
        api_key: Some("google-fixture-only".to_string()),
        ..StreamOptions::default()
    };
    runtime.block_on(async {
        let context = context();
        let cancel = async {
            ready.await.unwrap();
            owner.cancel_with(asupersync::types::CancelKind::User, Some("cancel Vertex request"));
        };
        let (response, ()) = futures::join!(
            under_owner(&owner, provider.stream(&context, &options)),
            cancel,
        );
        let error = response.err().expect("cancelled provider request");
        assert!(error.to_string().contains("cancelled"));
    });
    let captured = server.finish();
    assert_eq!(captured.headers["authorization"], "Bearer google-fixture-only");
    let body: serde_json::Value = serde_json::from_slice(&captured.body).unwrap();
    assert_eq!(body["anthropic_version"], "vertex-2023-10-16");
    assert!(body.get("model").is_none());
}
