//! Minimal HTTP test server for browser fixture pages.
//!
//! Uses only `std::net` — no external HTTP framework dependencies.
//! Designed for CI: random port allocation, graceful shutdown, actionable
//! diagnostics on boot failure.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Lightweight HTTP server serving fixture pages from the `pages/` directory.
///
/// Binds to `127.0.0.1:0` for CI-safe random port allocation.
/// Shuts down gracefully on drop.
pub struct FixtureServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    pages_dir: PathBuf,
}

impl FixtureServer {
    /// Start the fixture server on a random available port.
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot bind to any port or if the
    /// fixture pages directory is not found.
    pub fn start() -> Result<Self, FixtureServerError> {
        let pages_dir = find_pages_dir()?;
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| FixtureServerError::Bind(e.to_string()))?;

        let port = listener
            .local_addr()
            .map_err(|e| FixtureServerError::Bind(e.to_string()))?
            .port();

        // Non-blocking accept with short timeout for clean shutdown
        listener
            .set_nonblocking(true)
            .map_err(|e| FixtureServerError::Bind(e.to_string()))?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let pages_dir_clone = pages_dir.clone();

        let handle = thread::Builder::new()
            .name(format!("fixture-server-{port}"))
            .spawn(move || {
                serve_loop(listener, &pages_dir_clone, &shutdown_clone);
            })
            .map_err(|e| FixtureServerError::Bind(e.to_string()))?;

        // Wait briefly for the server to be ready
        thread::sleep(Duration::from_millis(10));

        eprintln!(
            "[FixtureServer] Started on port {port}, serving from {}",
            pages_dir.display()
        );

        Ok(Self {
            port,
            shutdown,
            handle: Some(handle),
            pages_dir,
        })
    }

    /// Server port number.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Build a full URL for the given path.
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    /// Path to the fixture pages directory.
    pub fn pages_dir(&self) -> &Path {
        &self.pages_dir
    }

    /// Check if the server is running and accepting connections.
    pub fn is_healthy(&self) -> bool {
        TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", self.port).parse().unwrap(),
            Duration::from_secs(1),
        )
        .is_ok()
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Poke the listener to unblock accept
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        eprintln!("[FixtureServer] Shut down (port {})", self.port);
    }
}

/// Errors that can occur when starting or running the fixture server.
#[derive(Debug)]
pub enum FixtureServerError {
    /// Failed to bind to a port.
    Bind(String),
    /// Fixture pages directory not found.
    PagesNotFound(String),
}

impl std::fmt::Display for FixtureServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(msg) => write!(f, "fixture server bind failed: {msg}"),
            Self::PagesNotFound(msg) => write!(f, "fixture pages not found: {msg}"),
        }
    }
}

impl std::error::Error for FixtureServerError {}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn find_pages_dir() -> Result<PathBuf, FixtureServerError> {
    // Try paths relative to the project root
    let candidates: Vec<PathBuf> = vec![
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/browser_fixtures/pages"),
        PathBuf::from("tests/browser_fixtures/pages"),
    ];

    for candidate in &candidates {
        if candidate.is_dir() {
            return Ok(candidate.clone());
        }
    }

    Err(FixtureServerError::PagesNotFound(format!(
        "searched: {:?}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
    )))
}

fn serve_loop(listener: TcpListener, pages_dir: &Path, shutdown: &AtomicBool) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        match listener.accept() {
            Ok((stream, _addr)) => {
                let pages = pages_dir.to_path_buf();
                // Handle each connection in-line (sufficient for test workloads)
                handle_connection(stream, &pages);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No pending connection — sleep briefly and retry
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                // Transient error — continue
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream, pages_dir: &Path) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut buf = [0u8; 4096];
    let n = match stream.read(&mut buf) {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let path = parse_request_path(&request);

    let (status, content_type, body) = route_request(path, pages_dir);

    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Access-Control-Allow-Origin: *\r\n\
         \r\n",
        body.len()
    );

    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

fn parse_request_path(request: &str) -> &str {
    // Parse "GET /path HTTP/1.1"
    let mut parts = request.split_whitespace();
    let _method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    // Strip query string
    path.split('?').next().unwrap_or("/")
}

fn route_request(path: &str, pages_dir: &Path) -> (&'static str, &'static str, Vec<u8>) {
    match path {
        // API endpoints for network failure testing
        "/api/ok" => (
            "200 OK",
            "application/json",
            br#"{"status":"ok","message":"success"}"#.to_vec(),
        ),
        "/api/not-found" => (
            "404 Not Found",
            "application/json",
            br#"{"error":"not_found"}"#.to_vec(),
        ),
        "/api/error" => (
            "500 Internal Server Error",
            "application/json",
            br#"{"error":"internal_error","message":"simulated failure"}"#.to_vec(),
        ),
        "/api/slow" => {
            // Simulate slow response (2 seconds)
            thread::sleep(Duration::from_secs(2));
            (
                "200 OK",
                "application/json",
                br#"{"status":"ok","message":"delayed response"}"#.to_vec(),
            )
        }
        "/submit" => (
            "200 OK",
            "application/json",
            br#"{"status":"submitted"}"#.to_vec(),
        ),
        "/sse/updates" => {
            // SSE endpoint for hot-reload testing
            let body = "data: {\"version\":\"v2\",\"content\":\"Updated content\"}\n\n";
            ("200 OK", "text/event-stream", body.as_bytes().to_vec())
        }
        "/" => {
            let body = generate_index_page(pages_dir);
            ("200 OK", "text/html; charset=utf-8", body)
        }
        _ => {
            // Try to serve a static file from pages_dir
            let clean_path = path.trim_start_matches('/');
            // Prevent directory traversal
            if clean_path.contains("..") {
                return ("403 Forbidden", "text/plain", b"Forbidden".to_vec());
            }
            let file_path = pages_dir.join(clean_path);
            match std::fs::read(&file_path) {
                Ok(content) => {
                    let content_type = guess_content_type(clean_path);
                    ("200 OK", content_type, content)
                }
                Err(_) => (
                    "404 Not Found",
                    "text/plain",
                    format!("Not Found: {path}").into_bytes(),
                ),
            }
        }
    }
}

fn guess_content_type(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else {
        "application/octet-stream"
    }
}

fn generate_index_page(pages_dir: &Path) -> Vec<u8> {
    let mut links = String::new();
    if let Ok(entries) = std::fs::read_dir(pages_dir) {
        let mut files: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".html") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        files.sort();
        for file in &files {
            links.push_str(&format!("  <li><a href=\"/{file}\">{file}</a></li>\n"));
        }
    }

    format!(
        "<!DOCTYPE html>\n\
         <html><head><title>Pi Chrome Fixture Index</title></head>\n\
         <body>\n\
         <h1>Pi Chrome Browser Test Fixtures</h1>\n\
         <ul>\n{links}</ul>\n\
         <h2>API Endpoints</h2>\n\
         <ul>\n\
         <li><a href=\"/api/ok\">/api/ok</a> - 200 JSON</li>\n\
         <li><a href=\"/api/not-found\">/api/not-found</a> - 404</li>\n\
         <li><a href=\"/api/error\">/api/error</a> - 500</li>\n\
         <li><a href=\"/api/slow\">/api/slow</a> - 2s delayed</li>\n\
         <li><a href=\"/sse/updates\">/sse/updates</a> - SSE stream</li>\n\
         </ul>\n\
         </body></html>"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_server_starts_and_stops() {
        let server = FixtureServer::start().expect("server should start");
        assert!(server.port() > 0);
        assert!(server.is_healthy());

        let url = server.url("/navigation.html");
        assert!(url.contains(&server.port().to_string()));
        assert!(url.ends_with("/navigation.html"));

        drop(server);
        // Server should be stopped — but port may take time to release
    }

    #[test]
    fn fixture_server_serves_pages() {
        let server = FixtureServer::start().expect("server should start");

        // Fetch the navigation page
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", server.port())).expect("connect");
        stream
            .write_all(b"GET /navigation.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(response.contains("200 OK"), "should return 200");
        assert!(
            response.contains("Navigation Fixture"),
            "should contain page content"
        );
    }

    #[test]
    fn fixture_server_returns_404_for_missing() {
        let server = FixtureServer::start().expect("server should start");

        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", server.port())).expect("connect");
        stream
            .write_all(b"GET /nonexistent.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(response.contains("404"), "should return 404");
    }

    #[test]
    fn fixture_server_api_endpoints() {
        let server = FixtureServer::start().expect("server should start");

        // Test /api/ok
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", server.port())).expect("connect");
        stream
            .write_all(b"GET /api/ok HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(response.contains("200 OK"));
        assert!(response.contains(r#""status":"ok""#));

        // Test /api/not-found
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", server.port())).expect("connect");
        stream
            .write_all(b"GET /api/not-found HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(response.contains("404"));
    }

    #[test]
    fn fixture_server_blocks_directory_traversal() {
        let server = FixtureServer::start().expect("server should start");

        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", server.port())).expect("connect");
        stream
            .write_all(b"GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(response.contains("403"), "should block traversal");
    }

    #[test]
    fn fixture_server_index_lists_pages() {
        let server = FixtureServer::start().expect("server should start");

        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", server.port())).expect("connect");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(response.contains("200 OK"));
        assert!(response.contains("navigation.html"));
        assert!(response.contains("form.html"));
        assert!(response.contains("console_errors.html"));
    }

    #[test]
    fn fixture_server_all_pages_served() {
        let server = FixtureServer::start().expect("server should start");

        for fixture in super::super::Fixture::all() {
            let mut stream =
                TcpStream::connect(format!("127.0.0.1:{}", server.port())).expect("connect");
            let request = format!("GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n", fixture.path());
            stream.write_all(request.as_bytes()).expect("write");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            assert!(
                response.contains("200 OK"),
                "fixture '{}' at {} should return 200, got: {}",
                fixture.name(),
                fixture.path(),
                &response[..response.len().min(100)]
            );
        }
    }

    #[test]
    fn fixture_enum_coverage() {
        let all = super::super::Fixture::all();
        assert_eq!(all.len(), 5, "should have 5 fixtures");

        for fixture in all {
            assert!(!fixture.path().is_empty());
            assert!(!fixture.name().is_empty());
            assert!(fixture.path().starts_with('/'));
            assert!(fixture.path().ends_with(".html"));
        }
    }
}
