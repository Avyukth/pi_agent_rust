//! Exercise the production HTTP/WebSocket path against a loopback CDP peer.
//! These are protocol fixtures, not claims of live Chromium coverage.
#![forbid(unsafe_code)]

use pi::browser::BrowserTool;
use pi::tools::Tool;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

type Script = Vec<(&'static str, Value)>;

fn headers(stream: &mut TcpStream) -> String {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16384);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}

fn read_frame(stream: &mut TcpStream) -> Value {
    let mut head = [0; 2];
    stream.read_exact(&mut head).unwrap();
    assert_eq!(head[0], 0x81, "client sends one final text frame");
    assert_ne!(head[1] & 0x80, 0, "client frames must be masked");
    let size = match head[1] & 0x7f {
        126 => { let mut size = [0; 2]; stream.read_exact(&mut size).unwrap(); usize::from(u16::from_be_bytes(size)) }
        127 => { let mut size = [0; 8]; stream.read_exact(&mut size).unwrap(); usize::try_from(u64::from_be_bytes(size)).unwrap() }
        size => usize::from(size),
    };
    assert!(size < 1024 * 1024);
    let mut mask = [0; 4];
    stream.read_exact(&mut mask).unwrap();
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).unwrap();
    for (index, byte) in bytes.iter_mut().enumerate() { *byte ^= mask[index % 4]; }
    serde_json::from_slice(&bytes).unwrap()
}

fn write_frame(stream: &mut TcpStream, value: &Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    stream.write_all(&[0x81]).unwrap();
    if bytes.len() < 126 {
        stream.write_all(&[u8::try_from(bytes.len()).unwrap()]).unwrap();
    } else {
        stream.write_all(&[126]).unwrap();
        stream.write_all(&u16::try_from(bytes.len()).unwrap().to_be_bytes()).unwrap();
    }
    stream.write_all(&bytes).unwrap();
}

fn peer(script: Script) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut discovery, _) = listener.accept().unwrap();
        assert!(headers(&mut discovery).starts_with("GET /json/version "));
        let body = json!({"webSocketDebuggerUrl": format!("ws://{addr}/devtools/browser/fixture")}).to_string();
        write!(discovery, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        drop(discovery);
        let (mut socket, _) = listener.accept().unwrap();
        let request = headers(&mut socket);
        assert!(request.starts_with("GET /devtools/browser/fixture "));
        let key = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("sec-websocket-key").then(|| value.trim())
        }).unwrap();
        let accept = asupersync::net::websocket::compute_accept_key(key);
        write!(socket, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").unwrap();
        for (method, response) in script {
            let request = read_frame(&mut socket);
            assert_eq!(request["method"], method);
            if method.starts_with("Runtime.") || method.starts_with("Page.") {
                assert_eq!(request["sessionId"], "session-1");
            }
            // An asynchronous event before the reply must not be mistaken for it.
            write_frame(&mut socket, &json!({"method": "Target.targetInfoChanged", "params": {}}));
            if method == "Runtime.evaluate" {
                assert_eq!(request["params"]["expression"], "({answer: 6 * 7})");
            }
            let mut reply = response;
            reply["id"] = request["id"].clone();
            write_frame(&mut socket, &reply);
        }
    });
    (format!("http://{addr}"), handle)
}

fn attached_script() -> Script {
    vec![
        ("Target.getTargets", json!({"result": {"targetInfos": [
            {"targetId": "page-1", "type": "page", "url": "https://example.com/", "title": "Real peer"}
        ]}})),
        ("Target.attachToTarget", json!({"result": {"sessionId": "session-1"}})),
    ]
}

#[test]
fn native_browser_evaluates_over_http_and_masked_websocket_not_canned_script_matching() {
    let mut script = attached_script();
    script.push(("Runtime.evaluate", json!({"result": {"result": {"type": "object", "value": {"answer": 42}}}})));
    let (endpoint, handle) = peer(script);
    let dir = tempfile::tempdir().unwrap();
    let tool = BrowserTool::new(dir.path()).with_mock(false).with_cdp_endpoint(endpoint);
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
    let result = runtime.block_on(tool.execute("native-eval", json!({
        "action": "evaluate", "tab": "page-1", "script": "({answer: 6 * 7})"
    }), None)).unwrap();
    assert_eq!(result.details.as_ref().unwrap()["result"]["answer"], 42);
    assert_eq!(result.details.as_ref().unwrap()["backend"], "cdp");
    handle.join().unwrap();
}

#[test]
fn native_browser_surfaces_protocol_errors() {
    let mut script = attached_script();
    script.push(("Runtime.evaluate", json!({"error": {"code": -32000, "message": "Execution context destroyed"}})));
    let (endpoint, handle) = peer(script);
    let dir = tempfile::tempdir().unwrap();
    let tool = BrowserTool::new(dir.path()).with_mock(false).with_cdp_endpoint(endpoint);
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
    let error = runtime.block_on(tool.execute("native-error", json!({
        "action": "evaluate", "tab": "page-1", "script": "({answer: 6 * 7})"
    }), None)).unwrap_err();
    assert!(error.to_string().contains("Execution context destroyed"));
    handle.join().unwrap();
}

#[test]
fn native_browser_never_falls_back_to_mock_when_endpoint_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let tool = BrowserTool::new(dir.path()).with_mock(false).with_cdp_endpoint("http://example.com:9222");
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
    let error = runtime.block_on(tool.execute("no-fallback", json!({"action": "screenshot"}), None)).unwrap_err();
    assert!(error.to_string().contains("loopback"));
    assert!(!dir.path().join("screenshots").exists());
}
