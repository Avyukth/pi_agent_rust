//! Hostcall dispatcher for JS extensions.
//!
//! This module introduces the core `ExtensionDispatcher` abstraction used to route
//! hostcall requests (tools, HTTP, session, UI, etc.) from the JS runtime to
//! Rust implementations.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use async_trait::async_trait;

use crate::connectors::http::HttpConnector;
use crate::error::Result;
use crate::extensions::{ExtensionSession, ExtensionUiRequest, ExtensionUiResponse};
use crate::extensions_js::{HostcallKind, HostcallRequest, PiJsRuntime};
use crate::scheduler::{Clock as SchedulerClock, HostcallOutcome, WallClock};
use crate::tools::ToolRegistry;

/// Coordinates hostcall dispatch between the JS extension runtime and Rust handlers.
pub struct ExtensionDispatcher<C: SchedulerClock = WallClock> {
    /// The JavaScript runtime that generates hostcall requests.
    runtime: Rc<PiJsRuntime<C>>,
    /// Registry of available tools (built-in + extension-registered).
    tool_registry: Arc<ToolRegistry>,
    /// HTTP connector for pi.http() calls.
    http_connector: Arc<HttpConnector>,
    /// Session access for pi.session() calls.
    session: Arc<dyn ExtensionSession + Send + Sync>,
    /// UI handler for pi.ui() calls.
    ui_handler: Arc<dyn ExtensionUiHandler + Send + Sync>,
    /// Current working directory for relative path resolution.
    cwd: PathBuf,
}

impl<C: SchedulerClock + 'static> ExtensionDispatcher<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: Rc<PiJsRuntime<C>>,
        tool_registry: Arc<ToolRegistry>,
        http_connector: Arc<HttpConnector>,
        session: Arc<dyn ExtensionSession + Send + Sync>,
        ui_handler: Arc<dyn ExtensionUiHandler + Send + Sync>,
        cwd: PathBuf,
    ) -> Self {
        Self {
            runtime,
            tool_registry,
            http_connector,
            session,
            ui_handler,
            cwd,
        }
    }

    /// Drain pending hostcall requests from the JS runtime.
    #[must_use]
    pub fn drain_hostcall_requests(&self) -> VecDeque<HostcallRequest> {
        self.runtime.drain_hostcall_requests()
    }

    /// Dispatch a hostcall and enqueue its completion into the JS scheduler.
    #[allow(clippy::future_not_send)]
    pub async fn dispatch_and_complete(&self, request: HostcallRequest) {
        let HostcallRequest {
            call_id,
            kind,
            payload,
            ..
        } = request;

        let outcome = match kind {
            HostcallKind::Tool { name } => self.dispatch_tool(&call_id, &name, payload).await,
            HostcallKind::Exec { cmd } => self.dispatch_exec(&call_id, &cmd, payload).await,
            other => HostcallOutcome::Error {
                code: "invalid_request".to_string(),
                message: format!("Unsupported hostcall kind: {other:?}"),
            },
        };

        self.runtime.complete_hostcall(call_id, outcome);
    }

    #[allow(clippy::future_not_send)]
    async fn dispatch_tool(
        &self,
        call_id: &str,
        name: &str,
        payload: serde_json::Value,
    ) -> HostcallOutcome {
        let Some(tool) = self.tool_registry.get(name) else {
            return HostcallOutcome::Error {
                code: "invalid_request".to_string(),
                message: format!("Unknown tool: {name}"),
            };
        };

        match tool.execute(call_id, payload, None).await {
            Ok(output) => match serde_json::to_value(output) {
                Ok(value) => HostcallOutcome::Success(value),
                Err(err) => HostcallOutcome::Error {
                    code: "internal".to_string(),
                    message: format!("Serialize tool output: {err}"),
                },
            },
            Err(err) => HostcallOutcome::Error {
                code: "tool_error".to_string(),
                message: err.to_string(),
            },
        }
    }

    #[allow(clippy::future_not_send, clippy::too_many_lines)]
    async fn dispatch_exec(
        &self,
        call_id: &str,
        cmd: &str,
        payload: serde_json::Value,
    ) -> HostcallOutcome {
        use std::io::Read as _;
        use std::process::{Command, Stdio};

        let args_value = payload
            .get("args")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let args_array = match args_value {
            serde_json::Value::Null => Vec::new(),
            serde_json::Value::Array(items) => items,
            _ => {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "exec args must be an array".to_string(),
                };
            }
        };

        let args = args_array
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), ToString::to_string)
            })
            .collect::<Vec<_>>();

        let options = payload
            .get("options")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let cwd = options
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        let timeout_ms = options
            .get("timeout")
            .and_then(serde_json::Value::as_u64)
            .or_else(|| options.get("timeoutMs").and_then(serde_json::Value::as_u64))
            .or_else(|| {
                options
                    .get("timeout_ms")
                    .and_then(serde_json::Value::as_u64)
            })
            .filter(|ms| *ms > 0);

        let cmd = cmd.to_string();
        let args = args.clone();
        let (tx, rx) = oneshot::channel();
        let call_id_for_error = call_id.to_string();

        thread::spawn(move || {
            let result: std::result::Result<serde_json::Value, String> = (|| {
                let mut command = Command::new(&cmd);
                command
                    .args(&args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());

                if let Some(cwd) = cwd.as_ref() {
                    command.current_dir(cwd);
                }

                let mut child = command.spawn().map_err(|err| err.to_string())?;
                let pid = child.id();

                let mut stdout = child.stdout.take().ok_or("Missing stdout pipe")?;
                let mut stderr = child.stderr.take().ok_or("Missing stderr pipe")?;

                let stdout_handle = thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = stdout.read_to_end(&mut buf);
                    buf
                });
                let stderr_handle = thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = stderr.read_to_end(&mut buf);
                    buf
                });

                let start = Instant::now();
                let mut killed = false;
                let status = loop {
                    if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
                        break status;
                    }

                    if let Some(timeout_ms) = timeout_ms {
                        if start.elapsed() >= Duration::from_millis(timeout_ms) {
                            killed = true;
                            crate::tools::kill_process_tree(Some(pid));
                            let _ = child.kill();
                            break child.wait().map_err(|err| err.to_string())?;
                        }
                    }

                    thread::sleep(Duration::from_millis(10));
                };

                let stdout_bytes = stdout_handle.join().unwrap_or_default();
                let stderr_bytes = stderr_handle.join().unwrap_or_default();

                let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
                let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
                let code = status.code().unwrap_or(0);

                Ok(serde_json::json!({
                    "stdout": stdout,
                    "stderr": stderr,
                    "code": code,
                    "killed": killed,
                }))
            })();

            let cx = Cx::for_request();
            if tx.send(&cx, result).is_err() {
                tracing::trace!(
                    call_id = %call_id_for_error,
                    "Exec hostcall result dropped before completion"
                );
            }
        });

        let cx = Cx::for_request();
        match rx.recv(&cx).await {
            Ok(Ok(value)) => HostcallOutcome::Success(value),
            Ok(Err(err)) => HostcallOutcome::Error {
                code: "io".to_string(),
                message: err,
            },
            Err(_) => HostcallOutcome::Error {
                code: "internal".to_string(),
                message: "exec task cancelled".to_string(),
            },
        }
    }
}

/// Trait for handling individual hostcall types.
#[async_trait]
pub trait HostcallHandler: Send + Sync {
    /// Process a hostcall request and return the outcome.
    async fn handle(&self, params: serde_json::Value) -> HostcallOutcome;

    /// The capability name for policy checking (e.g., "read", "exec", "http").
    fn capability(&self) -> &'static str;
}

/// Trait for handling UI hostcalls (pi.ui()).
#[async_trait]
pub trait ExtensionUiHandler: Send + Sync {
    async fn request_ui(&self, request: ExtensionUiRequest) -> Result<Option<ExtensionUiResponse>>;
}

#[cfg(test)]
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use super::*;

    use crate::scheduler::DeterministicClock;
    use crate::session::SessionMessage;
    use serde_json::Value;
    use std::path::Path;

    struct NullSession;

    #[async_trait]
    impl ExtensionSession for NullSession {
        async fn get_state(&self) -> Value {
            Value::Null
        }

        async fn get_messages(&self) -> Vec<SessionMessage> {
            Vec::new()
        }

        async fn get_entries(&self) -> Vec<Value> {
            Vec::new()
        }

        async fn get_branch(&self) -> Vec<Value> {
            Vec::new()
        }

        async fn set_name(&self, _name: String) -> Result<()> {
            Ok(())
        }

        async fn append_message(&self, _message: SessionMessage) -> Result<()> {
            Ok(())
        }

        async fn append_custom_entry(
            &self,
            _custom_type: String,
            _data: Option<Value>,
        ) -> Result<()> {
            Ok(())
        }
    }

    struct NullUiHandler;

    #[async_trait]
    impl ExtensionUiHandler for NullUiHandler {
        async fn request_ui(
            &self,
            _request: ExtensionUiRequest,
        ) -> Result<Option<ExtensionUiResponse>> {
            Ok(None)
        }
    }

    fn build_dispatcher(
        runtime: Rc<PiJsRuntime<DeterministicClock>>,
    ) -> ExtensionDispatcher<DeterministicClock> {
        ExtensionDispatcher::new(
            runtime,
            Arc::new(ToolRegistry::new(&[], Path::new("."), None)),
            Arc::new(HttpConnector::with_defaults()),
            Arc::new(NullSession),
            Arc::new(NullUiHandler),
            PathBuf::from("."),
        )
    }

    #[test]
    fn dispatcher_constructs() {
        futures::executor::block_on(async {
            let runtime = Rc::new(
                PiJsRuntime::with_clock(DeterministicClock::new(0))
                    .await
                    .expect("runtime"),
            );
            let dispatcher = build_dispatcher(Rc::clone(&runtime));
            assert!(Rc::ptr_eq(&dispatcher.runtime, &runtime));
            assert_eq!(dispatcher.cwd, PathBuf::from("."));
        });
    }

    #[test]
    fn dispatcher_drains_empty_queue() {
        futures::executor::block_on(async {
            let runtime = Rc::new(
                PiJsRuntime::with_clock(DeterministicClock::new(0))
                    .await
                    .expect("runtime"),
            );
            let dispatcher = build_dispatcher(Rc::clone(&runtime));
            let drained = dispatcher.drain_hostcall_requests();
            assert!(drained.is_empty());
        });
    }

    #[test]
    fn dispatcher_drains_runtime_requests() {
        futures::executor::block_on(async {
            let runtime = Rc::new(
                PiJsRuntime::with_clock(DeterministicClock::new(0))
                    .await
                    .expect("runtime"),
            );
            runtime
                .eval(r#"pi.tool("read", { "path": "test.txt" });"#)
                .await
                .expect("eval");

            let dispatcher = build_dispatcher(Rc::clone(&runtime));
            let drained = dispatcher.drain_hostcall_requests();
            assert_eq!(drained.len(), 1);
        });
    }

    #[test]
    fn dispatcher_tool_hostcall_executes_and_resolves_promise() {
        futures::executor::block_on(async {
            let temp_dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(temp_dir.path().join("test.txt"), "hello world").expect("write file");

            let runtime = Rc::new(
                PiJsRuntime::with_clock(DeterministicClock::new(0))
                    .await
                    .expect("runtime"),
            );
            runtime
                .eval(
                    r#"
                    globalThis.result = null;
                    pi.tool("read", { path: "test.txt" }).then((r) => { globalThis.result = r; });
                "#,
                )
                .await
                .expect("eval");

            let requests = runtime.drain_hostcall_requests();
            assert_eq!(requests.len(), 1);

            let dispatcher = ExtensionDispatcher::new(
                Rc::clone(&runtime),
                Arc::new(ToolRegistry::new(&["read"], temp_dir.path(), None)),
                Arc::new(HttpConnector::with_defaults()),
                Arc::new(NullSession),
                Arc::new(NullUiHandler),
                temp_dir.path().to_path_buf(),
            );

            for request in requests {
                dispatcher.dispatch_and_complete(request).await;
            }

            let stats = runtime.tick().await.expect("tick");
            assert!(stats.ran_macrotask);

            runtime
                .eval(
                    r#"
                    if (globalThis.result === null) throw new Error("Promise not resolved");
                    if (!JSON.stringify(globalThis.result).includes("hello world")) {
                        throw new Error("Wrong result: " + JSON.stringify(globalThis.result));
                    }
                "#,
                )
                .await
                .expect("verify result");
        });
    }

    #[test]
    fn dispatcher_tool_hostcall_unknown_tool_rejects_promise() {
        futures::executor::block_on(async {
            let runtime = Rc::new(
                PiJsRuntime::with_clock(DeterministicClock::new(0))
                    .await
                    .expect("runtime"),
            );
            runtime
                .eval(
                    r#"
                    globalThis.err = null;
                    pi.tool("nope", {}).catch((e) => { globalThis.err = e.code; });
                "#,
                )
                .await
                .expect("eval");

            let requests = runtime.drain_hostcall_requests();
            assert_eq!(requests.len(), 1);

            let dispatcher = build_dispatcher(Rc::clone(&runtime));
            for request in requests {
                dispatcher.dispatch_and_complete(request).await;
            }

            runtime.tick().await.expect("tick");

            runtime
                .eval(
                    r#"
                    if (globalThis.err === null) throw new Error("Promise not rejected");
                    if (globalThis.err !== "invalid_request") {
                        throw new Error("Wrong error code: " + globalThis.err);
                    }
                "#,
                )
                .await
                .expect("verify error");
        });
    }

    #[test]
    #[cfg(unix)]
    fn dispatcher_exec_hostcall_executes_and_resolves_promise() {
        futures::executor::block_on(async {
            let runtime = Rc::new(
                PiJsRuntime::with_clock(DeterministicClock::new(0))
                    .await
                    .expect("runtime"),
            );

            runtime
                .eval(
                    r#"
                    globalThis.result = null;
                    pi.exec("sh", ["-c", "printf hello"], {})
                        .then((r) => { globalThis.result = r; });
                "#,
                )
                .await
                .expect("eval");

            let requests = runtime.drain_hostcall_requests();
            assert_eq!(requests.len(), 1);

            let dispatcher = build_dispatcher(Rc::clone(&runtime));
            for request in requests {
                dispatcher.dispatch_and_complete(request).await;
            }

            runtime.tick().await.expect("tick");

            runtime
                .eval(
                    r#"
                    if (globalThis.result === null) throw new Error("Promise not resolved");
                    if (globalThis.result.stdout !== "hello") {
                        throw new Error("Wrong stdout: " + JSON.stringify(globalThis.result));
                    }
                    if (globalThis.result.code !== 0) {
                        throw new Error("Wrong exit code: " + JSON.stringify(globalThis.result));
                    }
                    if (globalThis.result.killed !== false) {
                        throw new Error("Unexpected killed flag: " + JSON.stringify(globalThis.result));
                    }
                "#,
                )
                .await
                .expect("verify result");
        });
    }

    #[test]
    #[cfg(unix)]
    fn dispatcher_exec_hostcall_command_not_found_rejects_promise() {
        futures::executor::block_on(async {
            let runtime = Rc::new(
                PiJsRuntime::with_clock(DeterministicClock::new(0))
                    .await
                    .expect("runtime"),
            );

            runtime
                .eval(
                    r#"
                    globalThis.err = null;
                    pi.exec("definitely_not_a_real_command", [], {})
                        .catch((e) => { globalThis.err = e.code; });
                "#,
                )
                .await
                .expect("eval");

            let requests = runtime.drain_hostcall_requests();
            assert_eq!(requests.len(), 1);

            let dispatcher = build_dispatcher(Rc::clone(&runtime));
            for request in requests {
                dispatcher.dispatch_and_complete(request).await;
            }

            runtime.tick().await.expect("tick");

            runtime
                .eval(
                    r#"
                    if (globalThis.err === null) throw new Error("Promise not rejected");
                    if (globalThis.err !== "io") {
                        throw new Error("Wrong error code: " + globalThis.err);
                    }
                "#,
                )
                .await
                .expect("verify error");
        });
    }
}
