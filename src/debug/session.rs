//! DAP session state, launch sequencing and retained breakpoint configuration.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::{Either, select};
use serde_json::{Value, json};

use super::breakpoints::{self, Change, Group, Store};
use super::dap::{DapError, DapEvent, DapTransport};
use super::tool_err;
use crate::agent_cx::AgentCx;
use crate::error::Result;

pub const DEFAULT_DAP_TIMEOUT: Duration = Duration::from_secs(30);
const INITIALIZED_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ExecState {
    Running,
    Stopped { thread_id: u64, reason: String },
    Exited,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Launch,
    Attach,
}

struct State {
    execution: ExecState,
    initialized: bool,
    revision: u64,
    capabilities: Value,
    origin: Option<Origin>,
}

impl State {
    fn event(&mut self, event: DapEvent) {
        match event.event.as_str() {
            "initialized" => self.initialized = true,
            "stopped" if self.execution != ExecState::Exited => {
                self.execution = ExecState::Stopped {
                    thread_id: event.body["threadId"].as_u64().unwrap_or(0),
                    reason: event.body["reason"].as_str().unwrap_or("unknown").to_string(),
                };
                self.revision = self.revision.wrapping_add(1);
            }
            "continued" if self.execution != ExecState::Exited => {
                self.execution = ExecState::Running;
                self.revision = self.revision.wrapping_add(1);
            }
            "terminated" | "exited" => {
                self.execution = ExecState::Exited;
                self.revision = self.revision.wrapping_add(1);
            }
            "capabilities" => {
                if let (Some(current), Some(update)) = (
                    self.capabilities.as_object_mut(), event.body["capabilities"].as_object(),
                ) {
                    current.extend(update.clone());
                }
            }
            _ => {}
        }
    }
}

/// Field order matters: stop the owned adapter before removing build outputs.
pub struct DapSession {
    transport: DapTransport,
    state: Mutex<State>,
    pub(super) breakpoints: Arc<asupersync::sync::Mutex<Store>>,
    _launch_artifacts: Option<tempfile::TempDir>,
}

impl DapSession {
    pub async fn begin(transport: DapTransport) -> Result<Self> {
        let capabilities = transport.request("initialize", json!({
            "clientID": "pi_agent_rust", "clientName": "pi_agent_rust", "adapterID": "pi-dap",
            "linesStartAt1": true, "columnsStartAt1": true, "pathFormat": "path",
            "supportsVariableType": true, "supportsVariablePaging": true,
            "supportsRunInTerminalRequest": false, "supportsStartDebuggingRequest": false
        }), DEFAULT_DAP_TIMEOUT).await?;
        if !capabilities.is_object() {
            return Err(tool_err("DAP_PROTOCOL", "initialize did not return adapter capabilities"));
        }
        Ok(Self {
            transport,
            state: Mutex::new(State {
                execution: ExecState::Running, initialized: false, revision: 0,
                capabilities, origin: None,
            }),
            breakpoints: Arc::new(asupersync::sync::Mutex::new(Store::default())),
            _launch_artifacts: None,
        })
    }

    pub(super) fn with_launch_artifacts(mut self, directory: Option<tempfile::TempDir>) -> Self {
        self._launch_artifacts = directory;
        self
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn capabilities(&self) -> Value {
        self.pump_events();
        Self::lock(&self.state).capabilities.clone()
    }

    pub(super) fn require_capability(&self, name: &str) -> Result<()> {
        if self.capabilities()[name] == true {
            Ok(())
        } else {
            Err(tool_err("DAP_UNSUPPORTED", format!("adapter does not advertise {name}")))
        }
    }

    #[must_use]
    pub fn state(&self) -> ExecState {
        self.pump_events();
        Self::lock(&self.state).execution.clone()
    }

    #[must_use]
    pub fn output_tail(&self) -> String {
        self.pump_events();
        self.transport.stderr_tail()
    }

    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.transport.is_alive() && self.state() != ExecState::Exited
    }

    pub(super) fn is_connected(&self) -> bool {
        self.transport.is_alive()
    }

    pub fn pump_events(&self) {
        let mut state = Self::lock(&self.state);
        for event in self.transport.drain_events() { state.event(event); }
        if !self.transport.is_alive() { state.execution = ExecState::Exited; }
    }

    /// One startup budget covers compilation, initialization and all initial
    /// breakpoint configuration, not a fresh timeout for each handshake step.
    pub(super) async fn start(
        &self, command: &str, arguments: Value,
        initial: &BTreeMap<String, Vec<Value>>, exception_filters: Option<&[String]>,
        timeout: Duration,
    ) -> Result<()> {
        let origin = match command {
            "launch" => Origin::Launch,
            "attach" => Origin::Attach,
            _ => return Err(tool_err("DAP_USAGE", "startup must be launch or attach")),
        };
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(tool_err("DAP_USAGE", "startup timeout must be in 1..=300000 ms"));
        }
        Self::lock(&self.state).origin = Some(origin);
        let configure = async {
            self.wait_initialized_for(timeout).await?;
            for (path, entries) in initial {
                for entry in entries { breakpoints::check_options(self, entry)?; }
                breakpoints::apply(self, Group::Source(path.clone()), Change::Replace(entries.clone())).await?;
            }
            if let Some(filters) = exception_filters {
                let caps = self.capabilities();
                for filter in filters {
                    if !caps["exceptionBreakpointFilters"].as_array().is_some_and(|supported| {
                        supported.iter().any(|entry| entry["filter"].as_str() == Some(filter.as_str()))
                    }) {
                        return Err(tool_err("DAP_UNSUPPORTED", format!("unsupported exception filter: {filter}")));
                    }
                }
                self.call("setExceptionBreakpoints", json!({"filters": filters})).await?;
            }
            if self.capabilities()["supportsConfigurationDoneRequest"] == true {
                self.call("configurationDone", json!({})).await?;
            }
            Ok::<(), crate::error::Error>(())
        };
        let operation = async {
            let launch = async {
                self.transport.request(command, arguments, timeout).await
                    .map_err(crate::error::Error::from)
            };
            futures::future::try_join(launch, configure).await?;
            self.pump_events();
            Ok(())
        };
        let owner = AgentCx::for_current_or_request();
        let deadline = async { owner.time().sleep(timeout).await; };
        match select(Box::pin(operation), Box::pin(deadline)).await {
            Either::Left((result, _)) => result,
            Either::Right(((), pending)) => {
                drop(pending);
                Err(tool_err("DAP_STARTUP_TIMEOUT", "debug launch/attach configuration exceeded its startup budget"))
            }
        }
    }

    pub async fn wait_initialized(&self) -> Result<()> {
        self.wait_initialized_for(INITIALIZED_WAIT).await
    }

    async fn wait_initialized_for(&self, wait: Duration) -> Result<()> {
        let owner = AgentCx::for_current_or_request();
        let start = owner.cx().timer_driver()
            .map_or_else(asupersync::time::wall_now, |timer| timer.now());
        loop {
            owner.checkpoint().map_err(|_| tool_err("DAP_CANCELLED", "debug configuration cancelled"))?;
            self.pump_events();
            {
                let state = Self::lock(&self.state);
                if state.initialized { return Ok(()); }
                if state.execution == ExecState::Exited {
                    return Err(tool_err("DAP_TRANSPORT", "adapter ended before initialization"));
                }
            }
            let now = owner.cx().timer_driver()
                .map_or_else(asupersync::time::wall_now, |timer| timer.now());
            if Duration::from_nanos(now.duration_since(start)) >= wait {
                return Err(tool_err("DAP_INITIALIZE_TIMEOUT", "adapter did not emit initialized"));
            }
            owner.time().sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn wait_stopped(&self, wait: Duration) -> Option<(u64, String)> {
        let owner = AgentCx::for_current_or_request();
        let start = owner.cx().timer_driver()
            .map_or_else(asupersync::time::wall_now, |timer| timer.now());
        loop {
            if owner.checkpoint().is_err() { return None; }
            match self.state() {
                ExecState::Stopped { thread_id, reason } => return Some((thread_id, reason)),
                ExecState::Exited => return None,
                ExecState::Running => {}
            }
            let now = owner.cx().timer_driver()
                .map_or_else(asupersync::time::wall_now, |timer| timer.now());
            if Duration::from_nanos(now.duration_since(start)) >= wait { return None; }
            owner.time().sleep(Duration::from_millis(10)).await;
        }
    }

    pub(super) fn require_stopped(&self) -> Result<u64> {
        match self.state() {
            ExecState::Stopped { thread_id, .. } => Ok(thread_id),
            ExecState::Running => Err(tool_err("DAP_STATE_RUNNING", "debuggee is running; pause or wait for a breakpoint first")),
            ExecState::Exited => Err(tool_err("DAP_STATE_EXITED", "debuggee has exited; start a new session")),
        }
    }

    pub async fn call(&self, command: &str, arguments: Value) -> Result<Value> {
        self.pump_events();
        let previous = if matches!(command, "continue" | "next" | "stepIn" | "stepOut" | "stepBack" | "reverseContinue" | "restartFrame") {
            self.require_stopped()?;
            let mut state = Self::lock(&self.state);
            let previous = state.execution.clone();
            state.execution = ExecState::Running;
            Some((previous, state.revision))
        } else { None };
        let result = self.transport.request(command, arguments, DEFAULT_DAP_TIMEOUT).await;
        self.pump_events();
        if matches!(&result, Err(DapError::Adapter { .. }))
            && let Some((previous, revision)) = previous
        {
            let mut state = Self::lock(&self.state);
            if state.revision == revision && state.execution != ExecState::Exited {
                state.execution = previous;
            }
        }
        result.map_err(crate::error::Error::from)
    }

    pub async fn call_stopped(&self, command: &str, arguments: Value) -> Result<Value> {
        self.require_stopped()?;
        self.call(command, arguments).await
    }

    /// Checked end-of-session operation used by the agent-facing tool. A
    /// rejection is not permission to force-kill an attached user's process.
    pub(super) async fn disconnect(&self, terminate_debuggee: bool) -> Result<()> {
        let capabilities = self.capabilities();
        let origin = Self::lock(&self.state).origin;
        let arguments = disconnect_arguments(origin, &capabilities, terminate_debuggee)?;
        self.transport.request("disconnect", arguments, DEFAULT_DAP_TIMEOUT).await?;
        self.transport.kill();
        Self::lock(&self.state).execution = ExecState::Exited;
        Ok(())
    }

    /// Low-level best-effort teardown for SDK callers and fixture cleanup.
    /// The tool uses the checked disconnect path above and surfaces rejection.
    pub async fn terminate(&self) {
        let _ = self.call("terminate", json!({})).await;
        self.transport.kill();
        Self::lock(&self.state).execution = ExecState::Exited;
    }
}

fn disconnect_arguments(origin: Option<Origin>, caps: &Value, terminate: bool) -> Result<Value> {
    let origin = origin.ok_or_else(|| tool_err("DAP_NO_SESSION", "debug session did not complete a start request"))?;
    if !terminate && origin == Origin::Launch {
        return Err(tool_err("DAP_USAGE", "disconnect preserves attached targets only; use terminate for a Pi-launched program"));
    }
    if terminate && origin == Origin::Attach && caps["supportTerminateDebuggee"] != true {
        return Err(tool_err("DAP_UNSUPPORTED", "adapter cannot guarantee the requested termination of an attached target; disconnect to leave it running"));
    }
    let mut args = json!({"restart":false});
    if caps["supportTerminateDebuggee"] == true {
        args["terminateDebuggee"] = json!(terminate);
    }
    // Without the optional capability, DAP's implicit rule terminates launch
    // targets and preserves attach targets. Never rely on an ignored override.
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State { execution: ExecState::Running, initialized: false, revision: 0, capabilities: json!({}), origin: None }
    }

    #[test]
    fn state_labels() {
        let stopped = ExecState::Stopped { thread_id: 7, reason: "breakpoint".to_string() };
        let rendered = serde_json::to_string(&stopped).expect("serialize");
        assert!(rendered.contains("\"state\":\"stopped\""));
        assert!(rendered.contains("\"thread_id\":7"));
    }

    #[test]
    fn initialized_and_stopped_in_the_same_batch_are_both_retained() {
        let mut state = state();
        state.event(DapEvent { event: "initialized".into(), body: json!({}) });
        state.event(DapEvent { event: "stopped".into(), body: json!({"threadId":7,"reason":"entry"}) });
        assert!(state.initialized);
        assert!(matches!(state.execution, ExecState::Stopped { thread_id:7, .. }));
        state.event(DapEvent { event: "continued".into(), body: json!({}) });
        assert!(state.initialized);
        assert_eq!(state.execution, ExecState::Running);
    }

    #[test]
    fn terminal_state_is_not_resurrected_and_capabilities_merge() {
        let mut state = state();
        state.event(DapEvent { event: "capabilities".into(), body: json!({"capabilities":{"supportsLogPoints":true}}) });
        assert_eq!(state.capabilities["supportsLogPoints"], true);
        state.event(DapEvent { event: "exited".into(), body: json!({}) });
        state.event(DapEvent { event: "stopped".into(), body: json!({"threadId":3}) });
        assert_eq!(state.execution, ExecState::Exited);
    }

    #[test]
    fn disconnect_respects_target_origin_and_optional_capabilities() {
        assert_eq!(disconnect_arguments(Some(Origin::Launch), &json!({}), true).unwrap(), json!({"restart":false}));
        assert_eq!(disconnect_arguments(Some(Origin::Attach), &json!({}), false).unwrap(), json!({"restart":false}));
        assert!(disconnect_arguments(Some(Origin::Attach), &json!({}), true).is_err());
        assert!(disconnect_arguments(Some(Origin::Launch), &json!({"supportTerminateDebuggee":true}), false).is_err());
        assert_eq!(disconnect_arguments(Some(Origin::Attach), &json!({"supportTerminateDebuggee":true}), true).unwrap()["terminateDebuggee"], true);
        assert_eq!(disconnect_arguments(Some(Origin::Attach), &json!({"supportTerminateDebuggee":true}), false).unwrap()["terminateDebuggee"], false);
    }
}
