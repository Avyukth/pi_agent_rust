//! DAP session state, launch sequencing and retained breakpoint configuration.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::breakpoints::{self, Change, Group, Store};
use super::dap::{DapError, DapEvent, DapTransport};
use super::tool_err;
use crate::agent_cx::AgentCx;
use crate::error::Result;

/// Default per-request timeout.
pub const DEFAULT_DAP_TIMEOUT: Duration = Duration::from_secs(30);
const INITIALIZED_WAIT: Duration = Duration::from_secs(10);

/// The debuggee's execution state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ExecState {
    Running,
    Stopped { thread_id: u64, reason: String },
    Exited,
}

struct State {
    execution: ExecState,
    initialized: bool,
    revision: u64,
    capabilities: Value,
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

/// One live debug session. Breakpoint requests are serialized independently of
/// state polling; no blocking mutex guard crosses an await.
pub struct DapSession {
    transport: DapTransport,
    state: Mutex<State>,
    pub(super) breakpoints: Arc<asupersync::sync::Mutex<Store>>,
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
                execution: ExecState::Running, initialized: false, revision: 0, capabilities,
            }),
            breakpoints: Arc::new(asupersync::sync::Mutex::new(Store::default())),
        })
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

    pub fn pump_events(&self) {
        // Serialize draining as well as applying: concurrent callers cannot
        // apply a later batch before an earlier batch. initialized is latched,
        // and processing it never discards the rest of the drained events.
        let mut state = Self::lock(&self.state);
        for event in self.transport.drain_events() { state.event(event); }
        if !self.transport.is_alive() { state.execution = ExecState::Exited; }
    }

    /// Dispatch launch/attach concurrently with configuration. Adapters such
    /// as debugpy reply to launch only after configurationDone is answered.
    pub(super) async fn start(
        &self, command: &str, arguments: Value,
        initial: &BTreeMap<String, Vec<Value>>, exception_filters: Option<&[String]>,
    ) -> Result<()> {
        let configure = async {
            self.wait_initialized().await?;
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
        futures::future::try_join(self.call(command, arguments), configure).await?;
        self.pump_events();
        Ok(())
    }

    /// Readiness is a latched event, not a one-shot queue item a state query
    /// can consume. Missing readiness, cancellation and disconnect are errors.
    pub async fn wait_initialized(&self) -> Result<()> {
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
            if Duration::from_nanos(now.duration_since(start)) >= INITIALIZED_WAIT {
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

    /// Resuming invalidates the old stop before dispatch. A new stopped event
    /// may precede the command reply and must win over the resume transition.
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
        // On timeout/transport loss/cancel, do not restore stale frame access:
        // the adapter may already have resumed the debuggee.
        result.map_err(crate::error::Error::from)
    }

    pub async fn call_stopped(&self, command: &str, arguments: Value) -> Result<Value> {
        self.require_stopped()?;
        self.call(command, arguments).await
    }

    pub async fn terminate(&self) {
        let _ = self.call("terminate", json!({})).await;
        self.transport.kill();
        Self::lock(&self.state).execution = ExecState::Exited;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State { execution: ExecState::Running, initialized: false, revision: 0, capabilities: json!({}) }
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
}
