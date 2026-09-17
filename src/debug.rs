//! Agent-facing DAP debugger: owned sessions, retained breakpoint sets,
//! pre-execution configuration and state-gated inspection (bd-cv653.1.2).

pub mod adapters;
pub mod dap;
pub mod session;
mod breakpoints;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::sync::OwnedMutexGuard;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use adapters::AdapterSpec;
use breakpoints::{Change, Group};
use session::{DapSession, ExecState};

use crate::agent_cx::AgentCx;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::model::{ContentBlock, TextContent};
use crate::tools::{Tool, ToolEffects, ToolOutput, ToolUpdate};

fn tool_err(code: &str, message: impl Into<String>) -> Error {
    Error::tool("debug", format!("[{code}] {}", message.into()))
}

fn text_output(text: String, details: Value) -> ToolOutput {
    ToolOutput {
        content: vec![ContentBlock::Text(TextContent::new(text))],
        details: Some(details), is_error: false,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub struct DebugTool {
    cwd: PathBuf,
    adapters: Vec<AdapterSpec>,
    session: Mutex<Option<Arc<DapSession>>>,
    operations: Arc<asupersync::sync::Mutex<()>>,
}

impl DebugTool {
    #[must_use]
    pub fn new(cwd: &Path, _config: Option<&Config>) -> Self {
        Self {
            cwd: cwd.to_path_buf(), adapters: adapters::default_adapters(),
            session: Mutex::new(None),
            operations: Arc::new(asupersync::sync::Mutex::new(())),
        }
    }

    /// Trusted SDK adapter definitions; executable selection is not a tool
    /// argument. Unspecified IDs retain the built-in adapter registry behavior.
    #[must_use]
    pub fn with_adapters(mut self, adapters: Vec<AdapterSpec>) -> Self {
        self.adapters = adapters;
        self
    }

    fn session(&self) -> Result<Arc<DapSession>> {
        lock(&self.session).clone().ok_or_else(|| {
            tool_err("DAP_NO_SESSION", "no active debug session; launch or attach first")
        })
    }

    async fn run_start(&self, input: &DebugInput) -> Result<ToolOutput> {
        if lock(&self.session).is_some() {
            return Err(tool_err("DAP_SESSION_EXISTS", "terminate the existing debug session before launch or attach"));
        }
        let program = if input.action == "launch" {
            let program = input.required("program", input.program.as_deref())?;
            let path = self.cwd.join(program);
            if !path.is_file() {
                return Err(tool_err("DAP_TARGET_MISSING", format!("program does not exist: {}", path.display())));
            }
            Some(path)
        } else {
            input.pid.filter(|pid| *pid > 0)
                .ok_or_else(|| tool_err("DAP_USAGE", "debug attach requires a positive pid"))?;
            None
        };
        let initial = breakpoints::initial(&self.cwd, input.initial_breakpoints.as_deref().unwrap_or(&[]))?;
        let adapter = adapters::select_adapter(program.as_deref(), input.adapter.as_deref(), &self.adapters)
            .ok_or_else(|| tool_err("DAP_ADAPTER_MISSING", "no matching debug adapter; install lldb-dap, debugpy, or dlv"))?;
        let command = adapter.resolve_command().ok_or_else(|| {
            tool_err("DAP_ADAPTER_MISSING", format!("adapter {} not on PATH. hint: {}", adapter.id, adapter.install_hint))
        })?;
        let owner = AgentCx::for_current_or_request();
        if !owner.capabilities().io || !owner.capabilities().spawn || !owner.capabilities().time {
            return Err(tool_err("DAP_PERMISSION", "debug launch requires I/O, spawn and timer capabilities"));
        }
        owner.checkpoint().map_err(|_| tool_err("DAP_CANCELLED", "debug launch cancelled"))?;
        let arguments = if let Some(program) = &program {
            let mut args = adapters::launch_arguments(&adapter, program,
                input.args.as_deref().unwrap_or(&[]), &self.cwd);
            if let Some(stop) = input.stop_on_entry { args["stopOnEntry"] = json!(stop); }
            args
        } else {
            adapters::attach_arguments(&adapter, input.pid.expect("validated pid"))
        };
        let transport = dap::DapTransport::spawn(&command, &adapter.adapter_args, &[], &self.cwd)?;
        let session = DapSession::begin(transport).await?;
        // A failed configuration drops this local session, never publishes it
        // as running, and never swallows a configurationDone rejection.
        session.start(&input.action, arguments, &initial, input.exception_filters.as_deref()).await?;
        if program.is_some() && input.stop_on_entry.unwrap_or(true) {
            session.wait_stopped(Duration::from_secs(10)).await;
        }
        owner.checkpoint().map_err(|_| tool_err("DAP_CANCELLED", "debug startup cancelled"))?;
        let state = session.state();
        let payload = json!({
            "action": input.action, "program": program.as_ref().map(|path| path.display().to_string()),
            "pid": input.pid, "adapter": adapter.id,
            "state": match &state {
                ExecState::Stopped { reason, .. } if reason == "entry" => "stopped_entry",
                ExecState::Stopped { .. } => "stopped",
                ExecState::Running => "running",
                ExecState::Exited => "exited"
            },
            "execution": state, "capabilities": session.capabilities()
        });
        *lock(&self.session) = Some(Arc::new(session));
        Ok(text_output(payload.to_string(), payload))
    }

    async fn run_simple(&self, input: &DebugInput) -> Result<ToolOutput> {
        let session = self.session()?;
        let mut payload = match input.action.as_str() {
            "set_breakpoint" | "remove_breakpoint" | "set_function_breakpoint"
            | "remove_function_breakpoint" | "set_instruction_breakpoint"
            | "remove_instruction_breakpoint" | "set_data_breakpoint" | "remove_data_breakpoint" => {
                self.run_breakpoints(&session, input).await?
            }
            "list_breakpoints" => breakpoints::inventory(&session).await?,
            "data_breakpoint_info" => {
                session.require_capability("supportsDataBreakpoints")?;
                let name = input.required("name", input.name.as_deref())?;
                let mut args = json!({"name": name});
                if let Some(reference) = input.variables_reference { args["variablesReference"] = json!(reference); }
                let frame = match input.frame_id {
                    Some(frame) => frame,
                    None => self.top_frame(&session, input.thread_id).await?,
                };
                args["frameId"] = json!(frame);
                json!({"result": session.call_stopped("dataBreakpointInfo", args).await?})
            }
            "set_exception_breakpoints" => {
                let filters = input.exception_filters.as_deref()
                    .ok_or_else(|| tool_err("DAP_USAGE", "set_exception_breakpoints requires exceptionFilters"))?;
                let caps = session.capabilities();
                for filter in filters {
                    if !caps["exceptionBreakpointFilters"].as_array().is_some_and(|supported| {
                        supported.iter().any(|entry| entry["filter"].as_str() == Some(filter.as_str()))
                    }) {
                        return Err(tool_err("DAP_UNSUPPORTED", format!("unsupported exception filter: {filter}")));
                    }
                }
                json!({"result":session.call("setExceptionBreakpoints", json!({"filters":filters})).await?})
            }
            "continue" | "step_over" | "step_in" | "step_out" | "pause" => {
                self.run_execution(&session, input).await?
            }
            "evaluate" | "stack_trace" | "threads" | "scopes" | "variables" => {
                self.run_inspection(&session, input).await?
            }
            "disassemble" => {
                session.require_capability("supportsDisassembleRequest")?;
                let reference = input.required("reference", input.reference.as_deref())?;
                let body = session.call_stopped("disassemble", json!({
                    "memoryReference":reference, "instructionOffset":input.offset.unwrap_or(0),
                    "instructionCount":input.limit.unwrap_or(50), "resolveSymbols":true
                })).await?;
                json!({"instructions":body.get("instructions")})
            }
            "read_memory" | "write_memory" => {
                let writing = input.action == "write_memory";
                session.require_capability(if writing { "supportsWriteMemoryRequest" } else { "supportsReadMemoryRequest" })?;
                let address = input.required("address", input.address.as_deref())?;
                let mut args = json!({"memoryReference":address, "offset":input.offset.unwrap_or(0)});
                if writing {
                    args["data"] = json!(input.required("data", input.data.as_deref())?);
                } else { args["count"] = json!(input.limit.unwrap_or(64)); }
                let body = session.call_stopped(if writing { "writeMemory" } else { "readMemory" }, args).await?;
                json!({"address":address,"result":body})
            }
            "modules" => {
                session.require_capability("supportsModulesRequest")?;
                let body = session.call("modules", json!({"startModule":input.start.unwrap_or(0),"moduleCount":input.limit.unwrap_or(100)})).await?;
                json!({"modules":body.get("modules"),"totalModules":body.get("totalModules")})
            }
            "loaded_sources" => {
                session.require_capability("supportsLoadedSourcesRequest")?;
                let body = session.call("loadedSources", json!({})).await?;
                json!({"sources":body.get("sources")})
            }
            "custom_request" => {
                let command = input.required("command", input.command.as_deref())?;
                if matches!(command, "initialize" | "launch" | "attach" | "configurationDone"
                    | "setBreakpoints" | "setFunctionBreakpoints" | "setInstructionBreakpoints"
                    | "setDataBreakpoints" | "terminate" | "disconnect")
                {
                    return Err(tool_err("DAP_USAGE", "use the typed action for session or breakpoint-set changes"));
                }
                json!({"command":command,"result":session.call(command,input.payload.clone().unwrap_or_else(||json!({}))).await?})
            }
            "output" => json!({"tail":session.output_tail()}),
            "terminate" => {
                session.terminate().await;
                lock(&self.session).take();
                json!({"state":"exited"})
            }
            "sessions" => json!({"sessions":[{"id":0,"state":session.state(),"capabilities":session.capabilities()}]}),
            other => return Err(tool_err("DAP_USAGE", format!("unknown debug action {other:?}"))),
        };
        payload["action"] = json!(input.action);
        Ok(text_output(payload.to_string(), payload))
    }

    async fn run_breakpoints(&self, session: &DapSession, input: &DebugInput) -> Result<Value> {
        let setting = input.action.starts_with("set_");
        let (group, key, mut payload) = match input.action.as_str() {
            "set_breakpoint" | "remove_breakpoint" => {
                let path = breakpoints::source_path(&self.cwd, input.required("file", input.file.as_deref())?)?;
                let line = if setting {
                    Some(input.line.ok_or_else(|| tool_err("DAP_USAGE", "set_breakpoint requires line"))?)
                } else { input.line };
                let key = line.map(|line| breakpoints::source_spec(line, input.column,
                    if setting { input.condition.as_deref() } else { None },
                    if setting { input.hit_condition.as_deref() } else { None },
                    if setting { input.log_message.as_deref() } else { None })).transpose()?;
                (Group::Source(path.clone()), key, json!({"file":path,"line":line,"column":input.column}))
            }
            "set_function_breakpoint" | "remove_function_breakpoint" => {
                let name = if setting { Some(input.required("name",input.name.as_deref())?) } else { input.name.as_deref() };
                (Group::Function, name.map(|name|json!({"name":name})), json!({"name":name}))
            }
            "set_instruction_breakpoint" | "remove_instruction_breakpoint" => {
                let reference = if setting { Some(input.required("reference",input.reference.as_deref())?) } else { input.reference.as_deref() };
                (Group::Instruction, reference.map(|reference|json!({"instructionReference":reference,"offset":input.offset.unwrap_or(0)})), json!({"reference":reference,"offset":input.offset.unwrap_or(0)}))
            }
            "set_data_breakpoint" | "remove_data_breakpoint" => {
                // dataId is opaque adapter output, not a source variable name.
                let data_id = input.data_id.as_deref().or(input.name.as_deref());
                let data_id = if setting { Some(input.required("dataId",data_id)?) } else { data_id };
                (Group::Data, data_id.map(|id|json!({"dataId":id,"accessType":input.access_type.as_deref().unwrap_or("write")})), json!({"dataId":data_id}))
            }
            _ => return Err(tool_err("DAP_USAGE", "unknown breakpoint action")),
        };
        let change = if setting {
            let mut spec = key.expect("setting requires a key");
            if !matches!(&group, Group::Source(_)) {
                if input.log_message.is_some() { return Err(tool_err("DAP_USAGE", "logMessage is supported on source breakpoints only")); }
                breakpoints::options(&mut spec,input.condition.as_deref(),input.hit_condition.as_deref(),None)?;
            }
            breakpoints::check_options(session,&spec)?;
            Change::Upsert(spec)
        } else { Change::Remove(key) };
        let result = breakpoints::apply(session,group,change).await?;
        payload["verified"] = result["selected"]["verified"].clone();
        payload["breakpoint"] = result["selected"].clone();
        payload["breakpoints"] = result["breakpoints"].clone();
        payload["count"] = result["count"].clone();
        payload["synchronized"] = result["synchronized"].clone();
        Ok(payload)
    }

    async fn run_execution(&self, session: &DapSession, input: &DebugInput) -> Result<Value> {
        let thread = if input.action == "pause" {
            match input.thread_id { Some(thread) => thread, None => self.any_thread(session).await? }
        } else { Self::current_thread(session,input.thread_id)? };
        let command = match input.action.as_str() {
            "continue" => "continue", "step_over" => "next", "step_in" => "stepIn",
            "step_out" => "stepOut", _ => "pause",
        };
        let response = session.call(command,json!({"threadId":thread})).await?;
        let stopped = if input.action == "continue" { None } else { session.wait_stopped(Duration::from_secs(5)).await };
        Ok(json!({"threadId":thread,"response":response,"state":session.state(),
            "stopped":stopped.map(|(thread,reason)|json!({"threadId":thread,"reason":reason}))}))
    }

    async fn run_inspection(&self, session: &DapSession, input: &DebugInput) -> Result<Value> {
        match input.action.as_str() {
            "evaluate" => {
                let expression = input.required("expression",input.expression.as_deref())?;
                let frame = match input.frame_id { Some(frame) => frame, None => self.top_frame(session,input.thread_id).await? };
                let body = session.call_stopped("evaluate",json!({"expression":expression,"frameId":frame,
                    "context":input.context.as_deref().unwrap_or("repl")})).await?;
                Ok(json!({"expression":expression,"frameId":frame,"result":body.get("result"),"type":body.get("type"),
                    "variablesReference":body.get("variablesReference"),"namedVariables":body.get("namedVariables"),
                    "indexedVariables":body.get("indexedVariables"),"memoryReference":body.get("memoryReference"),
                    "presentationHint":body.get("presentationHint")}))
            }
            "stack_trace" => {
                let thread = Self::current_thread(session,input.thread_id)?;
                let body = session.call_stopped("stackTrace",json!({"threadId":thread,
                    "startFrame":input.start.unwrap_or(0),"levels":input.limit.unwrap_or(50)})).await?;
                Ok(json!({"threadId":thread,"frames":body.get("stackFrames"),"totalFrames":body.get("totalFrames")}))
            }
            "threads" => {
                let body = session.call("threads",json!({})).await?;
                Ok(json!({"threads":body.get("threads")}))
            }
            "scopes" => {
                let frame = match input.frame_id { Some(frame) => frame, None => self.top_frame(session,input.thread_id).await? };
                let body = session.call_stopped("scopes",json!({"frameId":frame})).await?;
                Ok(json!({"frameId":frame,"scopes":body.get("scopes")}))
            }
            "variables" => {
                let reference = input.variables_reference.filter(|reference| *reference > 0)
                    .ok_or_else(||tool_err("DAP_USAGE","variables requires a positive variablesReference"))?;
                let mut args = json!({"variablesReference":reference});
                if let Some(start) = input.start { args["start"] = json!(start); }
                if let Some(count) = input.limit { args["count"] = json!(count); }
                if let Some(filter) = &input.filter { args["filter"] = json!(filter); }
                let body = session.call_stopped("variables",args).await?;
                Ok(json!({"variablesReference":reference,"variables":body.get("variables")}))
            }
            _ => Err(tool_err("DAP_USAGE","unknown inspection action")),
        }
    }

    fn current_thread(session: &DapSession, selected: Option<u64>) -> Result<u64> {
        let stopped = session.require_stopped()?;
        selected.or((stopped != 0).then_some(stopped)).ok_or_else(|| {
            tool_err("DAP_NO_THREADS","stopped event omitted threadId; query threads and supply threadId")
        })
    }

    async fn any_thread(&self, session: &DapSession) -> Result<u64> {
        if let ExecState::Stopped { thread_id, .. } = session.state()
            && thread_id > 0 { return Ok(thread_id); }
        let body = session.call("threads",json!({})).await?;
        body["threads"].as_array().and_then(|threads|threads.first())
            .and_then(|thread|thread["id"].as_u64()).filter(|thread|*thread > 0)
            .ok_or_else(||tool_err("DAP_NO_THREADS","adapter reported no threads"))
    }

    async fn top_frame(&self, session: &DapSession, thread: Option<u64>) -> Result<u64> {
        let thread = Self::current_thread(session,thread)?;
        let body = session.call_stopped("stackTrace",json!({"threadId":thread,"startFrame":0,"levels":1})).await?;
        body["stackFrames"].as_array().and_then(|frames|frames.first())
            .and_then(|frame|frame["id"].as_u64())
            .ok_or_else(||tool_err("DAP_NO_FRAMES","no stack frames"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DebugInput {
    action: String,
    program: Option<String>,
    args: Option<Vec<String>>,
    adapter: Option<String>,
    pid: Option<u32>,
    file: Option<String>,
    line: Option<u64>,
    column: Option<u64>,
    condition: Option<String>,
    hit_condition: Option<String>,
    log_message: Option<String>,
    name: Option<String>,
    data_id: Option<String>,
    access_type: Option<String>,
    reference: Option<String>,
    address: Option<String>,
    data: Option<String>,
    expression: Option<String>,
    context: Option<String>,
    thread_id: Option<u64>,
    frame_id: Option<u64>,
    variables_reference: Option<u64>,
    offset: Option<i64>,
    start: Option<u64>,
    limit: Option<u64>,
    filter: Option<String>,
    command: Option<String>,
    payload: Option<Value>,
    initial_breakpoints: Option<Vec<breakpoints::SourceInput>>,
    exception_filters: Option<Vec<String>>,
    stop_on_entry: Option<bool>,
}

impl DebugInput {
    fn required<'a>(&self, field: &str, value: Option<&'a str>) -> Result<&'a str> {
        value.filter(|value|!value.is_empty() && !value.contains('\0') && value.len() <= 1024 * 1024)
            .ok_or_else(||tool_err("DAP_USAGE",format!("{} requires nonempty, NUL-free {field}",self.action)))
    }

    fn validate(&self) -> Result<()> {
        if self.limit.is_some_and(|limit|limit == 0 || limit > 1_000_000)
            || self.start.is_some_and(|start|start > 2_147_483_647)
            || self.offset.is_some_and(|offset|!(-2_147_483_648..=2_147_483_647).contains(&offset))
            || self.thread_id.is_some_and(|thread|thread == 0 || thread > 2_147_483_647)
            || self.frame_id.is_some_and(|frame|frame > 2_147_483_647)
            || self.variables_reference.is_some_and(|reference|reference > 2_147_483_647)
        { return Err(tool_err("DAP_USAGE","invalid DAP identifier, offset or result limit")); }
        if self.filter.as_deref().is_some_and(|filter|!matches!(filter,"named"|"indexed")) {
            return Err(tool_err("DAP_USAGE","filter must be named or indexed"));
        }
        if self.access_type.as_deref().is_some_and(|access|!matches!(access,"read"|"write"|"readWrite")) {
            return Err(tool_err("DAP_USAGE","accessType must be read, write or readWrite"));
        }
        if self.exception_filters.as_ref().is_some_and(|filters|filters.len() > 64 || filters.iter().any(|filter|filter.is_empty() || filter.len() > 256)) {
            return Err(tool_err("DAP_USAGE","exceptionFilters must contain at most 64 nonempty filter IDs"));
        }
        Ok(())
    }
}

#[async_trait]
#[allow(clippy::unnecessary_literal_bound)]
impl Tool for DebugTool {
    fn name(&self) -> &str { "debug" }
    fn label(&self) -> &str { "debug" }
    fn description(&self) -> &str {
        "Drive a real DAP debugger: launch/attach with initial breakpoints, retained source/function/instruction/data breakpoints, conditional breakpoints/logpoints, stepping, evaluation, stack/variables and memory. One active session. Removing a breakpoint with its key preserves the others; omit the key to clear that set. Stack operations require a stopped debuggee."
    }
    fn parameters(&self) -> Value {
        json!({
            "type":"object", "required":["action"],
            "properties": {
                "action":{"type":"string","enum":["launch","attach","set_breakpoint","remove_breakpoint",
                    "set_function_breakpoint","remove_function_breakpoint","set_instruction_breakpoint","remove_instruction_breakpoint",
                    "data_breakpoint_info","set_data_breakpoint","remove_data_breakpoint","list_breakpoints","set_exception_breakpoints",
                    "continue","step_over","step_in","step_out","pause","evaluate","stack_trace","threads","scopes","variables",
                    "disassemble","read_memory","write_memory","modules","loaded_sources","custom_request","output","terminate","sessions"]},
                "program":{"type":"string","description":"Binary/script to launch"},
                "args":{"type":"array","items":{"type":"string"}},
                "adapter":{"type":"string","description":"Registered adapter ID, not an executable path"},
                "pid":{"type":"integer","minimum":1},
                "file":{"type":"string","description":"Source path; required for source breakpoint set/remove"},
                "line":{"type":"integer","minimum":1,"description":"1-based line; omit on removal to clear all breakpoints in file"},
                "column":{"type":"integer","minimum":1},
                "condition":{"type":"string","maxLength":4096},
                "hitCondition":{"type":"string","maxLength":4096},
                "logMessage":{"type":"string","maxLength":4096,"description":"Source logpoint message; requires adapter support"},
                "name":{"type":"string","description":"Function name or variable name for data_breakpoint_info"},
                "dataId":{"type":"string","description":"Opaque ID returned by data_breakpoint_info, not a variable name"},
                "accessType":{"type":"string","enum":["read","write","readWrite"]},
                "reference":{"type":"string","description":"Instruction reference; omit on removal to clear the instruction set"},
                "address":{"type":"string","description":"Memory reference"},
                "data":{"type":"string","description":"Base64 for write_memory"},
                "expression":{"type":"string"}, "context":{"type":"string"},
                "threadId":{"type":"integer","minimum":1,"description":"Selected thread; defaults to the stopped thread"},
                "frameId":{"type":"integer","minimum":0},
                "variablesReference":{"type":"integer","minimum":0},
                "offset":{"type":"integer"}, "start":{"type":"integer","minimum":0},
                "limit":{"type":"integer","minimum":1,"maximum":1000000},
                "filter":{"type":"string","enum":["named","indexed"]},
                "command":{"type":"string"}, "payload":{"type":"object"},
                "stopOnEntry":{"type":"boolean","default":true},
                "exceptionFilters":{"type":"array","maxItems":64,"items":{"type":"string"}},
                "initialBreakpoints":{"type":"array","maxItems":1024,"description":"Source breakpoints installed before configurationDone, for launch/attach",
                    "items":{"type":"object","required":["file","line"],"additionalProperties":false,
                        "properties":{"file":{"type":"string"},"line":{"type":"integer","minimum":1},
                            "column":{"type":"integer","minimum":1},"condition":{"type":"string"},
                            "hitCondition":{"type":"string"},"logMessage":{"type":"string"}}}}
            }
        })
    }
    fn effects(&self) -> ToolEffects { ToolEffects::process() }
    async fn execute(&self, _tool_call_id: &str, input: Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>) -> Result<ToolOutput>
    {
        let input: DebugInput = serde_json::from_value(input)
            .map_err(|error|tool_err("DAP_USAGE",format!("invalid input: {error}")))?;
        input.validate()?;
        let owner = AgentCx::for_current_or_request();
        let _operation = OwnedMutexGuard::lock(Arc::clone(&self.operations),owner.cx()).await
            .map_err(|_|tool_err("DAP_CANCELLED","debug operation cancelled while queued"))?;
        match input.action.as_str() {
            "launch"|"attach" => self.run_start(&input).await,
            "sessions" if lock(&self.session).is_none() => {
                let payload = json!({"action":"sessions","sessions":[]});
                Ok(text_output(payload.to_string(),payload))
            }
            _ => self.run_simple(&input).await,
        }
    }
}

#[cfg(test)]
mod tests;
