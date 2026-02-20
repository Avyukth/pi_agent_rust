use super::conversation::{
    add_usage, build_content_blocks_for_input, content_blocks_to_text, last_assistant_message,
    split_content_blocks_for_input,
};
use super::ext_session::{format_extension_ui_prompt, parse_extension_ui_response};
use super::*;

pub(super) fn extension_commands_for_catalog(
    manager: &ExtensionManager,
) -> Vec<crate::autocomplete::NamedEntry> {
    manager
        .list_commands()
        .into_iter()
        .filter_map(|cmd| {
            let name = cmd.get("name")?.as_str()?.to_string();
            let description = cmd
                .get("description")
                .and_then(|d| d.as_str())
                .map(std::string::ToString::to_string);
            Some(crate::autocomplete::NamedEntry { name, description })
        })
        .collect()
}

pub(super) fn build_user_message(text: String) -> ModelMessage {
    ModelMessage::User(UserMessage {
        content: UserContent::Text(text),
        timestamp: Utc::now().timestamp_millis(),
    })
}

async fn dispatch_input_event(
    manager: &ExtensionManager,
    text: String,
    images: Vec<ImageContent>,
) -> crate::error::Result<InputEventOutcome> {
    let images_value = serde_json::to_value(&images).unwrap_or(Value::Null);
    let payload = json!({
        "text": text,
        "images": images_value,
        "source": "user",
    });
    let response = manager
        .dispatch_event_with_response(
            ExtensionEventName::Input,
            Some(payload),
            EXTENSION_EVENT_TIMEOUT_MS,
        )
        .await?;
    Ok(apply_input_event_response(response, text, images))
}

const UI_STREAM_DELTA_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(45);
const UI_STREAM_DELTA_MAX_BUFFER_BYTES: usize = 2 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamDeltaKind {
    Text,
    Thinking,
}

struct UiStreamDeltaBatcher {
    sender: mpsc::Sender<PiMsg>,
    pending: std::collections::VecDeque<PiMsg>,
    pending_bytes: usize,
    flush_interval: std::time::Duration,
    max_pending_bytes: usize,
    last_flush: std::time::Instant,
}

impl UiStreamDeltaBatcher {
    fn new(sender: mpsc::Sender<PiMsg>) -> Self {
        let now = std::time::Instant::now();
        let flush_interval = UI_STREAM_DELTA_FLUSH_INTERVAL;
        Self {
            sender,
            pending: std::collections::VecDeque::new(),
            pending_bytes: 0,
            flush_interval,
            max_pending_bytes: UI_STREAM_DELTA_MAX_BUFFER_BYTES,
            // Prime the first delta flush so the UI shows immediate output.
            last_flush: now.checked_sub(flush_interval).unwrap_or(now),
        }
    }

    fn push_delta(&mut self, kind: StreamDeltaKind, delta: &str) {
        if delta.is_empty() {
            return;
        }
        if let Some(last) = self.pending.back_mut() {
            match (kind, last) {
                (StreamDeltaKind::Text, PiMsg::TextDelta(text))
                | (StreamDeltaKind::Thinking, PiMsg::ThinkingDelta(text)) => {
                    text.push_str(delta);
                    self.pending_bytes += delta.len();
                    self.flush(false);
                    return;
                }
                _ => {}
            }
        }

        let msg = match kind {
            StreamDeltaKind::Text => PiMsg::TextDelta(delta.to_string()),
            StreamDeltaKind::Thinking => PiMsg::ThinkingDelta(delta.to_string()),
        };
        self.pending.push_back(msg);
        self.pending_bytes += delta.len();
        self.flush(false);
    }

    fn send_immediate(&mut self, msg: PiMsg) {
        self.pending.push_back(msg);
        self.flush(true);
    }

    fn delta_bytes_for_msg(msg: &PiMsg) -> usize {
        match msg {
            PiMsg::TextDelta(text) | PiMsg::ThinkingDelta(text) => text.len(),
            _ => 0,
        }
    }

    fn flush(&mut self, force: bool) {
        if self.pending.is_empty() {
            return;
        }

        if !force
            && self.pending_bytes < self.max_pending_bytes
            && self.last_flush.elapsed() < self.flush_interval
        {
            return;
        }

        let mut sent_any = false;

        while let Some(msg) = self.pending.pop_front() {
            let delta_bytes = Self::delta_bytes_for_msg(&msg);
            match self.sender.try_send(msg) {
                Ok(()) => {
                    self.pending_bytes = self.pending_bytes.saturating_sub(delta_bytes);
                    sent_any = true;
                }
                Err(err) => {
                    match err {
                        mpsc::SendError::Full(msg) => {
                            self.pending.push_front(msg);
                        }
                        mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_) => {
                            self.pending.clear();
                            self.pending_bytes = 0;
                        }
                    }
                    break;
                }
            }
        }

        if sent_any {
            self.last_flush = std::time::Instant::now();
        }
    }
}

fn build_agent_done_pi_msg(messages: &[ModelMessage]) -> PiMsg {
    let last = last_assistant_message(messages);
    let mut usage = Usage::default();
    for message in messages {
        if let ModelMessage::Assistant(assistant) = message {
            add_usage(&mut usage, &assistant.usage);
        }
    }
    PiMsg::AgentDone {
        usage: Some(usage),
        stop_reason: last
            .as_ref()
            .map_or(StopReason::Stop, |msg| msg.stop_reason),
        error_message: last.as_ref().and_then(|msg| msg.error_message.clone()),
    }
}

fn dispatch_agent_event_to_ui(event: &AgentEvent, batcher: &mut UiStreamDeltaBatcher) {
    match event {
        AgentEvent::MessageUpdate {
            assistant_message_event,
            ..
        } => match assistant_message_event {
            AssistantMessageEvent::TextDelta { delta, .. } => {
                batcher.push_delta(StreamDeltaKind::Text, delta);
            }
            AssistantMessageEvent::ThinkingDelta { delta, .. } => {
                batcher.push_delta(StreamDeltaKind::Thinking, delta);
            }
            _ => {}
        },
        AgentEvent::AgentStart { .. } => {
            batcher.send_immediate(PiMsg::AgentStart);
        }
        AgentEvent::ToolExecutionStart {
            tool_name,
            tool_call_id,
            ..
        } => {
            batcher.send_immediate(PiMsg::ToolStart {
                name: tool_name.clone(),
                tool_id: tool_call_id.clone(),
            });
        }
        AgentEvent::ToolExecutionUpdate {
            tool_name,
            tool_call_id,
            partial_result,
            ..
        } => {
            batcher.send_immediate(PiMsg::ToolUpdate {
                name: tool_name.clone(),
                tool_id: tool_call_id.clone(),
                content: partial_result.content.clone(),
                details: partial_result.details.clone(),
            });
        }
        AgentEvent::ToolExecutionEnd {
            tool_name,
            tool_call_id,
            is_error,
            ..
        } => {
            batcher.send_immediate(PiMsg::ToolEnd {
                name: tool_name.clone(),
                tool_id: tool_call_id.clone(),
                is_error: *is_error,
            });
        }
        AgentEvent::AgentEnd { messages, .. } => {
            batcher.send_immediate(build_agent_done_pi_msg(messages));
        }
        _ => {}
    }
}

async fn flush_ui_stream_batcher_with_backpressure(batcher: &StdMutex<UiStreamDeltaBatcher>) {
    let (sender, pending) = {
        let mut guard = match batcher.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.flush(true);
        if guard.pending.is_empty() {
            return;
        }
        let sender = guard.sender.clone();
        let pending = std::mem::take(&mut guard.pending);
        guard.pending_bytes = 0;
        drop(guard);
        (sender, pending)
    };

    let cx = Cx::for_request();
    for msg in pending {
        if sender.send(&cx, msg).await.is_err() {
            break;
        }
    }
}

impl PiApp {
    /// Handle custom Pi messages from the agent.
    #[allow(clippy::too_many_lines)]
    pub(super) fn handle_pi_message(&mut self, msg: PiMsg) -> Option<Cmd> {
        match msg {
            PiMsg::AgentStart => {
                self.agent_state = AgentState::Processing;
                self.current_response.clear();
                self.current_thinking.clear();
                self.extension_streaming.store(true, Ordering::SeqCst);
            }
            PiMsg::RunPending => {
                return self.run_next_pending();
            }
            PiMsg::EnqueuePendingInput(input) => {
                self.pending_inputs.push_back(input);
                if self.agent_state == AgentState::Idle {
                    return self.run_next_pending();
                }
            }
            PiMsg::UiShutdown => {
                // Internal signal for shutting down the async→UI bridge; should not normally reach
                // the UI event loop, but handle it defensively.
            }
            PiMsg::TextDelta(text) => {
                self.current_response.push_str(&text);
                // While tail-following, `view()` computes the bottom slice
                // directly, so we can skip full viewport rebuilds on every
                // token to reduce redraw jitter.
                if !self.follow_stream_tail {
                    self.refresh_conversation_viewport(false);
                }
            }
            PiMsg::ThinkingDelta(text) => {
                self.current_thinking.push_str(&text);
                if !self.follow_stream_tail {
                    self.refresh_conversation_viewport(false);
                }
            }
            PiMsg::ToolStart { name, .. } => {
                self.agent_state = AgentState::ToolRunning;
                self.current_tool = Some(name);
                self.tool_progress = Some(ToolProgress::new());
                self.pending_tool_output = None;
            }
            PiMsg::ToolUpdate {
                name,
                content,
                details,
                ..
            } => {
                // Update progress metrics from details if present.
                if let Some(ref mut progress) = self.tool_progress {
                    progress.update_from_details(details.as_ref());
                } else {
                    let mut progress = ToolProgress::new();
                    progress.update_from_details(details.as_ref());
                    self.tool_progress = Some(progress);
                }
                if let Some(output) = format_tool_output(
                    &content,
                    details.as_ref(),
                    self.config.terminal_show_images(),
                ) {
                    self.pending_tool_output = Some(format!("Tool {name} output:\n{output}"));
                }
            }
            PiMsg::ToolEnd { .. } => {
                self.agent_state = AgentState::Processing;
                self.current_tool = None;
                self.tool_progress = None;
                if let Some(output) = self.pending_tool_output.take() {
                    self.messages.push(ConversationMessage::tool(output));
                    self.scroll_to_bottom();
                }
            }
            PiMsg::AgentDone {
                usage,
                stop_reason,
                error_message,
            } => {
                // Snapshot follow-tail *before* we mutate conversation state so
                // we preserve the user's scroll intent.
                let follow_tail = self.follow_stream_tail;

                // Finalize the response: move streaming buffers into the
                // permanent message list and clear them so they are not
                // double-rendered by build_conversation_content().
                let had_response = !self.current_response.is_empty();
                if had_response {
                    self.messages.push(ConversationMessage::new(
                        MessageRole::Assistant,
                        std::mem::take(&mut self.current_response),
                        if self.current_thinking.is_empty() {
                            None
                        } else {
                            Some(std::mem::take(&mut self.current_thinking))
                        },
                    ));
                }
                // Defensively clear both buffers even if they were already
                // taken — this prevents a stale streaming section from
                // appearing in the next view() frame.
                self.current_response.clear();
                self.current_thinking.clear();

                // Update usage
                if let Some(ref u) = usage {
                    add_usage(&mut self.total_usage, u);
                }

                self.agent_state = AgentState::Idle;
                self.current_tool = None;
                self.abort_handle = None;
                self.extension_streaming.store(false, Ordering::SeqCst);
                self.extension_compacting.store(false, Ordering::SeqCst);

                // Refresh git branch (may have changed during tool execution)
                self.git_branch = super::read_git_branch(&self.cwd);

                if stop_reason == StopReason::Aborted {
                    self.status_message = Some("Request aborted".to_string());
                } else if stop_reason == StopReason::Error {
                    let message = error_message.unwrap_or_else(|| "Request failed".to_string());
                    self.status_message = Some(message.clone());
                    if !had_response {
                        self.messages.push(ConversationMessage {
                            role: MessageRole::System,
                            content: format!("Error: {message}"),
                            thinking: None,
                            collapsed: false,
                        });
                    }
                }

                // Re-focus input BEFORE syncing the viewport — focus()
                // can change the input height, and the viewport offset
                // calculation depends on view_effective_conversation_height()
                // which accounts for the input area.
                self.input.focus();

                // Sync the viewport so the finalized (markdown-rendered)
                // message is visible. This is critical: without it the
                // viewport's stored content would still reflect the raw
                // streaming text, causing the final message to appear
                // overwritten or missing.
                self.refresh_conversation_viewport(follow_tail);

                if !self.pending_inputs.is_empty() {
                    return Some(Cmd::new(|| Message::new(PiMsg::RunPending)));
                }
            }
            PiMsg::AgentError(error) => {
                self.current_response.clear();
                self.current_thinking.clear();
                let content = if error.contains('\n') || error.starts_with("Error:") {
                    error
                } else {
                    format!("Error: {error}")
                };
                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content,
                    thinking: None,
                    collapsed: false,
                });
                self.agent_state = AgentState::Idle;
                self.current_tool = None;
                self.abort_handle = None;
                self.extension_streaming.store(false, Ordering::SeqCst);
                self.extension_compacting.store(false, Ordering::SeqCst);
                self.input.focus();
                self.refresh_conversation_viewport(true);

                if !self.pending_inputs.is_empty() {
                    return Some(Cmd::new(|| Message::new(PiMsg::RunPending)));
                }
            }
            PiMsg::CredentialUpdated { provider } => {
                self.sync_active_provider_credentials(&provider);
            }
            PiMsg::UpdateLastUserMessage(content) => {
                if let Some(message) = self
                    .messages
                    .iter_mut()
                    .rev()
                    .find(|message| message.role == MessageRole::User)
                {
                    message.content = content;
                }
                self.scroll_to_bottom();
            }
            PiMsg::System(message) => {
                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: message,
                    thinking: None,
                    collapsed: false,
                });
                self.agent_state = AgentState::Idle;
                self.current_tool = None;
                self.abort_handle = None;
                self.extension_streaming.store(false, Ordering::SeqCst);
                self.extension_compacting.store(false, Ordering::SeqCst);
                self.input.focus();

                if !self.pending_inputs.is_empty() {
                    return Some(Cmd::new(|| Message::new(PiMsg::RunPending)));
                }
            }
            PiMsg::SystemNote(message) => {
                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: message,
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_bottom();
            }
            PiMsg::BashResult {
                display,
                content_for_agent,
            } => {
                self.bash_running = false;
                self.current_tool = None;
                self.agent_state = AgentState::Idle;

                if let Some(content) = content_for_agent {
                    self.scroll_to_bottom();
                    return self.submit_content(content);
                }

                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: display,
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_bottom();
                self.input.focus();

                if !self.pending_inputs.is_empty() {
                    return Some(Cmd::new(|| Message::new(PiMsg::RunPending)));
                }
            }
            PiMsg::ConversationReset {
                messages,
                usage,
                status,
            } => {
                self.messages = messages;
                self.total_usage = usage;
                self.current_response.clear();
                self.current_thinking.clear();
                self.agent_state = AgentState::Idle;
                self.current_tool = None;
                self.abort_handle = None;
                self.status_message = status;
                self.message_render_cache.clear();
                self.scroll_to_bottom();
                self.input.focus();
            }
            PiMsg::SetEditorText(text) => {
                self.input.set_value(&text);
                self.input.focus();
            }
            PiMsg::ResourcesReloaded {
                resources,
                status,
                diagnostics,
            } => {
                let mut autocomplete_catalog = AutocompleteCatalog::from_resources(&resources);
                if let Some(manager) = &self.extensions {
                    autocomplete_catalog.extension_commands =
                        extension_commands_for_catalog(manager);
                }
                self.autocomplete.provider.set_catalog(autocomplete_catalog);
                self.autocomplete.close();
                self.resources = resources;
                self.apply_theme(Theme::resolve(&self.config, &self.cwd));
                self.agent_state = AgentState::Idle;
                self.current_tool = None;
                self.abort_handle = None;
                self.status_message = Some(status);
                if let Some(message) = diagnostics {
                    self.messages.push(ConversationMessage {
                        role: MessageRole::System,
                        content: message,
                        thinking: None,
                        collapsed: false,
                    });
                    self.scroll_to_bottom();
                }
                self.input.focus();
            }
            PiMsg::ExtensionUiRequest(request) => {
                return self.handle_extension_ui_request(request);
            }
            PiMsg::ExtensionCommandDone {
                command: _,
                display,
                is_error: _,
            } => {
                self.agent_state = AgentState::Idle;
                self.current_tool = None;

                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: display,
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_bottom();
                self.input.focus();

                if !self.pending_inputs.is_empty() {
                    return Some(Cmd::new(|| Message::new(PiMsg::RunPending)));
                }
            }
        }
        None
    }

    fn handle_extension_ui_request(&mut self, request: ExtensionUiRequest) -> Option<Cmd> {
        // Capability-specific prompts get a dedicated modal overlay.
        if CapabilityPromptOverlay::is_capability_prompt(&request) {
            self.capability_prompt = Some(CapabilityPromptOverlay::from_request(request));
            return None;
        }
        if request.expects_response() {
            self.extension_ui_queue.push_back(request);
            self.advance_extension_ui_queue();
        } else {
            self.apply_extension_ui_effect(&request);
        }
        None
    }

    fn apply_extension_ui_effect(&mut self, request: &ExtensionUiRequest) {
        match request.method.as_str() {
            "notify" => {
                let title = request
                    .payload
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("Notification");
                let message = request
                    .payload
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let level = request
                    .payload
                    .get("level")
                    .and_then(Value::as_str)
                    .or_else(|| request.payload.get("notifyType").and_then(Value::as_str))
                    .or_else(|| request.payload.get("notify_type").and_then(Value::as_str))
                    .unwrap_or("info");
                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: format!("Extension notify ({level}): {title} {message}"),
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_bottom();
            }
            "setStatus" | "set_status" => {
                let status_text = request
                    .payload
                    .get("statusText")
                    .and_then(Value::as_str)
                    .or_else(|| request.payload.get("status_text").and_then(Value::as_str))
                    .or_else(|| request.payload.get("text").and_then(Value::as_str))
                    .unwrap_or("");
                if !status_text.is_empty() {
                    let status_key = request
                        .payload
                        .get("statusKey")
                        .and_then(Value::as_str)
                        .or_else(|| request.payload.get("status_key").and_then(Value::as_str))
                        .unwrap_or("");

                    self.status_message = Some(if status_key.is_empty() {
                        status_text.to_string()
                    } else {
                        format!("{status_key}: {status_text}")
                    });
                }
            }
            "setWidget" | "set_widget" => {
                let widget_key = request
                    .payload
                    .get("widgetKey")
                    .and_then(Value::as_str)
                    .or_else(|| request.payload.get("widget_key").and_then(Value::as_str))
                    .unwrap_or("widget");

                let content = request
                    .payload
                    .get("content")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .or_else(|| {
                        request
                            .payload
                            .get("widgetLines")
                            .or_else(|| request.payload.get("widget_lines"))
                            .or_else(|| request.payload.get("lines"))
                            .and_then(Value::as_array)
                            .map(|items| {
                                items
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            })
                    });

                if let Some(content) = content {
                    self.messages.push(ConversationMessage {
                        role: MessageRole::System,
                        content: format!("Extension widget ({widget_key}):\n{content}"),
                        thinking: None,
                        collapsed: false,
                    });
                    self.scroll_to_bottom();
                }
            }
            "setTitle" | "set_title" => {
                if let Some(title) = request.payload.get("title").and_then(Value::as_str) {
                    self.status_message = Some(format!("Title: {title}"));
                }
            }
            "set_editor_text" => {
                if let Some(text) = request.payload.get("text").and_then(Value::as_str) {
                    self.input.set_value(text);
                }
            }
            _ => {}
        }
    }

    pub(super) fn send_extension_ui_response(&mut self, response: ExtensionUiResponse) {
        if let Some(manager) = &self.extensions {
            if !manager.respond_ui(response) {
                self.status_message = Some("No pending extension UI request".to_string());
            }
        } else {
            self.status_message = Some("Extensions are disabled".to_string());
        }
    }

    fn advance_extension_ui_queue(&mut self) {
        if self.active_extension_ui.is_some() {
            return;
        }
        if let Some(next) = self.extension_ui_queue.pop_front() {
            let prompt = format_extension_ui_prompt(&next);
            self.active_extension_ui = Some(next);
            self.messages.push(ConversationMessage {
                role: MessageRole::System,
                content: prompt,
                thinking: None,
                collapsed: false,
            });
            self.scroll_to_bottom();
            self.input.focus();
        }
    }

    fn dispatch_extension_command(&mut self, command: &str, args: &[String]) -> Option<Cmd> {
        let Some(manager) = &self.extensions else {
            self.status_message = Some("Extensions are disabled".to_string());
            return None;
        };

        let Some(runtime) = manager.runtime() else {
            self.status_message = Some(format!(
                "Extension command '/{command}' is not available (runtime not enabled)"
            ));
            return None;
        };

        self.agent_state = AgentState::ToolRunning;
        self.current_tool = Some(format!("/{command}"));

        let command_name = command.to_string();
        let args_str = args.join(" ");
        let cwd = self.cwd.display().to_string();
        let event_tx = self.event_tx.clone();
        let runtime_handle = self.runtime_handle.clone();

        let ctx_payload = serde_json::json!({
            "cwd": cwd,
            "hasUI": true,
        });

        let cmd_for_msg = command_name.clone();
        runtime_handle.spawn(async move {
            let result = runtime
                .execute_command(
                    command_name,
                    args_str,
                    std::sync::Arc::new(ctx_payload),
                    crate::extensions::EXTENSION_EVENT_TIMEOUT_MS,
                )
                .await;

            match result {
                Ok(value) => {
                    let display = if value.is_null() || value == serde_json::Value::Null {
                        format!("/{cmd_for_msg} completed.")
                    } else if let Some(s) = value.as_str() {
                        s.to_string()
                    } else {
                        format!("/{cmd_for_msg} completed: {value}")
                    };
                    let _ = event_tx.try_send(PiMsg::ExtensionCommandDone {
                        command: cmd_for_msg,
                        display,
                        is_error: false,
                    });
                }
                Err(err) => {
                    let _ = event_tx.try_send(PiMsg::ExtensionCommandDone {
                        command: cmd_for_msg,
                        display: format!("Extension command error: {err}"),
                        is_error: true,
                    });
                }
            }
        });

        None
    }

    pub(super) fn dispatch_extension_shortcut(&mut self, key_id: &str) -> Option<Cmd> {
        let Some(manager) = &self.extensions else {
            self.status_message = Some("Extensions are disabled".to_string());
            return None;
        };

        let Some(runtime) = manager.runtime() else {
            self.status_message =
                Some("Extension shortcut not available (runtime not enabled)".to_string());
            return None;
        };

        self.agent_state = AgentState::ToolRunning;
        self.current_tool = Some(format!("shortcut:{key_id}"));

        let key_id_owned = key_id.to_string();
        let cwd = self.cwd.display().to_string();
        let event_tx = self.event_tx.clone();
        let runtime_handle = self.runtime_handle.clone();

        let ctx_payload = serde_json::json!({
            "cwd": cwd,
            "hasUI": true,
        });

        let key_for_msg = key_id_owned.clone();
        runtime_handle.spawn(async move {
            let result = runtime
                .execute_shortcut(
                    key_id_owned,
                    std::sync::Arc::new(ctx_payload),
                    crate::extensions::EXTENSION_EVENT_TIMEOUT_MS,
                )
                .await;

            match result {
                Ok(_) => {
                    let display = format!("Shortcut [{key_for_msg}] executed.");
                    let _ = event_tx.try_send(PiMsg::ExtensionCommandDone {
                        command: key_for_msg,
                        display,
                        is_error: false,
                    });
                }
                Err(err) => {
                    let _ = event_tx.try_send(PiMsg::ExtensionCommandDone {
                        command: key_for_msg,
                        display: format!("Shortcut error: {err}"),
                        is_error: true,
                    });
                }
            }
        });

        None
    }

    fn run_next_pending(&mut self) -> Option<Cmd> {
        loop {
            if self.agent_state != AgentState::Idle {
                return None;
            }
            let next = self.pending_inputs.pop_front()?;

            let cmd = match next {
                PendingInput::Text(text) => self.submit_message(&text),
                PendingInput::Content(content) => self.submit_content(content),
            };

            if cmd.is_some() {
                return cmd;
            }
        }
    }

    pub(super) fn queue_input(&mut self, kind: QueuedMessageKind) {
        let raw_text = self.input.value();
        let trimmed = raw_text.trim();
        if trimmed.is_empty() {
            self.status_message = Some("No input to queue".to_string());
            return;
        }

        if let Some((command, _args)) = parse_extension_command(trimmed) {
            if let Some(manager) = &self.extensions {
                if manager.has_command(&command) {
                    self.status_message = Some(format!(
                        "Extension command '/{command}' cannot be queued while busy"
                    ));
                    return;
                }
            }
        }

        let expanded = self.resources.expand_input(trimmed);

        // Track input history
        self.history.push(trimmed.to_string());

        if let Ok(mut queue) = self.message_queue.lock() {
            match kind {
                QueuedMessageKind::Steering => queue.push_steering(expanded),
                QueuedMessageKind::FollowUp => queue.push_follow_up(expanded),
            }
        }

        // Clear input and reset to single-line mode
        self.input.reset();
        self.input_mode = InputMode::SingleLine;
        self.set_input_height(3);

        let label = match kind {
            QueuedMessageKind::Steering => "steering",
            QueuedMessageKind::FollowUp => "follow-up",
        };
        self.status_message = Some(format!("Queued {label} message"));
    }

    pub(super) fn restore_queued_messages_to_editor(&mut self, abort: bool) -> usize {
        let (steering, follow_up) = self
            .message_queue
            .lock()
            .map_or_else(|_| (Vec::new(), Vec::new()), |mut queue| queue.clear_all());
        let mut all = steering;
        all.extend(follow_up);
        if all.is_empty() {
            if abort {
                self.abort_agent();
            }
            return 0;
        }

        let queued_text = all.join("\n\n");
        let current_text = self.input.value();
        let combined = [queued_text, current_text]
            .into_iter()
            .filter(|text| !text.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        self.input.set_value(&combined);
        if combined.contains('\n') {
            self.input_mode = InputMode::MultiLine;
            self.set_input_height(6);
        }
        self.input.focus();

        if abort {
            self.abort_agent();
        }

        all.len()
    }

    fn abort_agent(&self) {
        if let Some(handle) = &self.abort_handle {
            handle.abort();
        }
    }

    #[allow(clippy::too_many_lines)]
    fn submit_content(&mut self, content: Vec<ContentBlock>) -> Option<Cmd> {
        let display = content_blocks_to_text(&content);
        self.submit_content_with_display(content, &display)
    }

    #[allow(clippy::too_many_lines)]
    fn submit_content_with_display(
        &mut self,
        content: Vec<ContentBlock>,
        display: &str,
    ) -> Option<Cmd> {
        if content.is_empty() {
            return None;
        }

        let display_owned = display.to_string();
        if !display_owned.trim().is_empty() {
            self.messages.push(ConversationMessage {
                role: MessageRole::User,
                content: display_owned.clone(),
                thinking: None,
                collapsed: false,
            });
        }

        // Clear input and reset to single-line mode
        self.input.reset();
        self.input_mode = InputMode::SingleLine;
        self.set_input_height(3);

        // Start processing
        self.agent_state = AgentState::Processing;

        // Auto-scroll to bottom when new message is added
        self.scroll_to_bottom();

        let content_for_agent = content;
        let event_tx = self.event_tx.clone();
        let agent = Arc::clone(&self.agent);
        let session = Arc::clone(&self.session);
        let save_enabled = self.save_enabled;
        let extensions = self.extensions.clone();
        let runtime_handle = self.runtime_handle.clone();
        let (abort_handle, abort_signal) = AbortHandle::new();
        self.abort_handle = Some(abort_handle);

        let runtime_handle_for_task = runtime_handle.clone();
        runtime_handle.spawn(async move {
            let mut content_for_agent = content_for_agent;
            if let Some(manager) = extensions.clone() {
                let (text, images) = split_content_blocks_for_input(&content_for_agent);
                match dispatch_input_event(&manager, text, images).await {
                    Ok(InputEventOutcome::Continue { text, images }) => {
                        content_for_agent = build_content_blocks_for_input(&text, &images);
                        let updated = content_blocks_to_text(&content_for_agent);
                        if updated != display_owned {
                            let _ = event_tx.try_send(PiMsg::UpdateLastUserMessage(updated));
                        }
                    }
                    Ok(InputEventOutcome::Block { reason }) => {
                        let _ = event_tx
                            .try_send(PiMsg::UpdateLastUserMessage("[input blocked]".to_string()));
                        let message = reason.unwrap_or_else(|| "Input blocked".to_string());
                        let _ = event_tx.try_send(PiMsg::AgentError(message));
                        return;
                    }
                    Err(err) => {
                        let _ = event_tx.try_send(PiMsg::AgentError(err.to_string()));
                        return;
                    }
                }
                let _ = manager
                    .dispatch_event(ExtensionEventName::BeforeAgentStart, None)
                    .await;
            }

            let cx = Cx::for_request();
            let mut agent_guard =
                match asupersync::sync::OwnedMutexGuard::lock(Arc::clone(&agent), &cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock agent: {err}")));
                        return;
                    }
                };
            let previous_len = agent_guard.messages().len();

            let event_sender = event_tx.clone();
            let extensions = extensions.clone();
            let runtime_handle = runtime_handle_for_task.clone();
            let coalescer = extensions
                .as_ref()
                .map(|m| crate::extensions::EventCoalescer::new(m.clone()));
            let ui_stream_batcher = Arc::new(StdMutex::new(UiStreamDeltaBatcher::new(
                event_sender.clone(),
            )));
            let ui_stream_batcher_for_events = Arc::clone(&ui_stream_batcher);
            let result = agent_guard
                .run_with_content_with_abort(content_for_agent, Some(abort_signal), move |event| {
                    {
                        let mut batcher = match ui_stream_batcher_for_events.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        dispatch_agent_event_to_ui(&event, &mut batcher);
                    }

                    if let Some(coal) = &coalescer {
                        coal.dispatch_agent_event_lazy(&event, &runtime_handle);
                    }
                })
                .await;
            flush_ui_stream_batcher_with_backpressure(&ui_stream_batcher).await;

            let new_messages: Vec<crate::model::Message> =
                agent_guard.messages()[previous_len..].to_vec();
            drop(agent_guard);

            let mut session_guard =
                match asupersync::sync::OwnedMutexGuard::lock(Arc::clone(&session), &cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock session: {err}")));
                        return;
                    }
                };
            for message in new_messages {
                session_guard.append_model_message(message);
            }
            let mut save_error = None;

            if save_enabled {
                if let Err(err) = session_guard.save().await {
                    save_error = Some(format!("Failed to save session: {err}"));
                }
            }
            drop(session_guard);

            if let Some(err) = save_error {
                let _ = event_tx.try_send(PiMsg::AgentError(err));
            }

            if let Err(err) = result {
                let formatted = crate::error_hints::format_error_with_hints(&err);
                let _ = event_tx.try_send(PiMsg::AgentError(formatted));
            }
        });

        None
    }

    /// Submit a message to the agent.
    #[allow(clippy::too_many_lines)]
    pub(super) fn submit_message(&mut self, message: &str) -> Option<Cmd> {
        let message = message.trim();
        if message.is_empty() {
            return None;
        }

        if let Some(active) = self.active_extension_ui.take() {
            match parse_extension_ui_response(&active, message) {
                Ok(response) => {
                    self.send_extension_ui_response(response);
                    self.advance_extension_ui_queue();
                }
                Err(err) => {
                    self.status_message = Some(err);
                    self.active_extension_ui = Some(active);
                }
            }
            self.input.reset();
            self.input.focus();
            return None;
        }

        if let Some(pending) = self.pending_oauth.take() {
            return self.submit_oauth_code(message, pending);
        }

        if let Some((command, exclude_from_context)) = parse_bash_command(message) {
            return self.submit_bash_command(message, command, exclude_from_context);
        }

        // Check for slash commands
        if let Some((cmd, args)) = SlashCommand::parse(message) {
            return self.handle_slash_command(cmd, args);
        }

        if let Some((command, args)) = parse_extension_command(message) {
            if let Some(manager) = &self.extensions {
                if manager.has_command(&command) {
                    return self.dispatch_extension_command(&command, &args);
                }
            }
        }

        let message_owned = message.to_string();
        let (message_without_refs, file_refs) = self.extract_file_references(&message_owned);
        let message_for_agent = if file_refs.is_empty() {
            self.resources.expand_input(&message_owned)
        } else {
            self.resources.expand_input(message_without_refs.trim())
        };

        if !file_refs.is_empty() {
            let auto_resize = self
                .config
                .images
                .as_ref()
                .and_then(|images| images.auto_resize)
                .unwrap_or(true);

            let processed = match process_file_arguments(&file_refs, &self.cwd, auto_resize) {
                Ok(processed) => processed,
                Err(err) => {
                    self.status_message = Some(err.to_string());
                    return None;
                }
            };

            let mut text = processed.text;
            if !message_for_agent.trim().is_empty() {
                text.push_str(&message_for_agent);
            }

            let mut content = Vec::new();
            if !text.trim().is_empty() {
                content.push(ContentBlock::Text(TextContent::new(text)));
            }
            for image in processed.images {
                content.push(ContentBlock::Image(image));
            }

            self.history.push(message_owned.clone());

            let display = content_blocks_to_text(&content);
            return self.submit_content_with_display(content, &display);
        }
        let event_tx = self.event_tx.clone();
        let agent = Arc::clone(&self.agent);
        let session = Arc::clone(&self.session);
        let save_enabled = self.save_enabled;
        let extensions = self.extensions.clone();
        let (abort_handle, abort_signal) = AbortHandle::new();
        self.abort_handle = Some(abort_handle);

        // Add to history
        self.history.push(message_owned.clone());

        // Add user message to display
        self.messages.push(ConversationMessage {
            role: MessageRole::User,
            content: message_for_agent.clone(),
            thinking: None,
            collapsed: false,
        });
        let displayed_message = message_for_agent.clone();

        // Clear input and reset to single-line mode
        self.input.reset();
        self.input_mode = InputMode::SingleLine;
        self.set_input_height(3);

        // Start processing
        self.agent_state = AgentState::Processing;

        // Auto-scroll to bottom when new message is added
        self.scroll_to_bottom();

        let runtime_handle = self.runtime_handle.clone();

        // Spawn async task to run the agent
        let runtime_handle_for_agent = runtime_handle.clone();
        runtime_handle.spawn(async move {
            let mut message_for_agent = message_for_agent;
            let mut input_images = Vec::new();
            if let Some(manager) = extensions.clone() {
                match dispatch_input_event(&manager, message_for_agent.clone(), Vec::new()).await {
                    Ok(InputEventOutcome::Continue { text, images }) => {
                        message_for_agent = text;
                        input_images = images;
                        if message_for_agent != displayed_message {
                            let _ = event_tx
                                .try_send(PiMsg::UpdateLastUserMessage(message_for_agent.clone()));
                        }
                    }
                    Ok(InputEventOutcome::Block { reason }) => {
                        let _ = event_tx
                            .try_send(PiMsg::UpdateLastUserMessage("[input blocked]".to_string()));
                        let message = reason.unwrap_or_else(|| "Input blocked".to_string());
                        let _ = event_tx.try_send(PiMsg::AgentError(message));
                        return;
                    }
                    Err(err) => {
                        let _ = event_tx.try_send(PiMsg::AgentError(err.to_string()));
                        return;
                    }
                }
                let _ = manager
                    .dispatch_event(ExtensionEventName::BeforeAgentStart, None)
                    .await;
            }

            let cx = Cx::for_request();
            let mut agent_guard =
                match asupersync::sync::OwnedMutexGuard::lock(Arc::clone(&agent), &cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock agent: {err}")));
                        return;
                    }
                };
            let previous_len = agent_guard.messages().len();

            let event_sender = event_tx.clone();
            let extensions = extensions.clone();
            let coalescer = extensions
                .as_ref()
                .map(|m| crate::extensions::EventCoalescer::new(m.clone()));
            let ui_stream_batcher = Arc::new(StdMutex::new(UiStreamDeltaBatcher::new(
                event_sender.clone(),
            )));
            let result = if input_images.is_empty() {
                let ui_stream_batcher_for_events = Arc::clone(&ui_stream_batcher);
                agent_guard
                    .run_with_abort(message_for_agent, Some(abort_signal), move |event| {
                        {
                            let mut batcher = match ui_stream_batcher_for_events.lock() {
                                Ok(guard) => guard,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            dispatch_agent_event_to_ui(&event, &mut batcher);
                        }

                        if let Some(coal) = &coalescer {
                            coal.dispatch_agent_event_lazy(&event, &runtime_handle_for_agent);
                        }
                    })
                    .await
            } else {
                let content_for_agent =
                    build_content_blocks_for_input(&message_for_agent, &input_images);
                let ui_stream_batcher_for_events = Arc::clone(&ui_stream_batcher);
                agent_guard
                    .run_with_content_with_abort(
                        content_for_agent,
                        Some(abort_signal),
                        move |event| {
                            {
                                let mut batcher = match ui_stream_batcher_for_events.lock() {
                                    Ok(guard) => guard,
                                    Err(poisoned) => poisoned.into_inner(),
                                };
                                dispatch_agent_event_to_ui(&event, &mut batcher);
                            }

                            if let Some(coal) = &coalescer {
                                coal.dispatch_agent_event_lazy(&event, &runtime_handle_for_agent);
                            }
                        },
                    )
                    .await
            };
            flush_ui_stream_batcher_with_backpressure(&ui_stream_batcher).await;

            let new_messages: Vec<crate::model::Message> =
                agent_guard.messages()[previous_len..].to_vec();
            drop(agent_guard);

            let mut session_guard =
                match asupersync::sync::OwnedMutexGuard::lock(Arc::clone(&session), &cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock session: {err}")));
                        return;
                    }
                };
            for message in new_messages {
                session_guard.append_model_message(message);
            }
            let mut save_error = None;

            if save_enabled {
                if let Err(err) = session_guard.save().await {
                    save_error = Some(format!("Failed to save session: {err}"));
                }
            }
            drop(session_guard);

            if let Some(err) = save_error {
                let _ = event_tx.try_send(PiMsg::AgentError(err));
            }

            if let Err(err) = result {
                let _ = event_tx.try_send(PiMsg::AgentError(err.to_string()));
            }
        });

        None
    }
}

#[cfg(test)]
mod stream_delta_batcher_tests {
    use super::*;

    #[test]
    fn coalesces_adjacent_deltas_of_same_kind() {
        let (tx, rx) = mpsc::channel(8);
        let mut batcher = UiStreamDeltaBatcher::new(tx);
        batcher.flush_interval = std::time::Duration::from_secs(60);
        batcher.last_flush = std::time::Instant::now();

        batcher.push_delta(StreamDeltaKind::Text, "Hel");
        batcher.push_delta(StreamDeltaKind::Text, "lo");
        assert!(rx.try_recv().is_err());

        batcher.flush(true);
        let msg = rx.try_recv().expect("expected coalesced text delta");
        assert!(matches!(msg, PiMsg::TextDelta(text) if text == "Hello"));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn send_immediate_flushes_pending_before_tool_event() {
        let (tx, rx) = mpsc::channel(8);
        let mut batcher = UiStreamDeltaBatcher::new(tx);
        batcher.flush_interval = std::time::Duration::from_secs(60);
        batcher.last_flush = std::time::Instant::now();

        batcher.push_delta(StreamDeltaKind::Text, "partial");
        batcher.send_immediate(PiMsg::ToolStart {
            name: "bash".to_string(),
            tool_id: "t1".to_string(),
        });

        let first = rx.try_recv().expect("expected flushed text delta first");
        let second = rx.try_recv().expect("expected immediate tool start second");
        assert!(matches!(first, PiMsg::TextDelta(text) if text == "partial"));
        assert!(
            matches!(second, PiMsg::ToolStart { name, tool_id } if name == "bash" && tool_id == "t1")
        );
    }

    #[test]
    fn retains_unsent_chunk_when_channel_is_full() {
        let (tx, rx) = mpsc::channel(1);
        let mut batcher = UiStreamDeltaBatcher::new(tx);
        batcher.flush_interval = std::time::Duration::from_secs(60);
        batcher.last_flush = std::time::Instant::now();

        batcher.send_immediate(PiMsg::System("occupy".to_string()));
        batcher.push_delta(StreamDeltaKind::Text, "later");
        batcher.flush(true);
        assert_eq!(batcher.pending_bytes, "later".len());

        let _ = rx.try_recv().expect("expected occupied slot message");
        batcher.flush(true);

        let msg = rx.try_recv().expect("expected retained text delta");
        assert!(matches!(msg, PiMsg::TextDelta(text) if text == "later"));
        assert_eq!(batcher.pending_bytes, 0);
    }

    #[test]
    fn retains_immediate_events_when_channel_is_full() {
        let (tx, rx) = mpsc::channel(1);
        let mut batcher = UiStreamDeltaBatcher::new(tx);
        batcher.flush_interval = std::time::Duration::from_secs(60);
        batcher.last_flush = std::time::Instant::now();

        // Occupy the single slot.
        batcher.send_immediate(PiMsg::System("occupy".to_string()));

        // Queue a delta and a control event while the channel is full.
        batcher.push_delta(StreamDeltaKind::Text, "before-done");
        batcher.send_immediate(PiMsg::AgentDone {
            usage: None,
            stop_reason: StopReason::Stop,
            error_message: None,
        });

        // Nothing should be dropped; queue should still hold both messages.
        assert_eq!(batcher.pending_bytes, "before-done".len());
        assert_eq!(batcher.pending.len(), 2);

        // Free slot and flush repeatedly; ordering must be preserved.
        let _ = rx.try_recv().expect("expected occupied slot message");
        batcher.flush(true);
        let first = rx.try_recv().expect("expected retained text delta");
        assert!(matches!(first, PiMsg::TextDelta(text) if text == "before-done"));

        batcher.flush(true);
        let second = rx.try_recv().expect("expected retained agent_done event");
        assert!(matches!(second, PiMsg::AgentDone { .. }));
    }
}
