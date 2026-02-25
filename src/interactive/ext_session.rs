use super::conversation::extension_model_from_entry;
use super::*;

#[derive(Clone)]
pub(super) struct InteractiveExtensionHostActions {
    pub(super) session: Arc<Mutex<Session>>,
    pub(super) agent: Arc<Mutex<Agent>>,
    pub(super) event_tx: mpsc::Sender<PiMsg>,
    pub(super) extension_streaming: Arc<AtomicBool>,
    pub(super) user_queue: Arc<StdMutex<InteractiveMessageQueue>>,
    pub(super) injected_queue: Arc<StdMutex<InjectedMessageQueue>>,
}

impl InteractiveExtensionHostActions {
    #[allow(clippy::unnecessary_wraps)]
    fn queue_custom_message(
        &self,
        deliver_as: Option<ExtensionDeliverAs>,
        message: ModelMessage,
    ) -> crate::error::Result<()> {
        let deliver_as = deliver_as.unwrap_or(ExtensionDeliverAs::Steer);
        let kind = match deliver_as {
            ExtensionDeliverAs::FollowUp => QueuedMessageKind::FollowUp,
            ExtensionDeliverAs::Steer | ExtensionDeliverAs::NextTurn => QueuedMessageKind::Steering,
        };
        let Ok(mut queue) = self.injected_queue.lock() else {
            return Ok(());
        };
        match kind {
            QueuedMessageKind::Steering => queue.push_steering(message),
            QueuedMessageKind::FollowUp => queue.push_follow_up(message),
        }
        Ok(())
    }

    async fn append_to_session(&self, message: ModelMessage) -> crate::error::Result<()> {
        let cx = Cx::for_request();
        let mut session_guard = self
            .session
            .lock(&cx)
            .await
            .map_err(|e| crate::error::Error::session(e.to_string()))?;
        session_guard.append_model_message(message);
        Ok(())
    }
}

#[async_trait]
impl ExtensionHostActions for InteractiveExtensionHostActions {
    async fn send_message(&self, message: ExtensionSendMessage) -> crate::error::Result<()> {
        let custom_message = ModelMessage::Custom(CustomMessage {
            content: message.content,
            custom_type: message.custom_type,
            display: message.display,
            details: message.details,
            timestamp: Utc::now().timestamp_millis(),
        });

        let is_streaming = self.extension_streaming.load(Ordering::SeqCst);
        if is_streaming {
            // Queue into the agent loop; session persistence happens when the message is delivered.
            self.queue_custom_message(message.deliver_as, custom_message.clone())?;
            if let ModelMessage::Custom(custom) = &custom_message {
                if custom.display {
                    let _ = self
                        .event_tx
                        .try_send(PiMsg::SystemNote(custom.content.clone()));
                }
            }
            return Ok(());
        }

        // Agent is idle: persist immediately and update in-memory history so it affects the next run.
        // Triggering a new turn for custom messages is handled separately and may be implemented later.
        let _ = message.trigger_turn;
        self.append_to_session(custom_message.clone()).await?;

        let cx = Cx::for_request();
        if let Ok(mut agent_guard) = self.agent.lock(&cx).await {
            agent_guard.add_message(custom_message.clone());
        }

        if let ModelMessage::Custom(custom) = &custom_message {
            if custom.display {
                let _ = self
                    .event_tx
                    .try_send(PiMsg::SystemNote(custom.content.clone()));
            }
        }

        Ok(())
    }

    async fn send_user_message(
        &self,
        message: ExtensionSendUserMessage,
    ) -> crate::error::Result<()> {
        let is_streaming = self.extension_streaming.load(Ordering::SeqCst);
        if is_streaming {
            let deliver_as = message.deliver_as.unwrap_or(ExtensionDeliverAs::Steer);
            let Ok(mut queue) = self.user_queue.lock() else {
                return Ok(());
            };
            match deliver_as {
                ExtensionDeliverAs::FollowUp => queue.push_follow_up(message.text),
                ExtensionDeliverAs::Steer | ExtensionDeliverAs::NextTurn => {
                    queue.push_steering(message.text);
                }
            }
            return Ok(());
        }

        let _ = self
            .event_tx
            .try_send(PiMsg::EnqueuePendingInput(PendingInput::Text(message.text)));
        Ok(())
    }
}

pub(super) struct InteractiveExtensionSession {
    pub(super) session: Arc<Mutex<Session>>,
    pub(super) model_entry: Arc<StdMutex<ModelEntry>>,
    pub(super) is_streaming: Arc<AtomicBool>,
    pub(super) is_compacting: Arc<AtomicBool>,
    pub(super) config: Config,
    pub(super) save_enabled: bool,
}

#[async_trait]
impl ExtensionSession for InteractiveExtensionSession {
    async fn get_state(&self) -> Value {
        let model = {
            let guard = self
                .model_entry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            extension_model_from_entry(&guard)
        };

        let cx = Cx::for_request();
        let (
            session_file,
            session_id,
            session_name,
            message_count,
            thinking_level,
            durability_mode,
            autosave_pending_mutations,
            autosave_max_pending_mutations,
            autosave_flush_failed_count,
            autosave_backpressure,
            persistence_status,
        ) = self.session.lock(&cx).await.map_or_else(
            |_| {
                (
                    None,
                    String::new(),
                    None,
                    0,
                    "off".to_string(),
                    "balanced".to_string(),
                    0usize,
                    0usize,
                    0u64,
                    false,
                    "unknown".to_string(),
                )
            },
            |guard| {
                let message_count = guard
                    .entries_for_current_path()
                    .iter()
                    .filter(|entry| matches!(entry, SessionEntry::Message(_)))
                    .count();
                let session_name = guard.get_name();
                let thinking_level = guard
                    .header
                    .thinking_level
                    .clone()
                    .unwrap_or_else(|| "off".to_string());
                let autosave_metrics = guard.autosave_metrics();
                let durability_mode = guard.autosave_durability_mode().as_str().to_string();
                let autosave_backpressure = autosave_metrics.max_pending_mutations > 0
                    && autosave_metrics.pending_mutations >= autosave_metrics.max_pending_mutations;
                let persistence_status = if autosave_metrics.flush_failed > 0 {
                    "degraded"
                } else if autosave_backpressure {
                    "backpressure"
                } else if autosave_metrics.pending_mutations > 0 {
                    "draining"
                } else {
                    "healthy"
                }
                .to_string();
                (
                    guard.path.as_ref().map(|p| p.display().to_string()),
                    guard.header.id.clone(),
                    session_name,
                    message_count,
                    thinking_level,
                    durability_mode,
                    autosave_metrics.pending_mutations,
                    autosave_metrics.max_pending_mutations,
                    autosave_metrics.flush_failed,
                    autosave_backpressure,
                    persistence_status,
                )
            },
        );

        json!({
            "model": model,
            "thinkingLevel": thinking_level,
            "isStreaming": self.is_streaming.load(Ordering::SeqCst),
            "isCompacting": self.is_compacting.load(Ordering::SeqCst),
            "steeringMode": "one-at-a-time",
            "followUpMode": "one-at-a-time",
            "sessionFile": session_file,
            "sessionId": session_id,
            "sessionName": session_name,
            "autoCompactionEnabled": self.config.compaction_enabled(),
            "messageCount": message_count,
            "pendingMessageCount": autosave_pending_mutations,
            "durabilityMode": durability_mode,
            "autosavePendingMutations": autosave_pending_mutations,
            "autosaveMaxPendingMutations": autosave_max_pending_mutations,
            "autosaveFlushFailedCount": autosave_flush_failed_count,
            "autosaveBackpressure": autosave_backpressure,
            "persistenceStatus": persistence_status,
        })
    }

    async fn get_messages(&self) -> Vec<SessionMessage> {
        let cx = Cx::for_request();
        let Ok(guard) = self.session.lock(&cx).await else {
            return Vec::new();
        };
        guard
            .entries_for_current_path()
            .iter()
            .filter_map(|entry| match entry {
                SessionEntry::Message(msg) => match msg.message {
                    SessionMessage::User { .. }
                    | SessionMessage::Assistant { .. }
                    | SessionMessage::ToolResult { .. }
                    | SessionMessage::BashExecution { .. } => Some(msg.message.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    async fn get_entries(&self) -> Vec<Value> {
        // Spec §3.1: return ALL session entries (entire session file), append order.
        let cx = Cx::for_request();
        let Ok(guard) = self.session.lock(&cx).await else {
            return Vec::new();
        };
        guard
            .entries
            .iter()
            .filter_map(|entry| serde_json::to_value(entry).ok())
            .collect()
    }

    async fn get_branch(&self) -> Vec<Value> {
        // Spec §3.2: return current path from root to leaf.
        let cx = Cx::for_request();
        let Ok(guard) = self.session.lock(&cx).await else {
            return Vec::new();
        };
        guard
            .entries_for_current_path()
            .iter()
            .filter_map(|entry| serde_json::to_value(*entry).ok())
            .collect()
    }

    async fn set_name(&self, name: String) -> crate::error::Result<()> {
        let cx = Cx::for_request();
        let mut guard =
            self.session.lock(&cx).await.map_err(|err| {
                crate::error::Error::session(format!("session lock failed: {err}"))
            })?;
        guard.set_name(&name);
        if self.save_enabled {
            guard.save().await?;
        }
        Ok(())
    }

    async fn append_message(&self, message: SessionMessage) -> crate::error::Result<()> {
        let cx = Cx::for_request();
        let mut guard =
            self.session.lock(&cx).await.map_err(|err| {
                crate::error::Error::session(format!("session lock failed: {err}"))
            })?;
        guard.append_message(message);
        if self.save_enabled {
            guard.save().await?;
        }
        Ok(())
    }

    async fn append_custom_entry(
        &self,
        custom_type: String,
        data: Option<Value>,
    ) -> crate::error::Result<()> {
        if custom_type.trim().is_empty() {
            return Err(crate::error::Error::validation(
                "customType must not be empty",
            ));
        }
        let cx = Cx::for_request();
        let mut guard =
            self.session.lock(&cx).await.map_err(|err| {
                crate::error::Error::session(format!("session lock failed: {err}"))
            })?;
        guard.append_custom_entry(custom_type, data);
        if self.save_enabled {
            guard.save().await?;
        }
        Ok(())
    }

    async fn set_model(&self, provider: String, model_id: String) -> crate::error::Result<()> {
        let cx = Cx::for_request();
        let mut guard =
            self.session.lock(&cx).await.map_err(|err| {
                crate::error::Error::session(format!("session lock failed: {err}"))
            })?;
        guard.append_model_change(provider.clone(), model_id.clone());
        guard.set_model_header(Some(provider), Some(model_id), None);
        if self.save_enabled {
            guard.save().await?;
        }
        Ok(())
    }

    async fn get_model(&self) -> (Option<String>, Option<String>) {
        let cx = Cx::for_request();
        let Ok(guard) = self.session.lock(&cx).await else {
            return (None, None);
        };
        (guard.header.provider.clone(), guard.header.model_id.clone())
    }

    async fn set_thinking_level(&self, level: String) -> crate::error::Result<()> {
        let cx = Cx::for_request();
        let mut guard =
            self.session.lock(&cx).await.map_err(|err| {
                crate::error::Error::session(format!("session lock failed: {err}"))
            })?;
        guard.append_thinking_level_change(level.clone());
        guard.set_model_header(None, None, Some(level));
        if self.save_enabled {
            guard.save().await?;
        }
        Ok(())
    }

    async fn get_thinking_level(&self) -> Option<String> {
        let cx = Cx::for_request();
        let Ok(guard) = self.session.lock(&cx).await else {
            return None;
        };
        guard.header.thinking_level.clone()
    }

    async fn set_label(
        &self,
        target_id: String,
        label: Option<String>,
    ) -> crate::error::Result<()> {
        let cx = Cx::for_request();
        let mut guard =
            self.session.lock(&cx).await.map_err(|err| {
                crate::error::Error::session(format!("session lock failed: {err}"))
            })?;
        if guard.add_label(&target_id, label).is_none() {
            return Err(crate::error::Error::validation(format!(
                "target entry '{target_id}' not found in session"
            )));
        }
        if self.save_enabled {
            guard.save().await?;
        }
        Ok(())
    }
}

pub fn format_extension_ui_prompt(request: &ExtensionUiRequest) -> String {
    let title = request
        .payload
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Extension");
    let message = request
        .payload
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("");

    // Show provenance: which extension is making this request.
    let provenance = request
        .extension_id
        .as_deref()
        .or_else(|| request.payload.get("extension_id").and_then(Value::as_str))
        .unwrap_or("unknown");

    match request.method.as_str() {
        "confirm" => {
            format!("[{provenance}] confirm: {title}\n{message}\n\nEnter yes/no, or 'cancel'.")
        }
        "select" => {
            let options = request
                .payload
                .get("options")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            let mut out = String::new();
            let _ = writeln!(&mut out, "[{provenance}] select: {title}");
            if !message.trim().is_empty() {
                let _ = writeln!(&mut out, "{message}");
            }
            for (idx, opt) in options.iter().enumerate() {
                let label = opt
                    .get("label")
                    .and_then(Value::as_str)
                    .or_else(|| opt.get("value").and_then(Value::as_str))
                    .or_else(|| opt.as_str())
                    .unwrap_or("");
                let _ = writeln!(&mut out, "  {}) {label}", idx + 1);
            }
            out.push_str("\nEnter a number, label, or 'cancel'.");
            out
        }
        "input" => format!("[{provenance}] input: {title}\n{message}"),
        "editor" => format!("[{provenance}] editor: {title}\n{message}"),
        _ => format!("[{provenance}] {title} {message}"),
    }
}

pub fn parse_extension_ui_response(
    request: &ExtensionUiRequest,
    input: &str,
) -> Result<ExtensionUiResponse, String> {
    let trimmed = input.trim();

    if trimmed.eq_ignore_ascii_case("cancel") || trimmed.eq_ignore_ascii_case("c") {
        return Ok(ExtensionUiResponse {
            id: request.id.clone(),
            value: None,
            cancelled: true,
        });
    }

    match request.method.as_str() {
        "confirm" => {
            let value = match trimmed.to_lowercase().as_str() {
                "y" | "yes" | "true" | "1" => true,
                "n" | "no" | "false" | "0" => false,
                _ => {
                    return Err("Invalid confirmation. Enter yes/no, or 'cancel'.".to_string());
                }
            };
            Ok(ExtensionUiResponse {
                id: request.id.clone(),
                value: Some(Value::Bool(value)),
                cancelled: false,
            })
        }
        "select" => {
            let options = request
                .payload
                .get("options")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    "Invalid selection. Enter a number, label, or 'cancel'.".to_string()
                })?;

            if let Ok(index) = trimmed.parse::<usize>() {
                if index > 0 && index <= options.len() {
                    let chosen = &options[index - 1];
                    let value = chosen
                        .get("value")
                        .cloned()
                        .or_else(|| chosen.get("label").cloned())
                        .or_else(|| chosen.as_str().map(|s| Value::String(s.to_string())));
                    return Ok(ExtensionUiResponse {
                        id: request.id.clone(),
                        value,
                        cancelled: false,
                    });
                }
            }

            let lowered = trimmed.to_lowercase();
            for option in options {
                if let Some(value_str) = option.as_str() {
                    if value_str.to_lowercase() == lowered {
                        return Ok(ExtensionUiResponse {
                            id: request.id.clone(),
                            value: Some(Value::String(value_str.to_string())),
                            cancelled: false,
                        });
                    }
                }

                let label = option.get("label").and_then(Value::as_str).unwrap_or("");
                if !label.is_empty() && label.to_lowercase() == lowered {
                    let value = option.get("value").cloned().or_else(|| {
                        option
                            .get("label")
                            .and_then(Value::as_str)
                            .map(|s| Value::String(s.to_string()))
                    });
                    return Ok(ExtensionUiResponse {
                        id: request.id.clone(),
                        value,
                        cancelled: false,
                    });
                }

                if let Some(value_str) = option.get("value").and_then(Value::as_str) {
                    if value_str.to_lowercase() == lowered {
                        return Ok(ExtensionUiResponse {
                            id: request.id.clone(),
                            value: Some(Value::String(value_str.to_string())),
                            cancelled: false,
                        });
                    }
                }
            }

            Err("Invalid selection. Enter a number, label, or 'cancel'.".to_string())
        }
        _ => Ok(ExtensionUiResponse {
            id: request.id.clone(),
            value: Some(Value::String(input.to_string())),
            cancelled: false,
        }),
    }
}
