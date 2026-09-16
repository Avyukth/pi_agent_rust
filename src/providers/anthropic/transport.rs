//! Transport adapters sharing the Anthropic message builder and SSE state machine.
//!
//! Vertex selects the model in its URL, puts the API version in the body, and
//! uses Google authorization. It must never enter the first-party OAuth lane.

use super::{AnthropicProvider, StreamState};
use crate::error::{Error, Result};
use crate::http::client::Response;
use crate::model::StreamEvent;
use crate::provider::{Context, Provider, StreamOptions};
use crate::sse::SseStream;
use futures::StreamExt;
use futures::stream::{self, Stream};
use serde_json::{Value, json};
use std::pin::Pin;

const VERTEX_ANTHROPIC_VERSION: &str = "vertex-2023-10-16";

pub(crate) type EventStream = Pin<Box<dyn Stream<Item = Result<StreamEvent>> + Send>>;

/// Restore host-owned transport fields after an extension rewrites the body.
/// The endpoint, not a body field, chooses the Vertex model.
fn vertex_request(value: Value) -> std::result::Result<Value, String> {
    let mut value = super::super::validate_streamed_json_rewrite(
        value,
        &[],
        &["messages"],
        &[
            ("stream", Value::Bool(true)),
            ("anthropic_version", json!(VERTEX_ANTHROPIC_VERSION)),
        ],
    )?;
    if !value
        .get("max_tokens")
        .and_then(Value::as_u64)
        .is_some_and(|n| n > 0)
    {
        return Err("Vertex Anthropic request requires a positive max_tokens".to_string());
    }
    // The shared validator guarantees an object. Do not remove anything else:
    // tool schemas, thinking, cache markers and future extension fields survive.
    if let Some(object) = value.as_object_mut() {
        object.remove("model");
    }
    Ok(value)
}

impl AnthropicProvider {
    /// Send an Anthropic Messages request over an explicitly selected Vertex
    /// endpoint. Authorization is resolved by VertexProvider; there is no
    /// Anthropic API-key/environment fallback and no Claude OAuth beta headers.
    pub(crate) async fn stream_vertex(
        &self,
        context: &Context<'_>,
        options: &StreamOptions,
        authorization: &str,
    ) -> Result<EventStream> {
        let original = vertex_request(serde_json::to_value(self.build_request(context, options))?)
            .map_err(|message| Error::provider(self.name(), message))?;
        let rewritten = super::super::offer_before_provider_request(
            options,
            self.name(),
            "google-vertex",
            self.model_id(),
            &self.base_url,
            &original,
            vertex_request,
        )
        .await;
        let body = rewritten.as_ref().unwrap_or(&original);
        let mut request = self
            .client
            .post(&self.base_url)
            .header("Accept", "text/event-stream");
        if let Some(headers) = self
            .compat
            .as_ref()
            .and_then(|compat| compat.custom_headers.as_ref())
        {
            request = super::super::apply_headers_ignoring_blank_auth_overrides(
                request,
                headers,
                &["authorization"],
            );
        }
        request = super::super::apply_headers_ignoring_blank_auth_overrides(
            request,
            &options.headers,
            &["authorization"],
        );
        // Install the already resolved winner last, including when an empty
        // request header must not erase a non-empty compatibility override.
        let request = request.header("Authorization", authorization).json(body)?;
        let response = Box::pin(request.send()).await?;
        let status = response.status();
        if !(200..300).contains(&status) {
            let body = response
                .text()
                .await
                .unwrap_or_else(|error| format!("<failed to read body: {error}>"));
            return Err(Error::provider(
                self.name(),
                format!("Vertex AI Anthropic API error (HTTP {status}): {body}"),
            ));
        }
        Ok(response_stream(
            response,
            self.model.clone(),
            "google-vertex".to_string(),
            self.provider.clone(),
        ))
    }
}

/// Both native Anthropic and Vertex use this exact stream driver. Owning the
/// response keeps socket cleanup tied to the stream's lifetime (including drop).
pub(super) fn response_stream(
    response: Response,
    model: String,
    api: String,
    provider: String,
) -> EventStream {
    let event_source = SseStream::new(response.bytes_stream());
    Box::pin(stream::unfold(
        StreamState::new(event_source, model, api, provider),
        |mut state| async move {
            if state.done {
                return None;
            }
            loop {
                match state.event_source.next().await {
                    Some(Ok(msg)) => {
                        state.transient_error_count = 0;
                        if msg.event == "ping" {
                            continue;
                        }
                        match state.process_event(&msg.data) {
                            Ok(Some(event)) => {
                                if matches!(
                                    &event,
                                    StreamEvent::Done { .. } | StreamEvent::Error { .. }
                                ) {
                                    state.done = true;
                                }
                                return Some((Ok(event), state));
                            }
                            Ok(None) => {}
                            Err(error) => {
                                state.done = true;
                                return Some((Err(error), state));
                            }
                        }
                    }
                    Some(Err(error)) => {
                        const MAX_CONSECUTIVE_TRANSIENT_ERRORS: usize = 5;
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WriteZero
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                        ) {
                            state.transient_error_count += 1;
                            if state.transient_error_count <= MAX_CONSECUTIVE_TRANSIENT_ERRORS {
                                tracing::warn!(
                                    kind = ?error.kind(),
                                    count = state.transient_error_count,
                                    "Transient error in SSE stream, continuing"
                                );
                                continue;
                            }
                        }
                        state.done = true;
                        return Some((Err(Error::sse(&error)), state));
                    }
                    None => {
                        state.done = true;
                        return Some((
                            Err(Error::api(
                                "Anthropic stream ended before message_stop (unexpected EOF)",
                            )),
                            state,
                        ));
                    }
                }
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertex_wire_format_keeps_messages_tools_thinking_and_cache() {
        let original = json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 16000,
            "stream": false,
            "anthropic_version": "wrong-version",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hello", "cache_control": {"type": "ephemeral"}}]}],
            "tools": [{"name": "read", "input_schema": {"type": "object"}}],
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": "high"},
            "metadata": {"user_id": "test"}
        });
        let body = vertex_request(original.clone()).unwrap();
        assert!(body.get("model").is_none());
        assert_eq!(body["anthropic_version"], VERTEX_ANTHROPIC_VERSION);
        assert_eq!(body["stream"], true);
        for key in [
            "messages", "tools", "thinking", "output_config", "metadata", "max_tokens",
        ] {
            assert_eq!(body[key], original[key], "{key}");
        }
    }

    #[test]
    fn malformed_vertex_rewrites_are_rejected_for_fail_open_fallback() {
        for body in [
            json!(null),
            json!([]),
            json!({"messages": "wrong", "max_tokens": 1}),
            json!({"messages": [], "max_tokens": 0}),
            json!({"messages": [], "max_tokens": -1}),
            json!({"messages": [], "max_tokens": "100"}),
            json!({"messages": []}),
        ] {
            assert!(vertex_request(body).is_err());
        }
    }
}
