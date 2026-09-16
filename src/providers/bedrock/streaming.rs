//! Incremental Bedrock ConverseStream decoding.
//!
//! AWS event-stream frames are binary, not SSE. Validate both IEEE CRC32s
//! before interpreting headers or JSON, and never turn a truncated response
//! into a successful assistant turn. All work belongs to the returned stream;
//! dropping it drops the HTTP body and any partially assembled tool input.

use crate::error::{Error, Result};
use crate::model::{
    AssistantMessage, ContentBlock, RedactedThinkingContent, StopReason, StreamEvent, TextContent,
    ThinkingContent, ToolCall, Usage,
};
use base64::Engine as _;
use futures::{Stream, StreamExt, stream};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::pin::Pin;

pub(super) const CONTENT_TYPE: &str = "application/vnd.amazon.eventstream";
// Local resource budgets, not validation of the service's protocol maxima.
const MAX_BUFFER_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONTENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_BLOCKS: usize = 1024;
type ByteStream = Pin<Box<dyn Stream<Item = std::io::Result<Vec<u8>>> + Send>>;

fn invalid(message: &str) -> Error {
    Error::provider(
        "amazon-bedrock",
        format!("Invalid Bedrock event stream: {message}"),
    )
}

// The table index is bounded to 0..256 before conversion.
#[allow(clippy::cast_possible_truncation)]
const fn crc_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut index = 0;
    while index < table.len() {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

fn crc32(bytes: &[u8]) -> u32 {
    const TABLE: [u32; 256] = crc_table();
    !bytes.iter().fold(u32::MAX, |crc, byte| {
        (crc >> 8) ^ TABLE[((crc ^ u32::from(*byte)) & 0xff) as usize]
    })
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    if count > bytes.len() {
        return Err(invalid("truncated frame header"));
    }
    let (value, rest) = bytes.split_at(count);
    *bytes = rest;
    Ok(value)
}

const fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[derive(Debug)]
struct Frame {
    headers: BTreeMap<String, Option<String>>,
    payload: Vec<u8>,
}

impl Frame {
    fn header(&self, name: &str) -> Result<&str> {
        self.headers
            .get(name)
            .and_then(Option::as_deref)
            .ok_or_else(|| invalid("missing or non-string event control header"))
    }
}

fn decode_headers(mut bytes: &[u8]) -> Result<BTreeMap<String, Option<String>>> {
    let mut headers = BTreeMap::new();
    while !bytes.is_empty() {
        let name_len = usize::from(take(&mut bytes, 1)?[0]);
        if name_len == 0 {
            return Err(invalid("empty event header name"));
        }
        let name = std::str::from_utf8(take(&mut bytes, name_len)?)
            .map_err(|_| invalid("event header name is not UTF-8"))?
            .to_string();
        let kind = take(&mut bytes, 1)?[0];
        let value = match kind {
            0 | 1 => None,
            2 => {
                take(&mut bytes, 1)?;
                None
            }
            3 => {
                take(&mut bytes, 2)?;
                None
            }
            4 => {
                take(&mut bytes, 4)?;
                None
            }
            5 | 8 => {
                take(&mut bytes, 8)?;
                None
            }
            9 => {
                take(&mut bytes, 16)?;
                None
            }
            6 | 7 => {
                let length = take(&mut bytes, 2)?;
                let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
                let value = take(&mut bytes, length)?;
                if kind == 7 {
                    Some(
                        std::str::from_utf8(value)
                            .map_err(|_| invalid("event header value is not UTF-8"))?
                            .to_string(),
                    )
                } else {
                    None
                }
            }
            _ => return Err(invalid("unknown event header type")),
        };
        if headers.insert(name, value).is_some() {
            return Err(invalid("duplicate event header"));
        }
    }
    Ok(headers)
}

#[derive(Default)]
struct Decoder {
    buffer: Vec<u8>,
    consumed: usize,
}

impl Decoder {
    fn push(&mut self, bytes: &[u8]) -> Result<()> {
        let remaining = self.buffer.len() - self.consumed;
        if bytes.len() > MAX_BUFFER_BYTES.saturating_sub(remaining) {
            return Err(invalid("local event-stream buffer budget exceeded"));
        }
        // Compact only when receiving another transport chunk, not once per
        // frame. A coalesced chunk can contain hundreds of tiny delta frames.
        if self.consumed != 0 {
            self.buffer.copy_within(self.consumed.., 0);
            self.buffer.truncate(remaining);
            self.consumed = 0;
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn next(&mut self) -> Result<Option<Frame>> {
        let bytes = &self.buffer[self.consumed..];
        if bytes.len() < 12 {
            return Ok(None);
        }
        // Verify the prelude before trusting either attacker-controlled length.
        if crc32(&bytes[..8]) != read_u32(&bytes[8..12]) {
            return Err(invalid("prelude CRC32 mismatch"));
        }
        let total = usize::try_from(read_u32(&bytes[..4]))
            .map_err(|_| invalid("frame length is not representable"))?;
        let header_len = usize::try_from(read_u32(&bytes[4..8]))
            .map_err(|_| invalid("header length is not representable"))?;
        if total < 16 || header_len > total - 16 {
            return Err(invalid("invalid frame lengths"));
        }
        if total > MAX_BUFFER_BYTES {
            return Err(invalid("local event-stream frame budget exceeded"));
        }
        if bytes.len() < total {
            return Ok(None);
        }
        if crc32(&bytes[..total - 4]) != read_u32(&bytes[total - 4..total]) {
            return Err(invalid("message CRC32 mismatch"));
        }
        let headers = decode_headers(&bytes[12..12 + header_len])?;
        let payload = bytes[12 + header_len..total - 4].to_vec();
        self.consumed += total;
        Ok(Some(Frame { headers, payload }))
    }

    fn finish(&self) -> Result<()> {
        if self.consumed != self.buffer.len() {
            return Err(invalid("unexpected EOF inside an event-stream frame"));
        }
        Ok(())
    }
}

struct OpenBlock {
    index: usize,
    tool_input: String,
    redacted: Vec<u8>,
}

struct MessageState {
    message: AssistantMessage,
    pending: VecDeque<StreamEvent>,
    open: BTreeMap<u64, OpenBlock>,
    seen: BTreeSet<u64>,
    started: bool,
    stopped: bool,
    metadata_seen: bool,
    content_bytes: usize,
}

impl MessageState {
    fn new(model: String, provider: String) -> Self {
        Self {
            message: AssistantMessage {
                api: "bedrock-converse-stream".to_string(),
                model,
                provider,
                timestamp: chrono::Utc::now().timestamp_millis(),
                ..AssistantMessage::default()
            },
            pending: VecDeque::new(),
            open: BTreeMap::new(),
            seen: BTreeSet::new(),
            started: false,
            stopped: false,
            metadata_seen: false,
            content_bytes: 0,
        }
    }

    fn reserve_content(&mut self, length: usize) -> Result<()> {
        self.content_bytes = self.content_bytes.saturating_add(length);
        if self.content_bytes > MAX_CONTENT_BYTES {
            return Err(invalid("local assistant-content budget exceeded"));
        }
        Ok(())
    }

    fn add_block(&mut self, id: u64, content: ContentBlock) -> Result<usize> {
        if self.seen.len() >= MAX_BLOCKS || !self.seen.insert(id) {
            return Err(invalid(
                "duplicate content block or local block budget exceeded",
            ));
        }
        let index = self.message.content.len();
        self.message.content.push(content);
        self.open.insert(
            id,
            OpenBlock {
                index,
                tool_input: String::new(),
                redacted: Vec::new(),
            },
        );
        Ok(index)
    }

    /// The only content-block kind Bedrock opens explicitly is a tool call;
    /// text and thinking blocks are created by their first delta. Split out of
    /// `event` so that dispatcher stays under the line budget.
    fn start_block(&mut self, value: &Value) -> Result<()> {
        let id = block_id(value)?;
        let start = value
            .get("start")
            .ok_or_else(|| invalid("missing block start"))?;
        let tool = start
            .get("toolUse")
            .ok_or_else(|| invalid("unsupported content block start"))?;
        let tool_id = string(tool, "toolUseId")?.to_string();
        let name = string(tool, "name")?.to_string();
        if tool_id.is_empty() || name.is_empty() {
            return Err(invalid("tool block has an empty identity"));
        }
        self.reserve_content(tool_id.len().saturating_add(name.len()))?;
        let index = self.add_block(
            id,
            ContentBlock::ToolCall(ToolCall {
                id: tool_id.clone(),
                name: name.clone(),
                arguments: Value::Null,
                thought_signature: None,
            }),
        )?;
        self.pending.push_back(StreamEvent::ToolCallStart {
            content_index: index,
            id: tool_id,
            name,
        });
        Ok(())
    }

    fn event(&mut self, kind: &str, value: &Value) -> Result<()> {
        if kind == "messageStart" {
            if self.started || string(value, "role")? != "assistant" {
                return Err(invalid("duplicate messageStart or non-assistant role"));
            }
            self.started = true;
            self.pending.push_back(StreamEvent::Start {
                partial: self.message.clone(),
            });
            return Ok(());
        }
        if !self.started {
            return Err(invalid("response event arrived before messageStart"));
        }
        if kind == "metadata" {
            if !self.stopped || self.metadata_seen {
                return Err(invalid(
                    "metadata arrived before messageStop or more than once",
                ));
            }
            let usage = value
                .get("usage")
                .ok_or_else(|| invalid("metadata has no usage"))?;
            let input = token_count(usage, "inputTokens")?;
            let output = token_count(usage, "outputTokens")?;
            let cache_read = token_count(usage, "cacheReadInputTokens")?;
            let cache_write = token_count(usage, "cacheWriteInputTokens")?;
            let total = match usage.get("totalTokens") {
                Some(value) => value
                    .as_u64()
                    .ok_or_else(|| invalid("invalid totalTokens"))?,
                None => input
                    .saturating_add(output)
                    .saturating_add(cache_read)
                    .saturating_add(cache_write),
            };
            self.message.usage = Usage {
                input,
                output,
                cache_read,
                cache_write,
                total_tokens: total,
                ..Usage::default()
            };
            self.metadata_seen = true;
            return Ok(());
        }
        if self.stopped {
            return Err(invalid("content arrived after messageStop"));
        }
        match kind {
            "contentBlockStart" => self.start_block(value)?,
            "contentBlockDelta" => self.delta(value)?,
            "contentBlockStop" => self.end_block(block_id(value)?)?,
            "messageStop" => {
                if !self.open.is_empty() {
                    return Err(invalid(
                        "messageStop arrived with unfinished content blocks",
                    ));
                }
                let reason = string(value, "stopReason")?;
                self.message.stop_reason = match reason {
                    "end_turn" | "stop_sequence" => StopReason::Stop,
                    "tool_use" => StopReason::ToolUse,
                    "max_tokens" | "model_context_window_exceeded" => StopReason::Length,
                    // Unknown terminal outcomes must not authorize tool execution
                    // or be committed as an ordinary successful answer.
                    _ => StopReason::Error,
                };
                if self.message.stop_reason == StopReason::Error {
                    self.message.error_message =
                        Some("Bedrock returned a non-success stop reason".to_string());
                }
                self.stopped = true;
            }
            _ => return Err(invalid("unsupported ConverseStream event type")),
        }
        Ok(())
    }

    fn delta(&mut self, value: &Value) -> Result<()> {
        let id = block_id(value)?;
        let delta = value
            .get("delta")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("missing content delta"))?;
        if delta.len() != 1 {
            return Err(invalid("ambiguous content delta"));
        }
        if let Some(text) = delta.get("text") {
            let text = text
                .as_str()
                .ok_or_else(|| invalid("non-string text delta"))?;
            self.reserve_content(text.len())?;
            let index = if let Some(block) = self.open.get(&id) {
                block.index
            } else {
                let index = self.add_block(id, ContentBlock::Text(TextContent::new("")))?;
                self.pending.push_back(StreamEvent::TextStart {
                    content_index: index,
                });
                index
            };
            let ContentBlock::Text(block) = &mut self.message.content[index] else {
                return Err(invalid("text delta changed the content block type"));
            };
            block.text.push_str(text);
            self.pending.push_back(StreamEvent::TextDelta {
                content_index: index,
                delta: text.to_string(),
            });
        } else if let Some(tool) = delta.get("toolUse") {
            let input = string(tool, "input")?;
            self.reserve_content(input.len())?;
            let block = self
                .open
                .get_mut(&id)
                .ok_or_else(|| invalid("tool delta arrived before tool start"))?;
            if !matches!(self.message.content[block.index], ContentBlock::ToolCall(_)) {
                return Err(invalid("tool delta changed the content block type"));
            }
            block.tool_input.push_str(input);
            self.pending.push_back(StreamEvent::ToolCallDelta {
                content_index: block.index,
                delta: input.to_string(),
            });
        } else if let Some(reasoning) = delta.get("reasoningContent") {
            self.reasoning(id, reasoning)?;
        } else {
            return Err(invalid("unsupported content delta"));
        }
        Ok(())
    }

    fn reasoning(&mut self, id: u64, value: &Value) -> Result<()> {
        let fields = value
            .as_object()
            .ok_or_else(|| invalid("invalid reasoning delta"))?;
        if fields.len() != 1 {
            return Err(invalid("ambiguous reasoning delta"));
        }
        if let Some(encoded) = fields.get("redactedContent") {
            let encoded = encoded
                .as_str()
                .ok_or_else(|| invalid("invalid redacted reasoning"))?;
            self.reserve_content(encoded.len())?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| invalid("invalid redacted reasoning base64"))?;
            let index = if let Some(block) = self.open.get(&id) {
                block.index
            } else {
                self.add_block(
                    id,
                    ContentBlock::RedactedThinking(RedactedThinkingContent {
                        data: String::new(),
                    }),
                )?
            };
            if !matches!(
                self.message.content[index],
                ContentBlock::RedactedThinking(_)
            ) {
                return Err(invalid("redacted reasoning changed the content block type"));
            }
            // Each JSON blob is independently base64 encoded. Concatenating
            // the encoded strings would corrupt padding and replay bytes.
            self.open
                .get_mut(&id)
                .ok_or_else(|| invalid("missing reasoning block"))?
                .redacted
                .extend_from_slice(&bytes);
            return Ok(());
        }
        let (signature, text) = if fields.contains_key("signature") {
            (true, string(value, "signature")?)
        } else {
            (false, string(value, "text")?)
        };
        self.reserve_content(text.len())?;
        let index = if let Some(block) = self.open.get(&id) {
            block.index
        } else {
            let index = self.add_block(
                id,
                ContentBlock::Thinking(ThinkingContent {
                    thinking: String::new(),
                    thinking_signature: None,
                }),
            )?;
            self.pending.push_back(StreamEvent::ThinkingStart {
                content_index: index,
            });
            index
        };
        let ContentBlock::Thinking(block) = &mut self.message.content[index] else {
            return Err(invalid("reasoning delta changed the content block type"));
        };
        if signature {
            block
                .thinking_signature
                .get_or_insert_with(String::new)
                .push_str(text);
        } else {
            block.thinking.push_str(text);
            self.pending.push_back(StreamEvent::ThinkingDelta {
                content_index: index,
                delta: text.to_string(),
            });
        }
        Ok(())
    }

    fn end_block(&mut self, id: u64) -> Result<()> {
        let block = self
            .open
            .remove(&id)
            .ok_or_else(|| invalid("stop for an unopened or closed block"))?;
        let content_index = block.index;
        match &mut self.message.content[content_index] {
            ContentBlock::Text(text) => self.pending.push_back(StreamEvent::TextEnd {
                content_index,
                content: text.text.clone(),
            }),
            ContentBlock::Thinking(thinking) => self.pending.push_back(StreamEvent::ThinkingEnd {
                content_index,
                content: thinking.thinking.clone(),
            }),
            ContentBlock::RedactedThinking(redacted) => {
                redacted.data = base64::engine::general_purpose::STANDARD.encode(block.redacted);
            }
            ContentBlock::ToolCall(tool) => {
                tool.arguments = if block.tool_input.is_empty() {
                    serde_json::json!({})
                } else {
                    serde_json::from_str(&block.tool_input)
                        .map_err(|_| invalid("malformed tool input JSON"))?
                };
                self.pending.push_back(StreamEvent::ToolCallEnd {
                    content_index,
                    tool_call: tool.clone(),
                });
            }
            _ => return Err(invalid("unsupported completed content block")),
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<StreamEvent> {
        if !self.started || !self.stopped || !self.open.is_empty() {
            return Err(invalid("unexpected EOF before a complete messageStop"));
        }
        let message = std::mem::take(&mut self.message);
        Ok(StreamEvent::Done {
            reason: message.stop_reason,
            message,
        })
    }
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing or invalid event field"))
}

fn block_id(value: &Value) -> Result<u64> {
    value
        .get("contentBlockIndex")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("missing or invalid contentBlockIndex"))
}

fn token_count(value: &Value, field: &str) -> Result<u64> {
    value.get(field).map_or(Ok(0), |value| {
        value
            .as_u64()
            .ok_or_else(|| invalid("invalid token usage counter"))
    })
}

fn dispatch(frame: &Frame, state: &mut MessageState, secrets: &[String]) -> Result<()> {
    let message_type = frame.header(":message-type")?;
    if message_type == "error" || message_type == "exception" {
        let (code, message) = if message_type == "error" {
            (
                frame.header(":error-code")?,
                frame.header(":error-message")?.to_string(),
            )
        } else {
            let code = frame.header(":exception-type")?;
            let value: Value = serde_json::from_slice(&frame.payload)
                .map_err(|_| invalid("invalid exception JSON"))?;
            (
                code,
                value
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("stream failed")
                    .to_string(),
            )
        };
        let status = match code {
            "throttlingException" => " (HTTP 429)",
            "internalServerException" => " (HTTP 500)",
            "serviceUnavailableException" => " (HTTP 503)",
            "modelStreamErrorException" => " (HTTP 424)",
            "validationException" => " (HTTP 400)",
            _ => "",
        };
        let details = super::bedrock_error_snippet(&format!("{code}{status}: {message}"), secrets);
        return Err(Error::provider(
            &state.message.provider,
            format!("Bedrock stream exception: {details}"),
        ));
    }
    if message_type != "event" {
        return Err(invalid("unknown event message type"));
    }
    if frame.headers.contains_key(":content-type") {
        let content_type = frame.header(":content-type")?;
        if !content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("application/json")
        {
            return Err(invalid("unexpected event payload content type"));
        }
    }
    let kind = frame.header(":event-type")?;
    let value =
        serde_json::from_slice(&frame.payload).map_err(|_| invalid("invalid event JSON"))?;
    state.event(kind, &value)
}

pub(super) fn from_bytes(
    source: ByteStream,
    model: String,
    provider: String,
    secrets: Vec<String>,
) -> Pin<Box<dyn Stream<Item = Result<StreamEvent>> + Send>> {
    struct State {
        source: Option<ByteStream>,
        decoder: Decoder,
        message: MessageState,
        secrets: Vec<String>,
        finished: bool,
    }
    let state = State {
        source: Some(source),
        decoder: Decoder::default(),
        message: MessageState::new(model, provider),
        secrets,
        finished: false,
    };
    Box::pin(stream::unfold(state, |mut state| async move {
        if state.finished {
            return None;
        }
        loop {
            if let Some(event) = state.message.pending.pop_front() {
                return Some((Ok(event), state));
            }
            let outcome = match state.decoder.next() {
                Ok(Some(frame)) => dispatch(&frame, &mut state.message, &state.secrets),
                Err(error) => Err(error),
                Ok(None) => {
                    let chunk = match state.source.as_mut() {
                        Some(source) => source.next().await,
                        None => None,
                    };
                    match chunk {
                        Some(Ok(bytes)) => state.decoder.push(&bytes),
                        Some(Err(error)) => {
                            let details =
                                super::bedrock_error_snippet(&error.to_string(), &state.secrets);
                            Err(Error::provider(
                                &state.message.message.provider,
                                format!("Bedrock stream transport error: {details}"),
                            ))
                        }
                        None => {
                            state.finished = true;
                            state.source = None;
                            let outcome =
                                state.decoder.finish().and_then(|()| state.message.finish());
                            return Some((outcome, state));
                        }
                    }
                }
            };
            if let Err(error) = outcome {
                // Drop the socket before yielding the terminal error. A caller
                // is not obliged to poll again or immediately drop our stream.
                state.source = None;
                state.finished = true;
                state.message.pending.clear();
                return Some((Err(error), state));
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt as _;
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::task::{Context, Poll};

    fn header(name: &str, value: &str, target: &mut Vec<u8>) {
        target.push(u8::try_from(name.len()).unwrap());
        target.extend_from_slice(name.as_bytes());
        target.push(7);
        target.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        target.extend_from_slice(value.as_bytes());
    }

    fn raw_frame(headers: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(
            &u32::try_from(16 + headers.len() + payload.len())
                .unwrap()
                .to_be_bytes(),
        );
        frame.extend_from_slice(&u32::try_from(headers.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&crc32(&frame).to_be_bytes());
        frame.extend_from_slice(headers);
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&crc32(&frame).to_be_bytes());
        frame
    }

    fn event(kind: &str, payload: &Value) -> Vec<u8> {
        let mut headers = Vec::new();
        header(":message-type", "event", &mut headers);
        header(":event-type", kind, &mut headers);
        header(":content-type", "application/json", &mut headers);
        raw_frame(&headers, &serde_json::to_vec(&payload).unwrap())
    }

    fn start() -> Vec<u8> {
        event("messageStart", &json!({"role": "assistant"}))
    }

    fn stop() -> Vec<u8> {
        event("messageStop", &json!({"stopReason": "end_turn"}))
    }

    fn text() -> Vec<u8> {
        event(
            "contentBlockDelta",
            &json!({"contentBlockIndex": 0, "delta": {"text": "héllo"}}),
        )
    }

    fn block_stop(index: u64) -> Vec<u8> {
        event("contentBlockStop", &json!({"contentBlockIndex": index}))
    }

    fn collect(chunks: Vec<Vec<u8>>) -> Vec<Result<StreamEvent>> {
        futures::executor::block_on(
            from_bytes(
                Box::pin(stream::iter(chunks.into_iter().map(Ok))),
                "model-a".to_string(),
                "provider-a".to_string(),
                Vec::new(),
            )
            .collect(),
        )
    }

    #[test]
    fn crc_uses_ieee_not_castagnoli() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn frames_decode_across_every_transport_split() {
        let frame = text();
        for split in 0..frame.len() {
            let mut decoder = Decoder::default();
            decoder.push(&frame[..split]).unwrap();
            assert!(decoder.next().unwrap().is_none());
            decoder.push(&frame[split..]).unwrap();
            let parsed = decoder.next().unwrap().unwrap();
            assert_eq!(parsed.header(":event-type").unwrap(), "contentBlockDelta");
            let payload: Value = serde_json::from_slice(&parsed.payload).unwrap();
            assert_eq!(payload["delta"]["text"], "héllo");
            assert!(decoder.next().unwrap().is_none());
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn coalesced_frames_and_single_byte_chunks_produce_identical_messages() {
        let bytes = [start(), text(), block_stop(0), stop()].concat();
        for chunks in [
            vec![bytes.clone()],
            bytes.iter().map(|byte| vec![*byte]).collect(),
        ] {
            let result = collect(chunks);
            assert_eq!(result.len(), 5);
            assert!(
                matches!(&result[0], Ok(StreamEvent::Start { partial }) if partial.content.is_empty())
            );
            assert!(
                matches!(&result[2], Ok(StreamEvent::TextDelta { delta, .. }) if delta == "héllo")
            );
            let Ok(StreamEvent::Done { message, .. }) = result.last().unwrap() else {
                panic!("{result:?}")
            };
            assert_eq!(message.provider, "provider-a");
            assert_eq!(message.model, "model-a");
            assert_eq!(message.api, "bedrock-converse-stream");
        }
    }

    #[test]
    fn text_delta_arrives_while_the_response_is_still_open() {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        tx.unbounded_send(Ok([start(), text()].concat())).unwrap();
        let mut output = from_bytes(Box::pin(rx), "m".into(), "p".into(), Vec::new());
        for expected in ["start", "text_start", "delta"] {
            let item = output
                .next()
                .now_or_never()
                .expect("must not wait for the tail")
                .unwrap()
                .unwrap();
            assert!(matches!(
                (expected, item),
                ("start", StreamEvent::Start { .. })
                    | ("text_start", StreamEvent::TextStart { .. })
                    | ("delta", StreamEvent::TextDelta { .. })
            ));
        }
        assert!(output.next().now_or_never().is_none());
        tx.unbounded_send(Ok([block_stop(0), stop()].concat()))
            .unwrap();
        drop(tx);
        let rest = futures::executor::block_on(output.collect::<Vec<_>>());
        assert!(matches!(rest.last(), Some(Ok(StreamEvent::Done { .. }))));
    }

    #[test]
    fn truncated_or_corrupt_frames_never_emit_done() {
        let frame = text();
        for end in 1..frame.len() {
            let result = collect(vec![start(), frame[..end].to_vec()]);
            assert!(result.last().unwrap().is_err(), "truncation at {end}");
            assert!(
                !result
                    .iter()
                    .any(|item| matches!(item, Ok(StreamEvent::Done { .. })))
            );
        }
        for offset in [0, 8, 15, frame.len() - 1] {
            let mut damaged = frame.clone();
            damaged[offset] ^= 1;
            let result = collect(vec![start(), damaged, stop()]);
            assert!(result.last().unwrap().is_err());
        }
        let result = collect(vec![start(), text(), block_stop(0)]);
        assert!(
            result
                .last()
                .unwrap()
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("messageStop")
        );
        let result = collect(vec![start(), stop(), vec![0]]);
        assert!(
            result.last().unwrap().is_err(),
            "partial trailing frame is still corruption"
        );
    }

    #[test]
    fn invalid_lengths_are_rejected_before_waiting_for_the_payload() {
        for (total, header_len) in [(15_u32, 0_u32), (16, 1), (u32::MAX, 0)] {
            let mut prelude = Vec::new();
            prelude.extend_from_slice(&total.to_be_bytes());
            prelude.extend_from_slice(&header_len.to_be_bytes());
            prelude.extend_from_slice(&crc32(&prelude).to_be_bytes());
            let mut decoder = Decoder::default();
            decoder.push(&prelude).unwrap();
            assert!(decoder.next().is_err());
        }
    }

    #[test]
    fn typed_headers_are_skipped_but_duplicates_and_bad_encodings_are_rejected() {
        let mut headers = Vec::new();
        for (kind, length) in [
            (0, 0),
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 4),
            (5, 8),
            (8, 8),
            (9, 16),
        ] {
            headers.extend_from_slice(&[1, b'a' + kind, kind]);
            headers.extend(std::iter::repeat_n(0, length));
        }
        headers.extend_from_slice(&[1, b'z', 6, 0, 2, 0, 255]);
        header(":message-type", "event", &mut headers);
        let parsed = decode_headers(&headers).unwrap();
        assert_eq!(parsed[":message-type"].as_deref(), Some("event"));
        header(":message-type", "exception", &mut headers);
        assert!(decode_headers(&headers).is_err());
        for bad in [
            vec![0],
            vec![1, 255, 0],
            vec![1, b'x', 7, 0, 1, 255],
            vec![1, b'x', 255],
        ] {
            assert!(decode_headers(&bad).is_err());
        }
    }

    #[test]
    fn tool_arguments_are_assembled_and_validated_before_tool_end() {
        let result = collect(vec![
            start(),
            event(
                "contentBlockStart",
                &json!({"contentBlockIndex": 7, "start": {"toolUse": {"toolUseId": "call-a", "name": "read"}}}),
            ),
            event(
                "contentBlockDelta",
                &json!({"contentBlockIndex": 7, "delta": {"toolUse": {"input": "{\"path\":"}}}),
            ),
            event(
                "contentBlockDelta",
                &json!({"contentBlockIndex": 7, "delta": {"toolUse": {"input": "\"a.txt\"}"}}}),
            ),
            block_stop(7),
            event("messageStop", &json!({"stopReason": "tool_use"})),
        ]);
        assert!(result.iter().all(Result::is_ok), "{result:?}");
        let tool = result
            .iter()
            .find_map(|item| match item {
                Ok(StreamEvent::ToolCallEnd {
                    content_index,
                    tool_call,
                }) => {
                    assert_eq!(*content_index, 0);
                    Some(tool_call)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(tool.id, "call-a");
        assert_eq!(tool.arguments, json!({"path": "a.txt"}));
        assert!(matches!(
            result.last(),
            Some(Ok(StreamEvent::Done {
                reason: StopReason::ToolUse,
                ..
            }))
        ));

        let result = collect(vec![
            start(),
            event(
                "contentBlockStart",
                &json!({"contentBlockIndex": 0, "start": {"toolUse": {"toolUseId": "a", "name": "read"}}}),
            ),
            event(
                "contentBlockDelta",
                &json!({"contentBlockIndex": 0, "delta": {"toolUse": {"input": "{"}}}),
            ),
            block_stop(0),
            stop(),
        ]);
        assert!(result.last().unwrap().is_err());
        assert!(
            !result
                .iter()
                .any(|item| matches!(item, Ok(StreamEvent::ToolCallEnd { .. })))
        );
    }

    #[test]
    fn reasoning_and_redacted_bytes_survive_without_becoming_visible_text() {
        let result = collect(vec![
            start(),
            event(
                "contentBlockDelta",
                &json!({"contentBlockIndex": 0, "delta": {"reasoningContent": {"text": "Think."}}}),
            ),
            event(
                "contentBlockDelta",
                &json!({"contentBlockIndex": 0, "delta": {"reasoningContent": {"signature": "sig-"}}}),
            ),
            event(
                "contentBlockDelta",
                &json!({"contentBlockIndex": 0, "delta": {"reasoningContent": {"signature": "part2"}}}),
            ),
            block_stop(0),
            event(
                "contentBlockDelta",
                &json!({"contentBlockIndex": 1, "delta": {"reasoningContent": {"redactedContent": "AA=="}}}),
            ),
            event(
                "contentBlockDelta",
                &json!({"contentBlockIndex": 1, "delta": {"reasoningContent": {"redactedContent": "AQ=="}}}),
            ),
            block_stop(1),
            stop(),
        ]);
        assert!(result.iter().all(Result::is_ok), "{result:?}");
        assert!(
            !result
                .iter()
                .any(|item| matches!(item, Ok(StreamEvent::TextDelta { .. })))
        );
        let Ok(StreamEvent::Done { message, .. }) = result.last().unwrap() else {
            panic!("{result:?}")
        };
        let ContentBlock::Thinking(thinking) = &message.content[0] else {
            panic!()
        };
        assert_eq!(thinking.thinking, "Think.");
        assert_eq!(thinking.thinking_signature.as_deref(), Some("sig-part2"));
        let ContentBlock::RedactedThinking(redacted) = &message.content[1] else {
            panic!()
        };
        assert_eq!(redacted.data, "AAE=");
    }

    #[test]
    fn metadata_after_message_stop_is_included_in_done() {
        let result = collect(vec![
            start(),
            stop(),
            event(
                "metadata",
                &json!({"usage": {
                    "inputTokens": 7, "outputTokens": 3, "cacheReadInputTokens": 20,
                    "cacheWriteInputTokens": 5, "totalTokens": 35
                }}),
            ),
        ]);
        let Ok(StreamEvent::Done { message, .. }) = result.last().unwrap() else {
            panic!("{result:?}")
        };
        assert_eq!(message.usage.input, 7);
        assert_eq!(message.usage.output, 3);
        assert_eq!(message.usage.cache_read, 20);
        assert_eq!(message.usage.cache_write, 5);
        assert_eq!(message.usage.total_tokens, 35);
    }

    #[test]
    fn invalid_lifecycle_cannot_be_committed_as_success() {
        for frames in [
            vec![text(), stop()],
            vec![start(), start()],
            vec![start(), text(), stop()],
            vec![start(), block_stop(0)],
            vec![start(), text(), block_stop(0), text()],
            vec![start(), stop(), text()],
            vec![start(), event("metadata", &json!({"usage": {}}))],
        ] {
            let result = collect(frames);
            assert!(result.last().unwrap().is_err(), "{result:?}");
        }
    }

    #[test]
    fn streamed_exceptions_are_redacted_and_terminal() {
        let mut headers = Vec::new();
        header(":message-type", "exception", &mut headers);
        header(":exception-type", "throttlingException", &mut headers);
        let frame = raw_frame(&headers, br#"{"message":"slow down secret-key-canary"}"#);
        let result: Vec<_> = futures::executor::block_on(
            from_bytes(
                Box::pin(stream::iter(vec![Ok(start()), Ok(frame), Ok(stop())])),
                "m".into(),
                "custom-bedrock".into(),
                vec!["secret-key-canary".into()],
            )
            .collect(),
        );
        assert_eq!(result.len(), 2);
        let error = result[1].as_ref().unwrap_err().to_string();
        assert!(error.contains("HTTP 429"), "{error}");
        assert!(!error.contains("secret-key-canary"), "{error}");
        assert!(error.contains("custom-bedrock"), "{error}");
    }

    struct DropProbe {
        frame: Option<Vec<u8>>,
        dropped: Arc<AtomicBool>,
    }

    impl Stream for DropProbe {
        type Item = std::io::Result<Vec<u8>>;
        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.frame
                .take()
                .map_or(Poll::Pending, |frame| Poll::Ready(Some(Ok(frame))))
        }
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn malformed_stream_releases_transport_before_yielding_error() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut output = from_bytes(
            Box::pin(DropProbe {
                frame: Some(vec![0; 12]),
                dropped: Arc::clone(&dropped),
            }),
            "m".into(),
            "p".into(),
            Vec::new(),
        );
        assert!(output.next().now_or_never().unwrap().unwrap().is_err());
        assert!(dropped.load(Ordering::SeqCst));
        assert!(output.next().now_or_never().unwrap().is_none());
    }

    #[test]
    fn dropping_a_pending_stream_releases_transport() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut output = from_bytes(
            Box::pin(DropProbe {
                frame: None,
                dropped: Arc::clone(&dropped),
            }),
            "m".into(),
            "p".into(),
            Vec::new(),
        );
        assert!(output.next().now_or_never().is_none());
        drop(output);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
