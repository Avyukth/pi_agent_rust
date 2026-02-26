use std::collections::BTreeMap;

use memchr::memchr;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_SOCKET_FRAME_BYTES: usize = 1024 * 1024;
pub const PROTOCOL_VERSION_V1: u16 = 1;
pub const PROTOCOL_MIN_SUPPORTED: u16 = PROTOCOL_VERSION_V1;
pub const PROTOCOL_MAX_SUPPORTED: u16 = PROTOCOL_VERSION_V1;

#[derive(Debug, Error)]
pub enum FrameCodecError {
    #[error("socket frame exceeds {max_bytes} bytes before JSON parse (got {frame_bytes})")]
    FrameTooLarge {
        frame_bytes: usize,
        max_bytes: usize,
    },
    #[error("invalid JSON socket frame: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameCodecError> {
    let mut encoded = serde_json::to_vec(message)?;
    if encoded.len() > MAX_SOCKET_FRAME_BYTES {
        return Err(FrameCodecError::FrameTooLarge {
            frame_bytes: encoded.len(),
            max_bytes: MAX_SOCKET_FRAME_BYTES,
        });
    }
    encoded.push(b'\n');
    Ok(encoded)
}

pub fn decode_frame<T: DeserializeOwned>(
    input: &[u8],
) -> Result<Option<(T, usize)>, FrameCodecError> {
    if let Some(newline_idx) = memchr(b'\n', input) {
        if newline_idx > MAX_SOCKET_FRAME_BYTES {
            return Err(FrameCodecError::FrameTooLarge {
                frame_bytes: newline_idx,
                max_bytes: MAX_SOCKET_FRAME_BYTES,
            });
        }
        let decoded = serde_json::from_slice::<T>(&input[..newline_idx])?;
        Ok(Some((decoded, newline_idx + 1)))
    } else {
        if input.len() > MAX_SOCKET_FRAME_BYTES {
            return Err(FrameCodecError::FrameTooLarge {
                frame_bytes: input.len(),
                max_bytes: MAX_SOCKET_FRAME_BYTES,
            });
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestFingerprint(String);

impl RequestFingerprint {
    pub fn new(op: &str, payload: &Value) -> Result<Self, serde_json::Error> {
        let canonical_payload = canonicalize_json_value(payload);
        let canonical_bytes = serde_json::to_vec(&canonical_payload)?;
        let mut hasher = Sha256::new();
        hasher.update(op.as_bytes());
        hasher.update(&canonical_bytes);
        Ok(Self(format!("{:x}", hasher.finalize())))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[must_use]
fn canonicalize_json_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted = map
                .iter()
                .map(|(key, val)| (key.clone(), canonicalize_json_value(val)))
                .collect::<BTreeMap<_, _>>();
            let mut out = serde_json::Map::with_capacity(sorted.len());
            for (key, val) in sorted {
                out.insert(key, val);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json_value).collect()),
        _ => value.clone(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimedBy {
    pub pi_session_id: String,
    pub client_instance_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthClaim {
    pub version: u16,
    pub host_id: String,
    pub pi_session_id: String,
    pub client_instance_id: String,
    pub token: String,
    pub protocol_min: u16,
    pub protocol_max: u16,
    pub want_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthOk {
    pub version: u16,
    pub host_id: String,
    pub claimed_by: ClaimedBy,
    pub host_epoch: String,
    pub protocol: u16,
    pub capabilities: Vec<String>,
    pub lease_ttl_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthBusy {
    pub version: u16,
    pub host_id: String,
    pub claimed_by: ClaimedBy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub version: u16,
    pub id: String,
    pub op: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub version: u16,
    pub id: String,
    pub ok: bool,
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolErrorDetail {
    pub code: ProtocolErrorCode,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub version: u16,
    pub id: String,
    pub ok: bool,
    pub error: ProtocolErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservationEntry {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservationEvent {
    pub version: u16,
    pub observer_id: String,
    pub events: Vec<ObservationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ResponseEnvelope {
    Ok(Response),
    Error(ErrorResponse),
}

// ============================================================================
// Voice Types (mirrors pi_chrome_extension/src/shared/voice-types.ts)
// ============================================================================

/// Verified Transcript Commit (VTC) evidence.
/// Every committed voice transcript carries this provenance chain.
/// Must stay byte-for-byte JSON-compatible with the TypeScript CommitProof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitProof {
    /// UUID v4, unique per committed turn.
    pub turn_id: String,
    /// STT confidence score, 0.0–1.0.
    pub confidence: f64,
    /// STT backend identifier (e.g. "whisper_apr_wasm", "web_speech", "simulated").
    pub backend: String,
    /// Model version identifier (e.g. "tiny-int8-v1.0.0").
    pub model_id: String,
    /// Date.now() at commit time (milliseconds since epoch).
    pub timestamp_ms: u64,
    /// Total captured audio duration in milliseconds.
    pub audio_duration_ms: u64,
    /// STT wall-clock processing time in milliseconds.
    pub processing_ms: u64,
}

/// The voice event that becomes agent text input (VS4).
/// Only voice_turn_committed observations produce Message::User in the agent.
/// Must stay byte-for-byte JSON-compatible with the TypeScript VoiceTurnCommitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VoiceTurnCommitted {
    /// Raw transcript text from STT.
    pub transcript: String,
    /// VTC provenance proof.
    pub proof: CommitProof,
}

/// Voice event kind string constants matching TypeScript `VoiceEventKind` values.
///
/// These are the unprefixed kind names used on the wire in `ObservationEntry.kind`
/// when `source="voice"`. The TypeScript extension's `VoiceEventKind` enum sends
/// these exact values (e.g., `"turn_committed"`, not `"voice_turn_committed"`).
///
/// Note: The Rust `ObservableEventKind` enum in observer.rs uses a `voice_` prefixed
/// form for its own serde serialization (e.g., `VoiceTurnCommitted` → `"voice_turn_committed"`),
/// but that is a separate subsystem from the observation wire protocol.
pub mod voice_event_kind {
    pub const TURN_COMMITTED: &str = "turn_committed";
    pub const STT_PARTIAL: &str = "stt_partial";
    pub const STT_FINAL: &str = "stt_final";
    pub const STT_ERROR: &str = "stt_error";
    pub const VAD_STARTED: &str = "vad_started";
    pub const VAD_STOPPED: &str = "vad_stopped";
    pub const TTS_STARTED: &str = "tts_started";
    pub const TTS_DONE: &str = "tts_done";
    pub const TTS_ERROR: &str = "tts_error";
}

/// Source field value for voice observations.
pub const VOICE_OBSERVATION_SOURCE: &str = "voice";

/// VoiceSession FSM states matching TypeScript `VoiceSessionState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceSessionState {
    Disabled,
    Idle,
    Listening,
    Processing,
    Speaking,
    Error,
}

/// Response from the `voice_status` tool.
/// Must stay JSON-compatible with TypeScript `VoiceStatusResult`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VoiceStatusResult {
    /// Current FSM state.
    pub state: VoiceSessionState,
    /// STT backend name, None if STT unavailable.
    pub stt_backend: Option<String>,
    /// TTS backend identifier.
    pub tts_backend: String,
    /// Whether the WASM STT model is loaded and ready.
    pub model_loaded: bool,
    /// Model version identifier, None if not loaded.
    pub model_id: Option<String>,
    /// Whether the earcon AudioBuffer is decoded and ready.
    pub earcon_ready: bool,
    /// Non-null during listening/processing states.
    pub active_turn_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageType {
    AuthClaim(AuthClaim),
    AuthOk(AuthOk),
    AuthBusy(AuthBusy),
    Request(Request),
    Response(ResponseEnvelope),
    Observation(ObservationEvent),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolErrorCode {
    ChromeNotFound,
    ExtensionNotInstalled,
    ChromeBridgeDisconnected,
    ChromeBridgeAuthFailed,
    ChromeBridgeBusy,
    ChromeBridgeProtocolMismatch,
    ChromeBridgeTimeout,
    ChromeBridgeExecutionIndeterminate,
    TabNotFound,
    ElementNotFound,
    NavigationFailed,
    ScreenshotFailed,
    JavascriptError,
    ObserverTabClosed,
    ObserverLimitReached,
}

#[cfg(test)]
impl CommitProof {
    /// Returns a valid `CommitProof` with sensible test defaults.
    pub fn test_default() -> Self {
        Self {
            turn_id: "00000000-0000-4000-8000-000000000001".to_string(),
            confidence: 0.95,
            backend: "simulated".to_string(),
            model_id: "tiny-int8-v1.0.0".to_string(),
            timestamp_ms: 1708700000000,
            audio_duration_ms: 3200,
            processing_ms: 450,
        }
    }
}

#[cfg(test)]
impl VoiceTurnCommitted {
    /// Returns a valid `VoiceTurnCommitted` with sensible test defaults.
    pub fn test_default() -> Self {
        Self {
            transcript: "list my open tabs".to_string(),
            proof: CommitProof::test_default(),
        }
    }
}

/// Construct a voice-tagged `ObservationEntry` for tests.
#[cfg(test)]
pub fn voice_observation_entry(kind: &str, message_json: Option<String>) -> ObservationEntry {
    ObservationEntry {
        kind: kind.to_string(),
        message: message_json,
        source: Some(VOICE_OBSERVATION_SOURCE.to_string()),
        url: None,
        ts: 1708700000000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn sample_request_message(payload: Value) -> MessageType {
        MessageType::Request(Request {
            version: PROTOCOL_VERSION_V1,
            id: "req-123".to_string(),
            op: "navigate".to_string(),
            payload,
        })
    }

    fn json_value_strategy() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|n| Value::Number(n.into())),
            any::<u64>().prop_map(|n| Value::Number(n.into())),
            "[a-zA-Z0-9 _./:-]{0,32}".prop_map(Value::String),
        ];

        leaf.prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                prop::collection::btree_map("[a-zA-Z0-9_]{1,12}", inner, 0..4).prop_map(|map| {
                    let mut obj = serde_json::Map::with_capacity(map.len());
                    for (key, value) in map {
                        obj.insert(key, value);
                    }
                    Value::Object(obj)
                }),
            ]
        })
    }

    #[test]
    fn test_protocol_frame_roundtrip_json_message() {
        let message = sample_request_message(json!({
            "url": "https://example.com",
            "headers": { "X-Test": "1" }
        }));

        let encoded = encode_frame(&message).expect("encode should succeed for small message");
        let decoded = decode_frame::<MessageType>(&encoded)
            .expect("decode should succeed for valid frame")
            .expect("complete frame should decode");

        assert_eq!(
            decoded.1,
            encoded.len(),
            "decoder must report consumed frame bytes"
        );
        assert_eq!(
            decoded.0, message,
            "frame roundtrip must preserve message content"
        );
    }

    #[test]
    fn test_protocol_decode_frame_returns_none_for_partial_read() {
        let partial = br#"{"version":1,"type":"request","id":"req-1"}"#;

        let decoded = decode_frame::<MessageType>(partial).expect("partial read is not an error");

        assert!(
            decoded.is_none(),
            "decoder must signal incomplete frame without newline"
        );
    }

    #[test]
    fn test_protocol_decode_frame_rejects_malformed_json() {
        let malformed = b"{\"version\":1,\"type\":\"request\",\"id\":]\n";

        let err = decode_frame::<MessageType>(malformed).expect_err("malformed JSON must fail");

        assert!(
            matches!(err, FrameCodecError::InvalidJson(_)),
            "expected JSON parse error, got {err:?}"
        );
    }

    #[test]
    fn test_protocol_decode_frame_rejects_oversized_frame_before_parse() {
        let mut oversized = vec![b'a'; MAX_SOCKET_FRAME_BYTES + 1];
        oversized.push(b'\n');

        let err = decode_frame::<MessageType>(&oversized)
            .expect_err("oversized frame must be rejected before JSON parse");

        assert!(
            matches!(
                err,
                FrameCodecError::FrameTooLarge {
                    frame_bytes,
                    max_bytes
                } if frame_bytes == MAX_SOCKET_FRAME_BYTES + 1 && max_bytes == MAX_SOCKET_FRAME_BYTES
            ),
            "expected size-cap error, got {err:?}"
        );
    }

    #[test]
    fn test_protocol_request_id_roundtrip_preserves_id() {
        let message = sample_request_message(json!({"url": "https://example.com"}));
        let encoded = encode_frame(&message).expect("encode request frame");
        let (decoded, _) = decode_frame::<MessageType>(&encoded)
            .expect("decode request frame")
            .expect("complete request frame");

        match decoded {
            MessageType::Request(req) => {
                assert_eq!(req.id, "req-123", "request id must survive frame roundtrip");
            }
            other => panic!("expected request message, got {other:?}"),
        }
    }

    #[test]
    fn test_protocol_message_type_decodes_success_response() {
        let raw = br#"{"version":1,"type":"response","id":"req-1","ok":true,"result":{"title":"Example"}}"#;

        let decoded: MessageType =
            serde_json::from_slice(raw).expect("success response must decode into MessageType");

        match decoded {
            MessageType::Response(ResponseEnvelope::Ok(resp)) => {
                assert!(resp.ok, "success response must preserve ok=true");
                assert_eq!(resp.id, "req-1", "response id must decode correctly");
                assert_eq!(
                    resp.result["title"], "Example",
                    "result payload must decode"
                );
            }
            other => panic!("expected success response variant, got {other:?}"),
        }
    }

    #[test]
    fn test_protocol_message_type_decodes_error_response() {
        let raw = br#"{"version":1,"type":"response","id":"req-1","ok":false,"error":{"code":"TAB_NOT_FOUND","message":"tab missing","retryable":false}}"#;

        let decoded: MessageType =
            serde_json::from_slice(raw).expect("error response must decode into MessageType");

        match decoded {
            MessageType::Response(ResponseEnvelope::Error(resp)) => {
                assert!(!resp.ok, "error response must preserve ok=false");
                assert_eq!(
                    resp.error.code,
                    ProtocolErrorCode::TabNotFound,
                    "code must decode"
                );
                assert!(!resp.error.retryable, "retryable flag must decode");
            }
            other => panic!("expected error response variant, got {other:?}"),
        }
    }

    #[test]
    fn test_protocol_message_type_decodes_observation_event() {
        let raw = br#"{"version":1,"type":"observation","observer_id":"obs-1","events":[{"kind":"console_error","message":"boom","source":"app.tsx:10","ts":1708700000},{"kind":"load_complete","url":"http://localhost:3000","ts":1708700001}]}"#;

        let decoded: MessageType =
            serde_json::from_slice(raw).expect("observation message must decode");

        match decoded {
            MessageType::Observation(obs) => {
                assert_eq!(obs.observer_id, "obs-1", "observer_id must decode");
                assert_eq!(obs.events.len(), 2, "observation batch size must decode");
                assert_eq!(
                    obs.events[0].kind, "console_error",
                    "first observation event kind must decode"
                );
                assert_eq!(
                    obs.events[1].url.as_deref(),
                    Some("http://localhost:3000"),
                    "load_complete URL must decode"
                );
            }
            other => panic!("expected observation message, got {other:?}"),
        }
    }

    #[test]
    fn test_protocol_request_fingerprint_is_deterministic_for_key_order() {
        let payload_a = json!({
            "b": [2, {"z": true, "a": 1}],
            "a": {"y": "x", "x": "y"}
        });
        let payload_b = json!({
            "a": {"x": "y", "y": "x"},
            "b": [2, {"a": 1, "z": true}]
        });

        let fp_a = RequestFingerprint::new("navigate", &payload_a).expect("fingerprint payload_a");
        let fp_b = RequestFingerprint::new("navigate", &payload_b).expect("fingerprint payload_b");
        let fp_c =
            RequestFingerprint::new("navigate", &json!({"a": 1, "b": 3})).expect("fingerprint c");

        assert_eq!(
            fp_a, fp_b,
            "fingerprint must ignore object-key insertion order via canonical JSON"
        );
        assert_ne!(fp_a, fp_c, "fingerprint must change when payload changes");
    }

    // -----------------------------------------------------------------------
    // ProtocolErrorCode serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_error_codes_serialize_screaming_snake_case() {
        let codes = [
            (ProtocolErrorCode::ChromeNotFound, "CHROME_NOT_FOUND"),
            (
                ProtocolErrorCode::ExtensionNotInstalled,
                "EXTENSION_NOT_INSTALLED",
            ),
            (
                ProtocolErrorCode::ChromeBridgeDisconnected,
                "CHROME_BRIDGE_DISCONNECTED",
            ),
            (
                ProtocolErrorCode::ChromeBridgeAuthFailed,
                "CHROME_BRIDGE_AUTH_FAILED",
            ),
            (ProtocolErrorCode::ChromeBridgeBusy, "CHROME_BRIDGE_BUSY"),
            (
                ProtocolErrorCode::ChromeBridgeProtocolMismatch,
                "CHROME_BRIDGE_PROTOCOL_MISMATCH",
            ),
            (
                ProtocolErrorCode::ChromeBridgeTimeout,
                "CHROME_BRIDGE_TIMEOUT",
            ),
            (
                ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
                "CHROME_BRIDGE_EXECUTION_INDETERMINATE",
            ),
            (ProtocolErrorCode::TabNotFound, "TAB_NOT_FOUND"),
            (ProtocolErrorCode::ElementNotFound, "ELEMENT_NOT_FOUND"),
            (ProtocolErrorCode::NavigationFailed, "NAVIGATION_FAILED"),
            (ProtocolErrorCode::ScreenshotFailed, "SCREENSHOT_FAILED"),
            (ProtocolErrorCode::JavascriptError, "JAVASCRIPT_ERROR"),
            (ProtocolErrorCode::ObserverTabClosed, "OBSERVER_TAB_CLOSED"),
            (
                ProtocolErrorCode::ObserverLimitReached,
                "OBSERVER_LIMIT_REACHED",
            ),
        ];

        for (code, expected_str) in &codes {
            let serialized = serde_json::to_string(code).expect("serialize error code");
            assert_eq!(
                serialized,
                format!("\"{expected_str}\""),
                "code {code:?} must serialize to {expected_str}"
            );

            let deserialized: ProtocolErrorCode =
                serde_json::from_str(&serialized).expect("deserialize error code");
            assert_eq!(
                &deserialized, code,
                "error code roundtrip must preserve variant"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Auth message roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_claim_frame_roundtrip() {
        let claim = MessageType::AuthClaim(AuthClaim {
            version: PROTOCOL_VERSION_V1,
            host_id: "host-1".to_string(),
            pi_session_id: "session-1".to_string(),
            client_instance_id: "client-1".to_string(),
            token: "tok_abc".to_string(),
            protocol_min: PROTOCOL_MIN_SUPPORTED,
            protocol_max: PROTOCOL_MAX_SUPPORTED,
            want_capabilities: vec!["browser_tools".to_string()],
        });

        let encoded = encode_frame(&claim).expect("encode auth_claim");
        let (decoded, consumed) = decode_frame::<MessageType>(&encoded)
            .expect("decode auth_claim")
            .expect("complete auth_claim frame");

        assert_eq!(decoded, claim);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_auth_ok_frame_roundtrip() {
        let auth_ok = MessageType::AuthOk(AuthOk {
            version: PROTOCOL_VERSION_V1,
            host_id: "host-1".to_string(),
            claimed_by: ClaimedBy {
                pi_session_id: "session-1".to_string(),
                client_instance_id: "client-1".to_string(),
            },
            host_epoch: "epoch-abc".to_string(),
            protocol: PROTOCOL_VERSION_V1,
            capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
            lease_ttl_ms: 30_000,
        });

        let encoded = encode_frame(&auth_ok).expect("encode auth_ok");
        let (decoded, _) = decode_frame::<MessageType>(&encoded)
            .expect("decode auth_ok")
            .expect("complete auth_ok frame");

        assert_eq!(decoded, auth_ok);
    }

    #[test]
    fn test_auth_busy_frame_roundtrip() {
        let busy = MessageType::AuthBusy(AuthBusy {
            version: PROTOCOL_VERSION_V1,
            host_id: "host-1".to_string(),
            claimed_by: ClaimedBy {
                pi_session_id: "other-session".to_string(),
                client_instance_id: "other-client".to_string(),
            },
        });

        let encoded = encode_frame(&busy).expect("encode auth_busy");
        let (decoded, _) = decode_frame::<MessageType>(&encoded)
            .expect("decode auth_busy")
            .expect("complete auth_busy frame");

        assert_eq!(decoded, busy);
    }

    // -----------------------------------------------------------------------
    // Fingerprint edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_fingerprint_different_ops_produce_different_fingerprints() {
        let payload = json!({"url": "https://example.com"});
        let fp_nav = RequestFingerprint::new("navigate", &payload).expect("fp navigate");
        let fp_click = RequestFingerprint::new("click", &payload).expect("fp click");
        assert_ne!(
            fp_nav, fp_click,
            "different ops must produce different fingerprints"
        );
    }

    #[test]
    fn test_fingerprint_empty_payload() {
        let fp1 = RequestFingerprint::new("navigate", &json!({})).expect("fp empty obj");
        let fp2 = RequestFingerprint::new("navigate", &json!(null)).expect("fp null");
        assert_ne!(fp1, fp2, "empty object vs null should differ");
    }

    #[test]
    fn test_fingerprint_nested_array_order_matters() {
        let fp1 = RequestFingerprint::new("op", &json!([1, 2, 3])).expect("fp 1,2,3");
        let fp2 = RequestFingerprint::new("op", &json!([3, 2, 1])).expect("fp 3,2,1");
        assert_ne!(fp1, fp2, "array element order must affect fingerprint");
    }

    // -----------------------------------------------------------------------
    // ObservationEntry optional fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_observation_entry_minimal() {
        let entry: ObservationEntry =
            serde_json::from_value(json!({"kind": "console_error", "ts": 1000}))
                .expect("minimal entry");
        assert_eq!(entry.kind, "console_error");
        assert!(entry.message.is_none());
        assert!(entry.source.is_none());
        assert!(entry.url.is_none());
    }

    #[test]
    fn test_observation_entry_full() {
        let entry: ObservationEntry = serde_json::from_value(json!({
            "kind": "network_error",
            "message": "404",
            "source": "fetch",
            "url": "https://api.example.com/data",
            "ts": 2000
        }))
        .expect("full entry");
        assert_eq!(entry.message.as_deref(), Some("404"));
        assert_eq!(entry.source.as_deref(), Some("fetch"));
        assert_eq!(entry.url.as_deref(), Some("https://api.example.com/data"));
    }

    #[test]
    fn test_observation_entry_serialization_skips_none_fields() {
        let entry = ObservationEntry {
            kind: "console_error".to_string(),
            message: None,
            source: None,
            url: None,
            ts: 1000,
        };
        let serialized = serde_json::to_value(&entry).expect("serialize");
        assert!(!serialized.as_object().unwrap().contains_key("message"));
        assert!(!serialized.as_object().unwrap().contains_key("source"));
        assert!(!serialized.as_object().unwrap().contains_key("url"));
    }

    // -----------------------------------------------------------------------
    // Multi-frame buffer
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_frame_handles_trailing_data_after_newline() {
        let msg1 = sample_request_message(json!({"a": 1}));
        let encoded1 = encode_frame(&msg1).expect("encode msg1");

        // Append partial second message
        let mut buf = encoded1.clone();
        buf.extend_from_slice(b"{\"partial\":true");

        let (decoded, consumed) = decode_frame::<MessageType>(&buf)
            .expect("decode first frame")
            .expect("first frame is complete");

        assert_eq!(decoded, msg1);
        assert_eq!(consumed, encoded1.len(), "should only consume first frame");
        assert!(buf.len() > consumed, "trailing data should remain");
    }

    #[test]
    fn test_decode_two_frames_in_sequence() {
        let msg1 = sample_request_message(json!({"x": 1}));
        let msg2 = sample_request_message(json!({"x": 2}));
        let mut buf = encode_frame(&msg1).expect("encode msg1");
        buf.extend(encode_frame(&msg2).expect("encode msg2"));

        let (decoded1, consumed1) = decode_frame::<MessageType>(&buf)
            .expect("decode first")
            .expect("first complete");
        assert_eq!(decoded1, msg1);

        let (decoded2, consumed2) = decode_frame::<MessageType>(&buf[consumed1..])
            .expect("decode second")
            .expect("second complete");
        assert_eq!(decoded2, msg2);
        assert_eq!(consumed1 + consumed2, buf.len());
    }

    // -----------------------------------------------------------------------
    // Empty buffer
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_empty_buffer_returns_none() {
        let result = decode_frame::<MessageType>(&[]).expect("empty buffer is not error");
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // ResponseEnvelope disambiguation
    // -----------------------------------------------------------------------

    #[test]
    fn test_response_envelope_ok_vs_error_disambiguation() {
        let ok_raw = json!({"version": 1, "id": "r1", "ok": true, "result": {}});
        let err_raw = json!({
            "version": 1, "id": "r1", "ok": false,
            "error": {"code": "TAB_NOT_FOUND", "message": "no tab", "retryable": false}
        });

        let ok_envelope: ResponseEnvelope = serde_json::from_value(ok_raw).expect("ok envelope");
        let err_envelope: ResponseEnvelope = serde_json::from_value(err_raw).expect("err envelope");

        assert!(matches!(ok_envelope, ResponseEnvelope::Ok(_)));
        assert!(matches!(err_envelope, ResponseEnvelope::Error(_)));
    }

    // -----------------------------------------------------------------------
    // Constants verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_protocol_constants_match_plan() {
        assert_eq!(MAX_SOCKET_FRAME_BYTES, 1024 * 1024);
        assert_eq!(PROTOCOL_VERSION_V1, 1);
        assert_eq!(PROTOCOL_MIN_SUPPORTED, PROTOCOL_VERSION_V1);
        assert_eq!(PROTOCOL_MAX_SUPPORTED, PROTOCOL_VERSION_V1);
    }

    // -----------------------------------------------------------------------
    // Proptest
    // -----------------------------------------------------------------------

    proptest! {
        #[test]
        fn test_protocol_proptest_frame_roundtrip_arbitrary_payloads(
            payload in json_value_strategy(),
            op in "[a-z_]{1,16}",
            id_suffix in "[a-z0-9]{1,12}"
        ) {
            let message = MessageType::Request(Request {
                version: PROTOCOL_VERSION_V1,
                id: format!("req-{id_suffix}"),
                op,
                payload,
            });

            let encoded = encode_frame(&message).expect("generated payload should remain under frame cap");
            let decoded = decode_frame::<MessageType>(&encoded)
                .expect("generated frame should decode")
                .expect("generated frame should be complete");

            prop_assert_eq!(
                decoded.0, message,
                "encode/decode roundtrip must preserve arbitrary request payloads"
            );
            prop_assert_eq!(
                decoded.1, encoded.len(),
                "decoder must report full consumed length for arbitrary frames"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Voice type roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn test_commit_proof_json_roundtrip() {
        let proof = CommitProof {
            turn_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            confidence: 0.95,
            backend: "whisper_apr_wasm".to_string(),
            model_id: "tiny-int8-v1.0.0".to_string(),
            timestamp_ms: 1708700000000,
            audio_duration_ms: 3200,
            processing_ms: 450,
        };

        let serialized = serde_json::to_string(&proof).expect("serialize CommitProof");
        let deserialized: CommitProof =
            serde_json::from_str(&serialized).expect("deserialize CommitProof");

        assert_eq!(deserialized.turn_id, proof.turn_id);
        assert!((deserialized.confidence - proof.confidence).abs() < f64::EPSILON);
        assert_eq!(deserialized.backend, proof.backend);
        assert_eq!(deserialized.model_id, proof.model_id);
        assert_eq!(deserialized.timestamp_ms, proof.timestamp_ms);
        assert_eq!(deserialized.audio_duration_ms, proof.audio_duration_ms);
        assert_eq!(deserialized.processing_ms, proof.processing_ms);
    }

    #[test]
    fn test_voice_turn_committed_json_roundtrip() {
        let committed = VoiceTurnCommitted {
            transcript: "list my open tabs".to_string(),
            proof: CommitProof {
                turn_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                confidence: 0.92,
                backend: "simulated".to_string(),
                model_id: "tiny-int8-v1.0.0".to_string(),
                timestamp_ms: 1708700001000,
                audio_duration_ms: 1500,
                processing_ms: 200,
            },
        };

        let serialized = serde_json::to_string(&committed).expect("serialize VoiceTurnCommitted");
        let deserialized: VoiceTurnCommitted =
            serde_json::from_str(&serialized).expect("deserialize VoiceTurnCommitted");

        assert_eq!(deserialized.transcript, committed.transcript);
        assert_eq!(deserialized.proof.turn_id, committed.proof.turn_id);
        assert!((deserialized.proof.confidence - committed.proof.confidence).abs() < f64::EPSILON);
    }

    #[test]
    fn test_commit_proof_has_all_7_fields() {
        let proof_json = json!({
            "turn_id": "abc-123",
            "confidence": 0.85,
            "backend": "whisper_apr_wasm",
            "model_id": "tiny-int8-v1.0.0",
            "timestamp_ms": 1000,
            "audio_duration_ms": 2000,
            "processing_ms": 300
        });

        let proof: CommitProof =
            serde_json::from_value(proof_json).expect("all 7 fields must deserialize");
        assert_eq!(proof.turn_id, "abc-123");
        assert!((proof.confidence - 0.85).abs() < f64::EPSILON);
    }

    /// JS Number.MAX_SAFE_INTEGER = 2^53 - 1.  All u64 timestamp/duration
    /// fields that cross the wire to TypeScript must stay within this bound.
    #[test]
    fn test_timestamp_ms_fits_js_safe_integer() {
        const JS_MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;
        // A realistic timestamp_ms: 2024-02-23T14:00:00Z ≈ 1.7 × 10^12
        let proof = CommitProof {
            turn_id: "test".into(),
            confidence: 0.9,
            backend: "test".into(),
            model_id: "test".into(),
            timestamp_ms: 1708700000000,
            audio_duration_ms: 3200,
            processing_ms: 450,
        };
        assert!(
            proof.timestamp_ms < JS_MAX_SAFE_INTEGER,
            "timestamp_ms must fit in JS safe integer range"
        );
        assert!(
            proof.audio_duration_ms < JS_MAX_SAFE_INTEGER,
            "audio_duration_ms must fit in JS safe integer range"
        );
        assert!(
            proof.processing_ms < JS_MAX_SAFE_INTEGER,
            "processing_ms must fit in JS safe integer range"
        );
        // Verify the boundary: max safe integer itself
        assert_eq!(JS_MAX_SAFE_INTEGER, 9_007_199_254_740_991);
    }

    #[test]
    fn test_voice_event_kind_constants_match_typescript() {
        assert_eq!(voice_event_kind::TURN_COMMITTED, "turn_committed");
        assert_eq!(voice_event_kind::STT_PARTIAL, "stt_partial");
        assert_eq!(voice_event_kind::STT_FINAL, "stt_final");
        assert_eq!(voice_event_kind::STT_ERROR, "stt_error");
        assert_eq!(voice_event_kind::VAD_STARTED, "vad_started");
        assert_eq!(voice_event_kind::VAD_STOPPED, "vad_stopped");
        assert_eq!(voice_event_kind::TTS_STARTED, "tts_started");
        assert_eq!(voice_event_kind::TTS_DONE, "tts_done");
        assert_eq!(voice_event_kind::TTS_ERROR, "tts_error");
    }

    #[test]
    fn test_voice_observation_source_constant() {
        assert_eq!(VOICE_OBSERVATION_SOURCE, "voice");
    }

    #[test]
    fn test_voice_observation_entry_with_voice_source() {
        let entry = voice_observation_entry(
            voice_event_kind::TURN_COMMITTED,
            Some(r#"{"transcript":"hello","proof":{}}"#.to_string()),
        );

        let serialized = serde_json::to_value(&entry).expect("serialize voice observation entry");
        assert_eq!(serialized["kind"], "turn_committed");
        assert_eq!(serialized["source"], "voice");
    }

    // -----------------------------------------------------------------------
    // Test helper roundtrips (bd-19o.1.2.4)
    // -----------------------------------------------------------------------

    #[test]
    fn test_commit_proof_test_default_roundtrip() {
        let proof = CommitProof::test_default();
        assert_eq!(proof.turn_id, "00000000-0000-4000-8000-000000000001");
        assert!((proof.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(proof.backend, "simulated");

        let json = serde_json::to_string(&proof).expect("serialize");
        let back: CommitProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof, back);
    }

    #[test]
    fn test_voice_turn_committed_test_default_roundtrip() {
        let vtc = VoiceTurnCommitted::test_default();
        assert_eq!(vtc.transcript, "list my open tabs");
        assert_eq!(vtc.proof.backend, "simulated");

        let json = serde_json::to_string(&vtc).expect("serialize");
        let back: VoiceTurnCommitted = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(vtc, back);
    }

    #[test]
    fn test_voice_observation_entry_helper_tags_source() {
        let entry = voice_observation_entry(
            voice_event_kind::STT_FINAL,
            Some(r#"{"text":"hello","confidence":0.9,"processing_ms":100}"#.to_string()),
        );
        assert_eq!(entry.source.as_deref(), Some("voice"));
        assert_eq!(entry.kind, "stt_final");
        assert!(entry.message.is_some());
    }

    #[test]
    fn test_voice_observation_entry_helper_no_message() {
        let entry = voice_observation_entry(voice_event_kind::TTS_DONE, None);
        assert_eq!(entry.source.as_deref(), Some("voice"));
        assert_eq!(entry.kind, "tts_done");
        assert!(entry.message.is_none());
    }

    // -----------------------------------------------------------------------
    // VoiceSessionState + VoiceStatusResult (bd-19o.1.5.2)
    // -----------------------------------------------------------------------

    #[test]
    fn test_voice_session_state_serde_roundtrip() {
        let states = [
            (VoiceSessionState::Disabled, "\"disabled\""),
            (VoiceSessionState::Idle, "\"idle\""),
            (VoiceSessionState::Listening, "\"listening\""),
            (VoiceSessionState::Processing, "\"processing\""),
            (VoiceSessionState::Speaking, "\"speaking\""),
            (VoiceSessionState::Error, "\"error\""),
        ];
        for (state, expected_json) in &states {
            let json = serde_json::to_string(state).expect("serialize state");
            assert_eq!(&json, expected_json);
            let back: VoiceSessionState = serde_json::from_str(&json).expect("deserialize state");
            assert_eq!(&back, state);
        }
    }

    #[test]
    fn test_voice_status_result_json_roundtrip() {
        let result = VoiceStatusResult {
            state: VoiceSessionState::Idle,
            stt_backend: Some("whisper_apr_wasm".to_string()),
            tts_backend: "chrome_tts".to_string(),
            model_loaded: true,
            model_id: Some("tiny-int8-v1.0.0".to_string()),
            earcon_ready: true,
            active_turn_id: None,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let back: VoiceStatusResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, back);
    }

    #[test]
    fn test_voice_status_result_from_typescript_json() {
        let ts_json = json!({
            "state": "listening",
            "stt_backend": "whisper_apr_wasm",
            "tts_backend": "chrome_tts",
            "model_loaded": true,
            "model_id": "tiny-int8-v1.0.0",
            "earcon_ready": false,
            "active_turn_id": "abc-123"
        });
        let result: VoiceStatusResult =
            serde_json::from_value(ts_json).expect("deserialize from TS shape");
        assert_eq!(result.state, VoiceSessionState::Listening);
        assert_eq!(result.active_turn_id.as_deref(), Some("abc-123"));
        assert!(!result.earcon_ready);
    }

    #[test]
    fn test_voice_status_result_null_optional_fields() {
        let ts_json = json!({
            "state": "disabled",
            "stt_backend": null,
            "tts_backend": "chrome_tts",
            "model_loaded": false,
            "model_id": null,
            "earcon_ready": false,
            "active_turn_id": null
        });
        let result: VoiceStatusResult =
            serde_json::from_value(ts_json).expect("deserialize with nulls");
        assert_eq!(result.state, VoiceSessionState::Disabled);
        assert!(result.stt_backend.is_none());
        assert!(result.model_id.is_none());
        assert!(result.active_turn_id.is_none());
    }

    // -----------------------------------------------------------------------
    // Schema roundtrip edge cases (bd-19o.1.10.1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_commit_proof_confidence_zero_roundtrip() {
        let proof = CommitProof {
            turn_id: "00000000-0000-4000-8000-000000000001".to_string(),
            confidence: 0.0,
            backend: "whisper_apr_wasm".to_string(),
            model_id: "tiny-int8-v1.0.0".to_string(),
            timestamp_ms: 0,
            audio_duration_ms: 0,
            processing_ms: 0,
        };
        let json = serde_json::to_string(&proof).expect("serialize confidence=0.0");
        let back: CommitProof = serde_json::from_str(&json).expect("deserialize confidence=0.0");
        assert!((back.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_commit_proof_confidence_one_roundtrip() {
        let proof = CommitProof {
            turn_id: "ffffffff-ffff-4fff-bfff-ffffffffffff".to_string(),
            confidence: 1.0,
            backend: "whisper_apr_wasm".to_string(),
            model_id: "tiny-int8-v1.0.0".to_string(),
            timestamp_ms: 9_007_199_254_740_991, // JS MAX_SAFE_INTEGER
            audio_duration_ms: 999999,
            processing_ms: 999999,
        };
        let json = serde_json::to_string(&proof).expect("serialize confidence=1.0");
        let back: CommitProof = serde_json::from_str(&json).expect("deserialize confidence=1.0");
        assert!((back.confidence - 1.0).abs() < f64::EPSILON);
        assert_eq!(back.timestamp_ms, 9_007_199_254_740_991);
    }

    #[test]
    fn test_voice_turn_committed_empty_transcript_roundtrip() {
        let vtc = VoiceTurnCommitted {
            transcript: String::new(),
            proof: CommitProof::test_default(),
        };
        let json = serde_json::to_string(&vtc).expect("serialize empty transcript");
        let back: VoiceTurnCommitted =
            serde_json::from_str(&json).expect("deserialize empty transcript");
        assert_eq!(back.transcript, "");
    }

    #[test]
    fn test_voice_tts_speak_payload_full_from_typescript_json() {
        // Matches the wire format TypeScript produces with all optional fields
        let ts_json = json!({
            "text": "Here is the refactored auth module",
            "utterance_id": "utt-001",
            "voice_name": "Google US English",
            "rate": 1.2,
            "pitch": 0.9
        });
        // Deserialize into a generic Value to verify field names match
        let obj: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(ts_json).expect("parse TS speak payload");
        assert_eq!(obj["text"], "Here is the refactored auth module");
        assert_eq!(obj["utterance_id"], "utt-001");
        assert_eq!(obj["voice_name"], "Google US English");
        assert_eq!(obj["rate"], 1.2);
        assert_eq!(obj["pitch"], 0.9);
    }

    #[test]
    fn test_voice_tts_speak_payload_minimal_from_typescript_json() {
        // Matches wire format with optional fields absent (TS undefined → not serialized)
        let ts_json = json!({
            "text": "Done",
            "utterance_id": "utt-002"
        });
        let obj: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(ts_json).expect("parse minimal TS speak payload");
        assert_eq!(obj["text"], "Done");
        assert_eq!(obj["utterance_id"], "utt-002");
        assert!(!obj.contains_key("voice_name"));
        assert!(!obj.contains_key("rate"));
        assert!(!obj.contains_key("pitch"));
    }
}
