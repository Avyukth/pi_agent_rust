//! Shared voice test helpers for Rust-side voice integration tests.
//!
//! bd-19o.1.8.3: Reusable across Phase A-D test files.
//!
//! Provides:
//! - Voice observation event factories for injection into ChromeBridge
//! - Message assertion helpers for checking User transcript content
//! - Convenience builders for common voice test scenarios
//!
//! Note: `push_observation()` and `CommitProof::test_default()` are `#[cfg(test)]`
//! on the library crate, so they are only available in unit tests (inside the crate).
//! The inject_* helpers below use the observation buffer directly via
//! `take_observations_limited()` assertions instead.

use pi::chrome::protocol::{
    voice_event_kind, CommitProof, ObservationEntry, ObservationEvent, VoiceTurnCommitted,
    VOICE_OBSERVATION_SOURCE,
};
use pi::model::{Message, UserContent};
use serde_json::json;

// ============================================================================
// Default CommitProof for integration tests
// ============================================================================

/// Provide a sensible default CommitProof for integration tests.
///
/// This mirrors `CommitProof::test_default()` (which is `#[cfg(test)]` on the
/// library crate and thus inaccessible from integration test crates).
pub fn default_commit_proof() -> CommitProof {
    CommitProof {
        turn_id: "test-turn-00000000-0000-4000-8000-000000000000".to_string(),
        confidence: 0.92,
        backend: "simulated".to_string(),
        model_id: "tiny-int8-v1.0.0".to_string(),
        timestamp_ms: 1740000000000,
        audio_duration_ms: 1200,
        processing_ms: 450,
    }
}

// ============================================================================
// Voice ObservationEvent factories
// ============================================================================

/// Build a voice-sourced `ObservationEvent` with a single entry.
///
/// This is the format ChromeBridge expects via `push_observation()`.
pub fn voice_observation(kind: &str, message_json: Option<String>) -> ObservationEvent {
    ObservationEvent {
        version: 1,
        observer_id: "observer_voice_test".to_string(),
        events: vec![ObservationEntry {
            kind: kind.to_string(),
            message: message_json,
            source: Some(VOICE_OBSERVATION_SOURCE.to_string()),
            url: None,
            ts: 1708700000000,
        }],
    }
}

/// Build a voice_turn_committed observation from a transcript and optional proof overrides.
pub fn voice_committed_observation(
    transcript: &str,
    proof_overrides: Option<CommitProof>,
) -> ObservationEvent {
    let proof = proof_overrides.unwrap_or_else(default_commit_proof);
    let vtc = VoiceTurnCommitted {
        transcript: transcript.to_string(),
        proof,
    };
    let json_str = serde_json::to_string(&vtc).expect("serialize VoiceTurnCommitted");
    voice_observation(voice_event_kind::TURN_COMMITTED, Some(json_str))
}

/// Build a voice_stt_partial observation.
pub fn voice_stt_partial_observation(partial_text: &str, chunk_index: u32) -> ObservationEvent {
    let msg = json!({
        "partial_text": partial_text,
        "chunk_index": chunk_index,
    });
    voice_observation(voice_event_kind::STT_PARTIAL, Some(msg.to_string()))
}

/// Build a voice_stt_final observation.
pub fn voice_stt_final_observation(
    text: &str,
    confidence: f64,
    processing_ms: u64,
) -> ObservationEvent {
    let msg = json!({
        "text": text,
        "confidence": confidence,
        "processing_ms": processing_ms,
    });
    voice_observation(voice_event_kind::STT_FINAL, Some(msg.to_string()))
}

/// Build a voice_stt_error observation.
pub fn voice_stt_error_observation(error: &str, detail: &str) -> ObservationEvent {
    let msg = json!({
        "error": error,
        "detail": detail,
    });
    voice_observation(voice_event_kind::STT_ERROR, Some(msg.to_string()))
}

/// Build a voice_tts_started observation.
pub fn voice_tts_started_observation(utterance_id: &str, text_length: usize) -> ObservationEvent {
    let msg = json!({
        "utterance_id": utterance_id,
        "text_length": text_length,
    });
    voice_observation(voice_event_kind::TTS_STARTED, Some(msg.to_string()))
}

/// Build a voice_tts_done observation.
pub fn voice_tts_done_observation(utterance_id: &str, duration_ms: u64) -> ObservationEvent {
    let msg = json!({
        "utterance_id": utterance_id,
        "duration_ms": duration_ms,
    });
    voice_observation(voice_event_kind::TTS_DONE, Some(msg.to_string()))
}

/// Build a voice_tts_error observation.
pub fn voice_tts_error_observation(
    error: &str,
    utterance_id: &str,
    detail: &str,
) -> ObservationEvent {
    let msg = json!({
        "error": error,
        "utterance_id": utterance_id,
        "detail": detail,
    });
    voice_observation(voice_event_kind::TTS_ERROR, Some(msg.to_string()))
}

// ============================================================================
// Message assertion helpers
// ============================================================================

/// Assert that a Message is a User message containing the expected transcript.
pub fn assert_user_transcript(msg: &Message, expected: &str) {
    match msg {
        Message::User(um) => match &um.content {
            UserContent::Text(text) => {
                assert_eq!(
                    text, expected,
                    "expected User transcript {expected:?}, got {text:?}"
                );
            }
            other => panic!("expected UserContent::Text, got {other:?}"),
        },
        other => panic!("expected Message::User, got {other:?}"),
    }
}

/// Assert that a Message is a Custom message with custom_type == "voice_commit_proof".
pub fn assert_voice_commit_proof(msg: &Message) {
    match msg {
        Message::Custom(cm) => {
            assert_eq!(
                cm.custom_type, "voice_commit_proof",
                "expected custom_type 'voice_commit_proof', got {:?}",
                cm.custom_type
            );
            assert!(
                cm.details.is_some(),
                "voice_commit_proof should have details"
            );
            let details = cm.details.as_ref().unwrap();
            assert!(
                details.get("proof").is_some(),
                "voice_commit_proof details should contain 'proof'"
            );
        }
        other => panic!("expected Message::Custom(voice_commit_proof), got {other:?}"),
    }
}

/// Assert that a Message is a Custom message of type "voice_event" (non-committed voice obs).
pub fn assert_voice_observation_summary(msg: &Message) {
    match msg {
        Message::Custom(cm) => {
            assert_eq!(
                cm.custom_type, "voice_event",
                "expected custom_type 'voice_event', got {:?}",
                cm.custom_type
            );
            assert!(
                cm.content.starts_with("[Voice Observation]"),
                "voice observation summary should start with [Voice Observation]"
            );
        }
        other => panic!("expected Message::Custom(voice_event), got {other:?}"),
    }
}

/// Assert that a Message is a Custom message of type "browser_observations".
pub fn assert_browser_observation_summary(msg: &Message) {
    match msg {
        Message::Custom(cm) => {
            assert_eq!(
                cm.custom_type, "browser_observations",
                "expected custom_type 'browser_observations', got {:?}",
                cm.custom_type
            );
            assert!(
                cm.content.starts_with("[Browser Observation]"),
                "browser observation should start with [Browser Observation]"
            );
        }
        other => panic!("expected Message::Custom(browser_observations), got {other:?}"),
    }
}

/// Extract User transcript from a Message, or None if not a User message.
pub fn extract_user_transcript(msg: &Message) -> Option<&str> {
    match msg {
        Message::User(um) => match &um.content {
            UserContent::Text(text) => Some(text.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// Extract voice_commit_proof details from a Message, or None.
pub fn extract_commit_proof(msg: &Message) -> Option<CommitProof> {
    match msg {
        Message::Custom(cm) if cm.custom_type == "voice_commit_proof" => {
            cm.details.as_ref().and_then(|d| {
                d.get("proof")
                    .and_then(|p| serde_json::from_value::<CommitProof>(p.clone()).ok())
            })
        }
        _ => None,
    }
}
