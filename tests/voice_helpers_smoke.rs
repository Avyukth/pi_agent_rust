//! Smoke tests for shared voice test helpers (bd-19o.1.8.3).

mod common;

use common::voice_helpers::*;
use pi::chrome::protocol::{voice_event_kind, VoiceTurnCommitted};
use pi::model::Message;

#[test]
fn voice_committed_observation_has_correct_structure() {
    let obs = voice_committed_observation("hello world", None);
    assert_eq!(obs.version, 1);
    assert_eq!(obs.events.len(), 1);
    let entry = &obs.events[0];
    assert_eq!(entry.kind, voice_event_kind::TURN_COMMITTED);
    assert_eq!(entry.source.as_deref(), Some("voice"));
    assert!(entry.message.is_some());

    // Parse the JSON message
    let vtc: VoiceTurnCommitted =
        serde_json::from_str(entry.message.as_ref().unwrap()).expect("parse VoiceTurnCommitted");
    assert_eq!(vtc.transcript, "hello world");
    assert!(vtc.proof.confidence > 0.0);
}

#[test]
fn voice_committed_observation_accepts_custom_proof() {
    let custom_proof = pi::chrome::protocol::CommitProof {
        turn_id: "custom-id".to_string(),
        confidence: 0.5,
        backend: "whisper".to_string(),
        model_id: "base-v1".to_string(),
        timestamp_ms: 9999,
        audio_duration_ms: 500,
        processing_ms: 100,
    };
    let obs = voice_committed_observation("test", Some(custom_proof));
    let vtc: VoiceTurnCommitted =
        serde_json::from_str(obs.events[0].message.as_ref().unwrap()).unwrap();
    assert_eq!(vtc.proof.turn_id, "custom-id");
    assert_eq!(vtc.proof.confidence, 0.5);
}

#[test]
fn voice_stt_partial_observation_has_correct_kind() {
    let obs = voice_stt_partial_observation("hel", 0);
    assert_eq!(obs.events[0].kind, voice_event_kind::STT_PARTIAL);
    assert_eq!(obs.events[0].source.as_deref(), Some("voice"));
}

#[test]
fn voice_stt_final_observation_has_correct_kind() {
    let obs = voice_stt_final_observation("hello world", 0.92, 450);
    assert_eq!(obs.events[0].kind, voice_event_kind::STT_FINAL);
}

#[test]
fn voice_stt_error_observation_has_correct_kind() {
    let obs = voice_stt_error_observation("stt_timeout", "timed out after 5000ms");
    assert_eq!(obs.events[0].kind, voice_event_kind::STT_ERROR);
}

#[test]
fn voice_tts_started_observation_has_correct_kind() {
    let obs = voice_tts_started_observation("utt-001", 42);
    assert_eq!(obs.events[0].kind, voice_event_kind::TTS_STARTED);
}

#[test]
fn voice_tts_done_observation_has_correct_kind() {
    let obs = voice_tts_done_observation("utt-001", 1350);
    assert_eq!(obs.events[0].kind, voice_event_kind::TTS_DONE);
}

#[test]
fn voice_tts_error_observation_has_correct_kind() {
    let obs = voice_tts_error_observation("tts_unavailable", "utt-001", "chrome.tts.speak failed");
    assert_eq!(obs.events[0].kind, voice_event_kind::TTS_ERROR);
}

#[test]
fn all_voice_observations_have_voice_source() {
    let factories: Vec<fn() -> pi::chrome::protocol::ObservationEvent> = vec![
        || voice_stt_partial_observation("test", 0),
        || voice_stt_final_observation("test", 0.9, 100),
        || voice_stt_error_observation("err", "detail"),
        || voice_tts_started_observation("utt", 10),
        || voice_tts_done_observation("utt", 500),
        || voice_tts_error_observation("err", "utt", "detail"),
        || voice_committed_observation("test", None),
    ];
    for factory in factories {
        let obs = factory();
        assert_eq!(
            obs.events[0].source.as_deref(),
            Some("voice"),
            "kind {:?} should have source='voice'",
            obs.events[0].kind
        );
    }
}

#[test]
fn assert_user_transcript_passes_on_match() {
    let msg = Message::User(pi::model::UserMessage {
        content: pi::model::UserContent::Text("hello world".to_string()),
        timestamp: 1000,
    });
    assert_user_transcript(&msg, "hello world");
}

#[test]
#[should_panic(expected = "expected User transcript")]
fn assert_user_transcript_fails_on_mismatch() {
    let msg = Message::User(pi::model::UserMessage {
        content: pi::model::UserContent::Text("wrong".to_string()),
        timestamp: 1000,
    });
    assert_user_transcript(&msg, "hello world");
}

#[test]
#[should_panic(expected = "expected Message::User")]
fn assert_user_transcript_fails_on_custom_msg() {
    let msg = Message::Custom(pi::model::CustomMessage {
        content: "custom".to_string(),
        custom_type: "test".to_string(),
        display: false,
        details: None,
        timestamp: 1000,
    });
    assert_user_transcript(&msg, "hello world");
}

#[test]
fn extract_user_transcript_returns_some_for_user_msg() {
    let msg = Message::User(pi::model::UserMessage {
        content: pi::model::UserContent::Text("test".to_string()),
        timestamp: 1000,
    });
    assert_eq!(extract_user_transcript(&msg), Some("test"));
}

#[test]
fn extract_user_transcript_returns_none_for_custom_msg() {
    let msg = Message::Custom(pi::model::CustomMessage {
        content: "custom".to_string(),
        custom_type: "test".to_string(),
        display: false,
        details: None,
        timestamp: 1000,
    });
    assert_eq!(extract_user_transcript(&msg), None);
}

#[test]
fn default_commit_proof_has_all_fields() {
    let proof = default_commit_proof();
    assert!(!proof.turn_id.is_empty());
    assert!(proof.confidence > 0.0);
    assert!(!proof.backend.is_empty());
    assert!(!proof.model_id.is_empty());
    assert!(proof.timestamp_ms > 0);
    assert!(proof.audio_duration_ms > 0);
    assert!(proof.processing_ms > 0);
}
