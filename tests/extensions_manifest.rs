use pi::Error;
use pi::extensions::{
    ExtensionMessage, ExtensionPolicy, ExtensionPolicyMode, PolicyDecision,
    required_capability_for_host_call,
};
use serde_json::json;

fn register_message_json(overrides: serde_json::Value) -> String {
    let mut base = json!({
        "id": "msg-1",
        "version": pi::extensions::PROTOCOL_VERSION,
        "type": "register",
        "payload": {
            "name": "demo",
            "version": "0.1.0",
            "api_version": "1.0",
            "capabilities": ["read"],
            "tools": [],
            "slash_commands": [],
            "event_hooks": []
        }
    });

    if let serde_json::Value::Object(dst) = &mut base {
        if let serde_json::Value::Object(src) = overrides {
            for (k, v) in src {
                dst.insert(k, v);
            }
        }
    }

    base.to_string()
}

#[test]
fn parse_and_validate_register_ok() {
    let json = register_message_json(json!({}));
    let parsed = ExtensionMessage::parse_and_validate(&json).expect("parse");
    assert_eq!(parsed.version, pi::extensions::PROTOCOL_VERSION);
}

#[test]
fn parse_and_validate_allows_unknown_fields() {
    let json = register_message_json(json!({
        "unknown_top_level": 123,
        "payload": {
            "name": "demo",
            "version": "0.1.0",
            "api_version": "1.0",
            "capabilities": ["read"],
            "tools": [],
            "slash_commands": [],
            "event_hooks": [],
            "unknown_payload_field": "ok"
        }
    }));
    ExtensionMessage::parse_and_validate(&json).expect("unknown fields should not reject parse");
}

#[test]
fn parse_and_validate_rejects_missing_type_field() {
    let json = json!({
        "id": "msg-1",
        "version": pi::extensions::PROTOCOL_VERSION,
        "payload": {
            "name": "demo",
            "version": "0.1.0",
            "api_version": "1.0",
            "capabilities": [],
            "tools": [],
            "slash_commands": [],
            "event_hooks": []
        }
    })
    .to_string();

    let err = ExtensionMessage::parse_and_validate(&json).unwrap_err();
    assert!(
        matches!(err, Error::Json(_)),
        "expected json error, got {err}"
    );
    let message = err.to_string();
    assert!(
        message.contains("missing field `type`"),
        "expected actionable missing-field message, got: {message}"
    );
}

#[test]
fn parse_and_validate_rejects_protocol_version_mismatch() {
    let json = register_message_json(json!({ "version": "999.0" }));
    let err = ExtensionMessage::parse_and_validate(&json).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Validation(ref msg)
                if msg.contains("Unsupported extension protocol version")
        ),
        "expected validation error, got {err}"
    );
}

#[test]
fn parse_and_validate_rejects_empty_message_id() {
    let json = register_message_json(json!({ "id": "   " }));
    let err = ExtensionMessage::parse_and_validate(&json).unwrap_err();
    assert!(
        matches!(err, Error::Validation(ref msg) if msg == "Extension message id is empty"),
        "expected validation error, got {err}"
    );
}

#[test]
fn parse_and_validate_rejects_empty_register_name() {
    let json = json!({
        "id": "msg-1",
        "version": pi::extensions::PROTOCOL_VERSION,
        "type": "register",
        "payload": {
            "name": " ",
            "version": "0.1.0",
            "api_version": "1.0",
            "capabilities": [],
            "tools": [],
            "slash_commands": [],
            "event_hooks": []
        }
    })
    .to_string();
    let err = ExtensionMessage::parse_and_validate(&json).unwrap_err();
    assert!(
        matches!(err, Error::Validation(ref msg) if msg == "Extension name is empty"),
        "expected validation error, got {err}"
    );
}

#[test]
fn policy_evaluate_covers_modes_and_deny_list() {
    let mut policy = ExtensionPolicy::default();

    // Prompt mode (default): default_caps are allowed, unknown prompts, deny_caps always deny.
    let read = policy.evaluate("read");
    assert_eq!(read.decision, PolicyDecision::Allow);
    assert_eq!(read.reason, "default_caps");

    let empty = policy.evaluate("   ");
    assert_eq!(empty.decision, PolicyDecision::Deny);
    assert_eq!(empty.reason, "empty_capability");
    assert!(empty.capability.is_empty());

    let http = policy.evaluate("HTTP");
    assert_eq!(http.decision, PolicyDecision::Allow);
    assert_eq!(http.reason, "default_caps");

    let unknown = policy.evaluate("custom_cap");
    assert_eq!(unknown.decision, PolicyDecision::Prompt);
    assert_eq!(unknown.reason, "prompt_required");

    let denied = policy.evaluate("exec");
    assert_eq!(denied.decision, PolicyDecision::Deny);
    assert_eq!(denied.reason, "deny_caps");

    // Strict: unknown is denied (but deny_caps still denies).
    policy.mode = ExtensionPolicyMode::Strict;
    let strict_unknown = policy.evaluate("custom_cap");
    assert_eq!(strict_unknown.decision, PolicyDecision::Deny);
    assert_eq!(strict_unknown.reason, "not_in_default_caps");

    // Permissive: unknown is allowed (but deny_caps still denies).
    policy.mode = ExtensionPolicyMode::Permissive;
    let permissive_unknown = policy.evaluate("custom_cap");
    assert_eq!(permissive_unknown.decision, PolicyDecision::Allow);
    assert_eq!(permissive_unknown.reason, "permissive");

    let permissive_denied = policy.evaluate("ENV");
    assert_eq!(permissive_denied.decision, PolicyDecision::Deny);
    assert_eq!(permissive_denied.reason, "deny_caps");
}

#[test]
fn required_capability_for_host_call_maps_tool_to_capability() {
    assert_eq!(
        required_capability_for_host_call("exec", &json!({})).as_deref(),
        Some("exec")
    );
    assert_eq!(
        required_capability_for_host_call("http", &json!({})).as_deref(),
        Some("http")
    );
    assert_eq!(
        required_capability_for_host_call("session", &json!({})).as_deref(),
        Some("session")
    );
    assert_eq!(
        required_capability_for_host_call("ui", &json!({})).as_deref(),
        Some("ui")
    );
    assert_eq!(
        required_capability_for_host_call("log", &json!({})).as_deref(),
        Some("log")
    );

    assert_eq!(
        required_capability_for_host_call("tool", &json!({ "name": "read" })).as_deref(),
        Some("read")
    );
    assert_eq!(
        required_capability_for_host_call(" TOOL ", &json!({ "name": " READ " })).as_deref(),
        Some("read")
    );
    assert_eq!(
        required_capability_for_host_call("tool", &json!({ "name": "grep" })).as_deref(),
        Some("read")
    );
    assert_eq!(
        required_capability_for_host_call("tool", &json!({ "name": "edit" })).as_deref(),
        Some("write")
    );
    assert_eq!(
        required_capability_for_host_call("tool", &json!({ "name": "bash" })).as_deref(),
        Some("exec")
    );
    assert_eq!(
        required_capability_for_host_call("tool", &json!({ "name": "unknown-tool" })).as_deref(),
        Some("tool")
    );

    assert_eq!(required_capability_for_host_call("tool", &json!({})), None);
    assert_eq!(
        required_capability_for_host_call("unknown", &json!({})),
        None
    );
}
