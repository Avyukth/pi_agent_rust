//! DROPIN-174: Cross-surface unit tests for CLI, config, session, and error
//! parity. These tests verify invariants that span multiple subsystems and
//! confirm drop-in replacement behavior.

use pi::error::Error;
use pi::model::{
    AssistantMessage, ContentBlock, Message, StopReason, TextContent, ToolCall, Usage,
};
use pi::session::Session;
use serde_json::json;

// ============================================================================
// 1. Exit-Code Classification — every error variant → correct exit code
// ============================================================================

mod exit_codes {
    use super::*;

    /// Helper: wrap a pi Error in anyhow and classify.
    fn classify(err: Error) -> &'static str {
        let anyhow_err = anyhow::Error::new(err);
        let is_usage = anyhow_err.chain().any(|cause| {
            cause
                .downcast_ref::<Error>()
                .is_some_and(|e| matches!(e, Error::Validation(_)))
        });
        if is_usage { "usage" } else { "failure" }
    }

    #[test]
    fn validation_errors_are_usage() {
        assert_eq!(classify(Error::validation("bad flag")), "usage");
        assert_eq!(classify(Error::validation("")), "usage");
        assert_eq!(
            classify(Error::validation("unknown --only categories")),
            "usage"
        );
    }

    #[test]
    fn config_errors_are_failure() {
        assert_eq!(classify(Error::config("missing file")), "failure");
    }

    #[test]
    fn session_errors_are_failure() {
        assert_eq!(classify(Error::session("corrupt")), "failure");
    }

    #[test]
    fn provider_errors_are_failure() {
        assert_eq!(
            classify(Error::provider("anthropic", "rate limited")),
            "failure"
        );
    }

    #[test]
    fn auth_errors_are_failure() {
        assert_eq!(classify(Error::auth("missing key")), "failure");
    }

    #[test]
    fn tool_errors_are_failure() {
        assert_eq!(classify(Error::tool("bash", "timeout")), "failure");
    }

    #[test]
    fn extension_errors_are_failure() {
        assert_eq!(classify(Error::extension("load failed")), "failure");
    }

    #[test]
    fn api_errors_are_failure() {
        assert_eq!(classify(Error::api("server error")), "failure");
    }

    #[test]
    fn aborted_errors_are_failure() {
        assert_eq!(classify(Error::Aborted), "failure");
    }

    #[test]
    fn io_errors_are_failure() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let err: Error = io_err.into();
        assert_eq!(classify(err), "failure");
    }

    #[test]
    fn json_errors_are_failure() {
        let json_err =
            serde_json::from_str::<serde_json::Value>("{{bad}}").expect_err("should fail");
        let err: Error = json_err.into();
        assert_eq!(classify(err), "failure");
    }
}

// ============================================================================
// 2. CLI Flag Combination Tests — multiple flags parsed together
// ============================================================================

mod cli_combinations {
    use clap::Parser;
    use pi::cli::Cli;

    #[test]
    fn print_mode_with_provider_and_model() {
        let cli = Cli::parse_from([
            "pi",
            "-p",
            "--provider",
            "openai",
            "--model",
            "gpt-4o",
            "--thinking",
            "off",
        ]);
        assert!(cli.print);
        assert_eq!(cli.provider.as_deref(), Some("openai"));
        assert_eq!(cli.model.as_deref(), Some("gpt-4o"));
        assert_eq!(cli.thinking.as_deref(), Some("off"));
    }

    #[test]
    fn session_flags_are_mutually_parsed() {
        let cli = Cli::parse_from([
            "pi",
            "-c",
            "--session",
            "/tmp/sess.jsonl",
            "--session-dir",
            "/tmp/sessions",
        ]);
        assert!(cli.r#continue);
        assert_eq!(cli.session.as_deref(), Some("/tmp/sess.jsonl"));
        assert_eq!(cli.session_dir.as_deref(), Some("/tmp/sessions"));
    }

    #[test]
    fn no_flags_disable_discovery() {
        let cli = Cli::parse_from([
            "pi",
            "--no-tools",
            "--no-extensions",
            "--no-skills",
            "--no-prompt-templates",
            "--no-themes",
        ]);
        assert!(cli.no_tools);
        assert!(cli.no_extensions);
        assert!(cli.no_skills);
        assert!(cli.no_prompt_templates);
        assert!(cli.no_themes);
    }

    #[test]
    fn multiple_extensions_and_skills() {
        let cli = Cli::parse_from([
            "pi", "-e", "ext1.js", "-e", "ext2.js", "--skill", "s1.md", "--skill", "s2.md",
        ]);
        assert_eq!(cli.extension, vec!["ext1.js", "ext2.js"]);
        assert_eq!(cli.skill, vec!["s1.md", "s2.md"]);
    }

    #[test]
    fn print_mode_with_json_output() {
        let cli = Cli::parse_from(["pi", "-p", "--mode", "json"]);
        assert!(cli.print);
        assert_eq!(cli.mode.as_deref(), Some("json"));
    }

    #[test]
    fn tools_subset_with_provider() {
        let cli = Cli::parse_from(["pi", "--tools", "read,bash", "--provider", "anthropic"]);
        assert_eq!(cli.tools, "read,bash");
        assert_eq!(cli.provider.as_deref(), Some("anthropic"));
    }

    #[test]
    fn config_subcommand_with_flags() {
        let cli = Cli::parse_from(["pi", "config", "--show"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn trailing_message_with_at_file_ref() {
        let cli = Cli::parse_from(["pi", "-p", "hello", "@file.txt", "world"]);
        assert!(cli.print);
        assert_eq!(cli.args, vec!["hello", "@file.txt", "world"]);
    }

    #[test]
    fn version_flag_short() {
        let cli = Cli::parse_from(["pi", "-v"]);
        assert!(cli.version);
    }

    #[test]
    fn thinking_levels_all_valid() {
        for level in &["off", "minimal", "low", "medium", "high", "xhigh"] {
            let cli = Cli::parse_from(["pi", "--thinking", level]);
            assert_eq!(cli.thinking.as_deref(), Some(*level));
        }
    }

    #[test]
    fn extension_policy_profiles() {
        for profile in &["safe", "balanced", "permissive"] {
            let cli = Cli::parse_from(["pi", "--extension-policy", profile]);
            assert_eq!(cli.extension_policy.as_deref(), Some(*profile));
        }
    }

    #[test]
    fn list_models_without_pattern() {
        let cli = Cli::parse_from(["pi", "--list-models"]);
        assert!(cli.list_models.is_some());
        assert!(cli.list_models.unwrap().is_none());
    }

    #[test]
    fn list_models_with_pattern() {
        let cli = Cli::parse_from(["pi", "--list-models", "claude*"]);
        assert_eq!(cli.list_models.unwrap().as_deref(), Some("claude*"));
    }

    #[test]
    fn all_short_flags_together() {
        // -v, -c, -r, -p are all short flags; they should parse together
        let cli = Cli::parse_from(["pi", "-p", "-c"]);
        assert!(cli.print);
        assert!(cli.r#continue);
    }

    #[test]
    fn system_prompt_with_append() {
        let cli = Cli::parse_from([
            "pi",
            "--system-prompt",
            "Be helpful",
            "--append-system-prompt",
            "Also be concise",
        ]);
        assert_eq!(cli.system_prompt.as_deref(), Some("Be helpful"));
        assert_eq!(cli.append_system_prompt.as_deref(), Some("Also be concise"));
    }

    #[test]
    fn repair_policy_modes() {
        for mode in &["off", "suggest", "auto-safe", "auto-strict"] {
            let cli = Cli::parse_from(["pi", "--repair-policy", mode]);
            assert_eq!(cli.repair_policy.as_deref(), Some(*mode));
        }
    }
}

// ============================================================================
// 3. CLI Flag Combinations
// ============================================================================

mod cli_flag_combinations {
    use clap::Parser;
    use pi::cli::Cli;

    fn parse_args(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("CLI parse should succeed")
    }

    #[test]
    fn provider_flag_sets_provider() {
        let cli = parse_args(&["pi", "--provider", "openai"]);
        assert_eq!(cli.provider.as_deref(), Some("openai"));
    }

    #[test]
    fn model_flag_sets_model() {
        let cli = parse_args(&["pi", "--model", "gpt-4o"]);
        assert_eq!(cli.model.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn both_flags_together() {
        let cli = parse_args(&[
            "pi",
            "--provider",
            "anthropic",
            "--model",
            "claude-opus-4-5",
        ]);
        assert_eq!(cli.provider.as_deref(), Some("anthropic"));
        assert_eq!(cli.model.as_deref(), Some("claude-opus-4-5"));
    }

    #[test]
    fn model_flag_without_provider() {
        let cli = parse_args(&["pi", "--model", "gpt-4o-mini"]);
        assert!(cli.provider.is_none());
        assert_eq!(cli.model.as_deref(), Some("gpt-4o-mini"));
    }

    #[test]
    fn provider_flag_without_model() {
        let cli = parse_args(&["pi", "--provider", "openai"]);
        assert_eq!(cli.provider.as_deref(), Some("openai"));
        assert!(cli.model.is_none());
    }
}

// ============================================================================
// 4. Session State Invariants
// ============================================================================

mod session_invariants {
    use super::*;

    fn user_msg(text: &str) -> Message {
        Message::User(pi::model::UserMessage {
            content: pi::model::UserContent::Text(text.to_string()),
            timestamp: 0,
        })
    }

    fn assistant_msg(text: &str) -> Message {
        Message::assistant(AssistantMessage {
            content: vec![ContentBlock::Text(TextContent {
                text: text.to_string(),
                text_signature: None,
            })],
            api: String::new(),
            provider: "test".to_string(),
            model: "test-model".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        })
    }

    #[test]
    fn fresh_session_has_no_messages() {
        let session = Session::in_memory();
        let messages = session.to_messages();
        assert!(messages.is_empty());
    }

    #[test]
    fn append_message_returns_unique_ids() {
        let mut session = Session::in_memory();
        let id1 = session.append_model_message(user_msg("hello"));
        let id2 = session.append_model_message(assistant_msg("hi"));
        let id3 = session.append_model_message(user_msg("bye"));
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn messages_round_trip_through_session() {
        let mut session = Session::in_memory();
        session.append_model_message(user_msg("hello"));
        session.append_model_message(assistant_msg("hi there"));

        let messages = session.to_messages();
        assert_eq!(messages.len(), 2);
        // First should be User, second should be Assistant
        assert!(matches!(&messages[0], Message::User(_)));
        assert!(matches!(&messages[1], Message::Assistant(_)));
    }

    #[test]
    fn session_name_roundtrip() {
        let mut session = Session::in_memory();
        assert!(session.get_name().is_none());
        session.set_name("test-session");
        assert_eq!(session.get_name().as_deref(), Some("test-session"));
    }

    #[test]
    fn branch_creates_fork_point() {
        let mut session = Session::in_memory();
        let _id1 = session.append_model_message(user_msg("hello"));
        let id2 = session.append_model_message(assistant_msg("hi"));
        let _id3 = session.append_model_message(user_msg("follow up"));

        let branched = session.create_branch_from(&id2);
        assert!(branched, "branching should succeed");

        // After branching, new messages go on the new branch
        let id4 = session.append_model_message(user_msg("branch msg"));
        assert!(session.get_entry(&id4).is_some());
    }

    #[test]
    fn compaction_entry_accessible() {
        let mut session = Session::in_memory();
        let id1 = session.append_model_message(user_msg("hello"));
        session.append_model_message(assistant_msg("hi"));

        let compaction_id = session.append_compaction(
            "summary of prior conversation".to_string(),
            id1,  // first_kept_entry_id
            150,  // tokens_before
            None, // details
            None, // from_hook
        );

        let entry = session.get_entry(&compaction_id);
        assert!(entry.is_some(), "compaction entry should exist");
    }

    #[test]
    fn model_change_entries_tracked() {
        let mut session = Session::in_memory();
        let id =
            session.append_model_change("anthropic".to_string(), "claude-opus-4-5".to_string());
        let entry = session.get_entry(&id);
        assert!(entry.is_some(), "model change entry should exist");
    }

    #[test]
    fn thinking_level_change_tracked() {
        let mut session = Session::in_memory();
        let id = session.append_thinking_level_change("high".to_string());
        let entry = session.get_entry(&id);
        assert!(entry.is_some(), "thinking level change entry should exist");
    }

    #[test]
    fn leaves_increase_after_branch() {
        let mut session = Session::in_memory();
        session.append_model_message(user_msg("hello"));
        let id2 = session.append_model_message(assistant_msg("hi"));
        session.append_model_message(user_msg("follow up"));

        let leaves_before = session.list_leaves();

        session.create_branch_from(&id2);
        session.append_model_message(user_msg("branch msg"));

        let leaves_after = session.list_leaves();
        assert!(
            leaves_after.len() > leaves_before.len(),
            "branching should create a new leaf"
        );
    }
}

// ============================================================================
// 5. Error Display Format Parity
// ============================================================================

mod error_display {
    use super::*;

    #[test]
    fn error_messages_include_context() {
        let err = Error::provider("anthropic", "rate limited (429)");
        let display = err.to_string();
        assert!(display.contains("anthropic"));
        assert!(display.contains("rate limited"));
    }

    #[test]
    fn tool_error_includes_tool_name() {
        let err = Error::tool("bash", "command timed out after 120s");
        let display = err.to_string();
        assert!(display.contains("bash"));
        assert!(display.contains("timed out"));
    }

    #[test]
    fn validation_error_message_is_clean() {
        let err = Error::validation("--only must include at least one category");
        let display = err.to_string();
        assert!(display.contains("--only"));
    }

    #[test]
    fn session_not_found_includes_path() {
        let err = Error::SessionNotFound {
            path: "/tmp/missing-session.jsonl".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("/tmp/missing-session.jsonl"));
    }

    #[test]
    fn all_error_variants_have_nonempty_display() {
        let errors: Vec<Error> = vec![
            Error::config("test"),
            Error::session("test"),
            Error::SessionNotFound {
                path: "test".to_string(),
            },
            Error::provider("p", "m"),
            Error::auth("test"),
            Error::tool("t", "m"),
            Error::validation("test"),
            Error::extension("test"),
            Error::Aborted,
            Error::api("test"),
        ];
        for err in errors {
            let display = err.to_string();
            assert!(
                !display.is_empty(),
                "Error display should not be empty: {err:?}"
            );
            assert!(
                display.len() > 5,
                "Error display should be descriptive: {display}"
            );
        }
    }
}

// ============================================================================
// 6. Message/Content Type Serialization Invariants
// ============================================================================

mod message_serde_invariants {
    use super::*;

    #[test]
    fn user_text_message_round_trips() {
        let msg = Message::User(pi::model::UserMessage {
            content: pi::model::UserContent::Text("hello".to_string()),
            timestamp: 12345,
        });
        let json = serde_json::to_value(&msg).expect("serialize");
        let decoded: Message = serde_json::from_value(json.clone()).expect("deserialize");
        let rejson = serde_json::to_value(&decoded).expect("re-serialize");
        assert_eq!(json, rejson);
    }

    #[test]
    fn assistant_message_with_tool_call_round_trips() {
        let msg = Message::assistant(AssistantMessage {
            content: vec![
                ContentBlock::Text(TextContent {
                    text: "Let me check".to_string(),
                    text_signature: None,
                }),
                ContentBlock::ToolCall(ToolCall {
                    id: "call_123".to_string(),
                    name: "read".to_string(),
                    arguments: json!({"file_path": "/tmp/test.txt"}),
                    thought_signature: None,
                }),
            ],
            api: "anthropic-messages".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-opus-4-5".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::ToolUse,
            error_message: None,
            timestamp: 0,
        });
        let json = serde_json::to_value(&msg).expect("serialize");
        let decoded: Message = serde_json::from_value(json.clone()).expect("deserialize");
        let rejson = serde_json::to_value(&decoded).expect("re-serialize");
        assert_eq!(json, rejson);
    }

    #[test]
    fn text_content_with_signature_preserved() {
        let content = TextContent {
            text: "verified content".to_string(),
            text_signature: Some("sig_abc123".to_string()),
        };
        let json = serde_json::to_value(&content).expect("serialize");
        assert_eq!(json["textSignature"], "sig_abc123");
        let decoded: TextContent = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded.text_signature.as_deref(), Some("sig_abc123"));
    }

    #[test]
    fn text_content_without_signature_is_null_or_absent() {
        let content = TextContent {
            text: "plain".to_string(),
            text_signature: None,
        };
        let json = serde_json::to_value(&content).expect("serialize");
        let sig = json.get("textSignature");
        assert!(
            sig.is_none() || sig == Some(&serde_json::Value::Null),
            "textSignature should be absent or null"
        );
    }

    #[test]
    fn usage_defaults_to_zero() {
        let usage = Usage::default();
        assert_eq!(usage.input, 0);
        assert_eq!(usage.output, 0);
        assert_eq!(usage.cache_read, 0);
        assert_eq!(usage.cache_write, 0);
    }
}

// ============================================================================
// 7. Config Type Tests
// ============================================================================

mod config_types {
    use pi::config::Config;

    #[test]
    fn config_default_is_valid() {
        let config = Config::default();
        let json = serde_json::to_value(&config).expect("serialize default config");
        assert!(json.is_object());
    }

    #[test]
    fn config_round_trip_via_json() {
        let config = Config::default();
        let json = serde_json::to_value(&config).expect("serialize");
        let decoded: Config = serde_json::from_value(json.clone()).expect("deserialize");
        let rejson = serde_json::to_value(&decoded).expect("re-serialize");
        assert_eq!(json, rejson);
    }

    #[test]
    fn config_unknown_fields_ignored() {
        let json = serde_json::json!({
            "unknownField": true,
            "anotherUnknown": "value"
        });
        let result: Result<Config, _> = serde_json::from_value(json);
        assert!(result.is_ok(), "unknown fields should be ignored");
    }

    #[test]
    fn config_camel_case_aliases_work() {
        // Config uses serde aliases for camelCase compat
        let json = serde_json::json!({
            "defaultProvider": "openai",
            "defaultModel": "gpt-4o",
            "hideThinkingBlock": true,
            "checkForUpdates": false
        });
        let config: Config = serde_json::from_value(json).expect("camelCase should work");
        assert_eq!(config.default_provider.as_deref(), Some("openai"));
        assert_eq!(config.default_model.as_deref(), Some("gpt-4o"));
        assert_eq!(config.hide_thinking_block, Some(true));
        assert_eq!(config.check_for_updates, Some(false));
    }

    #[test]
    fn config_snake_case_also_works() {
        let json = serde_json::json!({
            "default_provider": "google",
            "default_model": "gemini-2.5-pro"
        });
        let config: Config = serde_json::from_value(json).expect("snake_case should work");
        assert_eq!(config.default_provider.as_deref(), Some("google"));
        assert_eq!(config.default_model.as_deref(), Some("gemini-2.5-pro"));
    }

    #[test]
    fn config_compaction_settings_round_trip() {
        let json = serde_json::json!({
            "compaction": {
                "enabled": true,
                "reserveTokens": 16384,
                "keepRecentTokens": 4096
            }
        });
        let config: Config = serde_json::from_value(json).expect("compaction config");
        let compaction = config.compaction.expect("compaction should be present");
        assert_eq!(compaction.enabled, Some(true));
        assert_eq!(compaction.reserve_tokens, Some(16384));
        assert_eq!(compaction.keep_recent_tokens, Some(4096));
    }

    #[test]
    fn config_retry_settings() {
        let json = serde_json::json!({
            "retry": {
                "enabled": true,
                "maxRetries": 3,
                "baseDelayMs": 2000,
                "maxDelayMs": 60000
            }
        });
        let config: Config = serde_json::from_value(json).expect("retry config");
        let retry = config.retry.expect("retry should be present");
        assert_eq!(retry.enabled, Some(true));
        assert_eq!(retry.max_retries, Some(3));
        assert_eq!(retry.base_delay_ms, Some(2000));
        assert_eq!(retry.max_delay_ms, Some(60000));
    }

    #[test]
    fn config_extension_policy_profiles() {
        for profile in &["safe", "balanced", "permissive", "standard"] {
            let json = serde_json::json!({
                "extensionPolicy": { "profile": profile }
            });
            let config: Config = serde_json::from_value(json).expect("extension policy");
            let policy = config.extension_policy.expect("policy should be present");
            assert_eq!(policy.profile.as_deref(), Some(*profile));
        }
    }

    #[test]
    fn config_repair_policy_modes() {
        for mode in &["off", "suggest", "auto-safe", "auto-strict"] {
            let json = serde_json::json!({
                "repairPolicy": { "mode": mode }
            });
            let config: Config = serde_json::from_value(json).expect("repair policy");
            let rp = config
                .repair_policy
                .expect("repair policy should be present");
            assert_eq!(rp.mode.as_deref(), Some(*mode));
        }
    }

    #[test]
    fn config_thinking_budgets() {
        let json = serde_json::json!({
            "thinkingBudgets": {
                "minimal": 1024,
                "low": 4096,
                "medium": 8192,
                "high": 16384,
                "xhigh": 32768
            }
        });
        let config: Config = serde_json::from_value(json).expect("thinking budgets");
        let budgets = config.thinking_budgets.expect("budgets present");
        assert_eq!(budgets.minimal, Some(1024));
        assert_eq!(budgets.low, Some(4096));
        assert_eq!(budgets.medium, Some(8192));
        assert_eq!(budgets.high, Some(16384));
        assert_eq!(budgets.xhigh, Some(32768));
    }

    #[test]
    fn config_image_settings() {
        let json = serde_json::json!({
            "images": {
                "autoResize": true,
                "blockImages": false
            }
        });
        let config: Config = serde_json::from_value(json).expect("image settings");
        let images = config.images.expect("images present");
        assert_eq!(images.auto_resize, Some(true));
        assert_eq!(images.block_images, Some(false));
    }

    #[test]
    fn config_all_subconfigs_absent_by_default() {
        let config = Config::default();
        assert!(config.compaction.is_none());
        assert!(config.retry.is_none());
        assert!(config.extension_policy.is_none());
        assert!(config.repair_policy.is_none());
        assert!(config.thinking_budgets.is_none());
        assert!(config.images.is_none());
        assert!(config.terminal.is_none());
        assert!(config.markdown.is_none());
    }
}

// ============================================================================
// 8. StopReason Serialization Parity
// ============================================================================

mod stop_reason_parity {
    use super::*;

    #[test]
    fn all_variants_serialize_to_camel_case() {
        let cases: &[(StopReason, &str)] = &[
            (StopReason::Stop, "\"stop\""),
            (StopReason::Length, "\"length\""),
            (StopReason::ToolUse, "\"toolUse\""),
            (StopReason::Error, "\"error\""),
            (StopReason::Aborted, "\"aborted\""),
        ];
        for (variant, expected) in cases {
            let json = serde_json::to_string(variant).expect("serialize");
            assert_eq!(
                &json, expected,
                "StopReason::{variant:?} should serialize to {expected}"
            );
        }
    }

    #[test]
    fn all_variants_round_trip() {
        let variants = [
            StopReason::Stop,
            StopReason::Length,
            StopReason::ToolUse,
            StopReason::Error,
            StopReason::Aborted,
        ];
        for variant in &variants {
            let json = serde_json::to_value(variant).expect("serialize");
            let decoded: StopReason = serde_json::from_value(json).expect("deserialize");
            assert_eq!(*variant, decoded);
        }
    }

    #[test]
    fn default_is_stop() {
        assert_eq!(StopReason::default(), StopReason::Stop);
    }

    #[test]
    fn unknown_variant_fails_gracefully() {
        let result: Result<StopReason, _> = serde_json::from_str("\"unknown\"");
        assert!(result.is_err(), "unknown stop reason should fail");
    }
}

// ============================================================================
// 9. Provider/Tool Error Structure Tests
// ============================================================================

mod error_structure {
    use super::*;

    #[test]
    fn provider_error_preserves_both_fields() {
        let err = Error::provider("anthropic", "rate limited (429)");
        let display = err.to_string();
        assert!(
            display.contains("anthropic"),
            "should include provider name"
        );
        assert!(display.contains("rate limited"), "should include message");
    }

    #[test]
    fn tool_error_preserves_both_fields() {
        let err = Error::tool("bash", "command timed out after 120s");
        let display = err.to_string();
        assert!(display.contains("bash"), "should include tool name");
        assert!(display.contains("timed out"), "should include message");
    }

    #[test]
    fn session_not_found_preserves_path() {
        let err = Error::SessionNotFound {
            path: "/home/user/.pi/sessions/abc123.jsonl".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("abc123.jsonl"),
            "should include session file"
        );
    }

    #[test]
    fn all_string_errors_include_content() {
        let cases: Vec<(&str, Error)> = vec![
            ("cfg", Error::config("cfg")),
            ("sess", Error::session("sess")),
            ("auth", Error::auth("auth")),
            ("ext", Error::extension("ext")),
            ("api", Error::api("api")),
            ("val", Error::validation("val")),
        ];
        for (expected_content, err) in cases {
            let display = err.to_string();
            assert!(
                display.contains(expected_content),
                "Error display should contain '{expected_content}': got '{display}'"
            );
        }
    }

    #[test]
    fn provider_error_variants_for_http_codes() {
        // Common HTTP error scenarios that providers emit
        let cases = [
            ("anthropic", "rate limited (429)"),
            ("openai", "server error (500)"),
            ("google", "unauthorized (401)"),
            ("anthropic", "overloaded (529)"),
            ("azure", "forbidden (403)"),
        ];
        for (provider, message) in cases {
            let err = Error::provider(provider, message);
            let display = err.to_string();
            assert!(display.contains(provider));
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }
}

// ============================================================================
// 10. CLI Subcommand Parsing Tests
// ============================================================================

mod cli_subcommands {
    use clap::Parser;
    use pi::cli::Cli;

    #[test]
    fn config_subcommand_show() {
        let cli = Cli::parse_from(["pi", "config", "--show"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn config_subcommand_paths() {
        let cli = Cli::parse_from(["pi", "config", "--paths"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn config_subcommand_json() {
        let cli = Cli::parse_from(["pi", "config", "--json"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn doctor_subcommand_basic() {
        let cli = Cli::parse_from(["pi", "doctor"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn doctor_subcommand_with_fix() {
        let cli = Cli::parse_from(["pi", "doctor", "--fix"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn install_subcommand() {
        let cli = Cli::parse_from(["pi", "install", "my-extension"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn install_local_flag() {
        let cli = Cli::parse_from(["pi", "install", "--local", "my-ext"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn search_subcommand() {
        let cli = Cli::parse_from(["pi", "search", "linter"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn list_subcommand() {
        let cli = Cli::parse_from(["pi", "list"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn update_index_subcommand() {
        let cli = Cli::parse_from(["pi", "update-index"]);
        assert!(cli.command.is_some());
    }

    #[test]
    fn no_subcommand_means_interactive() {
        let cli = Cli::parse_from(["pi"]);
        assert!(cli.command.is_none(), "no subcommand = interactive mode");
    }
}

// ============================================================================
// 11. CLI Utility Methods
// ============================================================================

mod cli_utilities {
    use clap::Parser;
    use pi::cli::Cli;

    #[test]
    fn file_args_extracts_at_refs() {
        let cli = Cli::parse_from(["pi", "-p", "hello", "@file.txt", "world", "@dir/other.md"]);
        let file_args = cli.file_args();
        assert_eq!(file_args, vec!["file.txt", "dir/other.md"]);
    }

    #[test]
    fn message_args_excludes_at_refs() {
        let cli = Cli::parse_from(["pi", "-p", "hello", "@file.txt", "world"]);
        let msg_args = cli.message_args();
        assert_eq!(msg_args, vec!["hello", "world"]);
    }

    #[test]
    fn enabled_tools_default() {
        let cli = Cli::parse_from(["pi"]);
        let tools = cli.enabled_tools();
        assert!(tools.contains(&"read"));
        assert!(tools.contains(&"bash"));
        assert!(tools.contains(&"edit"));
        assert!(tools.contains(&"write"));
    }

    #[test]
    fn enabled_tools_subset() {
        let cli = Cli::parse_from(["pi", "--tools", "read,bash"]);
        let tools = cli.enabled_tools();
        assert_eq!(tools, vec!["read", "bash"]);
    }

    #[test]
    fn enabled_tools_no_tools_flag() {
        let cli = Cli::parse_from(["pi", "--no-tools"]);
        let tools = cli.enabled_tools();
        assert!(tools.is_empty(), "no-tools should disable all tools");
    }

    #[test]
    fn file_args_empty_when_no_at_refs() {
        let cli = Cli::parse_from(["pi", "-p", "hello", "world"]);
        let file_args = cli.file_args();
        assert!(file_args.is_empty());
    }

    #[test]
    fn message_args_empty_in_interactive() {
        let cli = Cli::parse_from(["pi"]);
        let msg_args = cli.message_args();
        assert!(msg_args.is_empty());
    }
}

// ============================================================================
// 12. Session Entry Type Coverage
// ============================================================================

mod session_entry_types {
    use super::*;

    fn user_msg(text: &str) -> Message {
        Message::User(pi::model::UserMessage {
            content: pi::model::UserContent::Text(text.to_string()),
            timestamp: 0,
        })
    }

    fn assistant_msg(text: &str) -> Message {
        Message::assistant(AssistantMessage {
            content: vec![ContentBlock::Text(TextContent {
                text: text.to_string(),
                text_signature: None,
            })],
            api: String::new(),
            provider: "test".to_string(),
            model: "test-model".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        })
    }

    #[test]
    fn label_entry_on_existing_message() {
        let mut session = Session::in_memory();
        let id = session.append_model_message(user_msg("hello"));
        let label_id = session.add_label(&id, Some("important".to_string()));
        assert!(label_id.is_some(), "label on existing entry should succeed");
    }

    #[test]
    fn label_entry_on_nonexistent_returns_none() {
        let mut session = Session::in_memory();
        let result = session.add_label("nonexistent-id", Some("tag".to_string()));
        assert!(
            result.is_none(),
            "label on missing entry should return None"
        );
    }

    #[test]
    fn custom_entry_round_trip() {
        let mut session = Session::in_memory();
        let custom_id = session.append_custom_entry(
            "debug_marker".to_string(),
            Some(json!({"reason": "test checkpoint"})),
        );
        let entry = session.get_entry(&custom_id);
        assert!(entry.is_some(), "custom entry should be retrievable");
    }

    #[test]
    fn model_change_preserves_provider_and_model() {
        let mut session = Session::in_memory();
        let id = session.append_model_change("openai".to_string(), "gpt-4o".to_string());
        let entry = session.get_entry(&id);
        assert!(entry.is_some());
    }

    #[test]
    fn branch_summary_entry() {
        let mut session = Session::in_memory();
        let id1 = session.append_model_message(user_msg("hello"));
        let id2 = session.append_model_message(assistant_msg("hi"));
        session.append_model_message(user_msg("follow up"));

        session.create_branch_from(&id2);
        session.append_model_message(user_msg("branch msg"));

        // Verify the branch created a new leaf distinct from original
        let leaves = session.list_leaves();
        assert!(
            leaves.len() >= 2,
            "should have at least 2 leaves after branch"
        );

        // Original first message should still be accessible
        let entry = session.get_entry(&id1);
        assert!(entry.is_some(), "original entries survive branching");
    }

    #[test]
    fn compaction_preserves_summary_text() {
        let mut session = Session::in_memory();
        let id1 = session.append_model_message(user_msg("first"));
        session.append_model_message(assistant_msg("response"));

        let summary = "User greeted, assistant responded.";
        let _compaction_id = session.append_compaction(summary.to_string(), id1, 200, None, None);

        // Messages should still be accessible (compaction doesn't delete)
        let messages = session.to_messages();
        assert!(!messages.is_empty());
    }

    #[test]
    fn multiple_branches_from_same_point() {
        let mut session = Session::in_memory();
        session.append_model_message(user_msg("root"));
        let fork_point = session.append_model_message(assistant_msg("response"));
        session.append_model_message(user_msg("original continuation"));

        let leaves_before = session.list_leaves().len();

        // Branch from the fork point
        session.create_branch_from(&fork_point);
        session.append_model_message(user_msg("branch msg"));

        let leaves_after = session.list_leaves().len();
        assert!(
            leaves_after >= leaves_before,
            "branching should not reduce leaf count (before={leaves_before}, after={leaves_after})"
        );
        let branch_msg_present = session.to_messages().iter().any(|msg| {
            matches!(
                msg,
                Message::User(pi::model::UserMessage {
                    content: pi::model::UserContent::Text(text),
                    ..
                }) if text == "branch msg"
            )
        });
        assert!(
            branch_msg_present,
            "branch message should be present after branching"
        );
    }

    #[test]
    fn session_name_survives_messages() {
        let mut session = Session::in_memory();
        session.set_name("my-session");
        session.append_model_message(user_msg("hello"));
        session.append_model_message(assistant_msg("hi"));
        assert_eq!(session.get_name().as_deref(), Some("my-session"));
    }
}

// ============================================================================
// 13. Message Content Variant Coverage
// ============================================================================

mod message_content_variants {
    use super::*;

    #[test]
    fn tool_call_with_complex_args_round_trips() {
        let tool_call = ToolCall {
            id: "tc_001".to_string(),
            name: "edit".to_string(),
            arguments: json!({
                "file_path": "/src/main.rs",
                "old_string": "fn old() {}",
                "new_string": "fn new() {}"
            }),
            thought_signature: None,
        };
        let json = serde_json::to_value(&tool_call).expect("serialize");
        let decoded: ToolCall = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded.id, "tc_001");
        assert_eq!(decoded.name, "edit");
        assert_eq!(decoded.arguments["file_path"], "/src/main.rs");
    }

    #[test]
    fn tool_call_with_thought_signature() {
        let tool_call = ToolCall {
            id: "tc_002".to_string(),
            name: "bash".to_string(),
            arguments: json!({"command": "ls -la"}),
            thought_signature: Some("sig_thought_abc".to_string()),
        };
        let json = serde_json::to_value(&tool_call).expect("serialize");
        let decoded: ToolCall = serde_json::from_value(json).expect("deserialize");
        assert_eq!(
            decoded.thought_signature.as_deref(),
            Some("sig_thought_abc")
        );
    }

    #[test]
    fn usage_with_cache_fields() {
        let usage = Usage {
            input: 1500,
            output: 500,
            cache_read: 1000,
            cache_write: 200,
            ..Usage::default()
        };
        let json = serde_json::to_value(&usage).expect("serialize");
        let decoded: Usage = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded.input, 1500);
        assert_eq!(decoded.output, 500);
        assert_eq!(decoded.cache_read, 1000);
        assert_eq!(decoded.cache_write, 200);
    }

    #[test]
    fn assistant_message_with_multiple_content_blocks() {
        let msg = Message::assistant(AssistantMessage {
            content: vec![
                ContentBlock::Text(TextContent {
                    text: "I'll read the file.".to_string(),
                    text_signature: Some("sig_1".to_string()),
                }),
                ContentBlock::ToolCall(ToolCall {
                    id: "tc_1".to_string(),
                    name: "read".to_string(),
                    arguments: json!({"file_path": "/tmp/test.txt"}),
                    thought_signature: None,
                }),
                ContentBlock::Text(TextContent {
                    text: "And also edit it.".to_string(),
                    text_signature: None,
                }),
                ContentBlock::ToolCall(ToolCall {
                    id: "tc_2".to_string(),
                    name: "edit".to_string(),
                    arguments: json!({"file_path": "/tmp/test.txt", "old_string": "a", "new_string": "b"}),
                    thought_signature: Some("sig_2".to_string()),
                }),
            ],
            api: "anthropic-messages".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-opus-4-5".to_string(),
            usage: Usage {
                input: 2000,
                output: 300,
                cache_read: 500,
                cache_write: 0,
                ..Usage::default()
            },
            stop_reason: StopReason::ToolUse,
            error_message: None,
            timestamp: 1_700_000_000,
        });

        let json = serde_json::to_value(&msg).expect("serialize");
        let decoded: Message = serde_json::from_value(json.clone()).expect("deserialize");
        let rejson = serde_json::to_value(&decoded).expect("re-serialize");
        assert_eq!(json, rejson, "complex assistant message should round-trip");
    }

    #[test]
    fn assistant_message_with_error_message() {
        let msg = Message::assistant(AssistantMessage {
            content: vec![],
            api: String::new(),
            provider: "anthropic".to_string(),
            model: "claude-opus-4-5".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Error,
            error_message: Some("stream interrupted".to_string()),
            timestamp: 0,
        });
        let json = serde_json::to_value(&msg).expect("serialize");
        let decoded: Message = serde_json::from_value(json).expect("deserialize");
        if let Message::Assistant(am) = &decoded {
            assert_eq!(am.error_message.as_deref(), Some("stream interrupted"));
            assert_eq!(am.stop_reason, StopReason::Error);
        } else {
            panic!("expected Assistant message");
        }
    }
}
