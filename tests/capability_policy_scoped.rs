//! Capability policy scoped enforcement tests (bd-k5q5.7.4).
//!
//! Covers:
//!   - Config-based policy resolution (`resolve_extension_policy`)
//!   - `allow_dangerous` toggle removing exec/env from deny_caps
//!   - Config merge logic for `ExtensionPolicyConfig`
//!   - Per-extension scoped enforcement through `evaluate_for` at the policy level
//!   - Prompt cache semantics (cache-key independence, revocation clearing)
//!   - `required_capability_for_host_call()` tool-name → capability mapping
//!   - FsOp parsing and capability mapping (all variants)
//!   - Dispatch edge cases (validation, error codes)
#![allow(clippy::needless_raw_string_hashes)]

use std::future::Future;

use asupersync::runtime::RuntimeBuilder;
use pi::config::{Config, ExtensionPolicyConfig};
use pi::connectors::http::HttpConnector;
use pi::extensions::{
    Capability, ExtensionManager, ExtensionOverride, ExtensionPolicy, ExtensionPolicyMode,
    HostCallContext, HostCallErrorCode, HostCallPayload, PolicyDecision, PolicyProfile,
    dispatch_host_call_shared, required_capability_for_host_call,
};
use pi::tools::ToolRegistry;
use serde_json::json;
use tempfile::tempdir;

// ─── Async helper ─────────────────────────────────────────────────────────

fn run_async<T, Fut>(future: Fut) -> T
where
    Fut: Future<Output = T>,
{
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");
    runtime.block_on(future)
}

// ─── Context helpers ──────────────────────────────────────────────────────

fn make_ctx<'a>(
    tools: &'a ToolRegistry,
    http: &'a HttpConnector,
    policy: &'a ExtensionPolicy,
    extension_id: Option<&'a str>,
) -> HostCallContext<'a> {
    HostCallContext {
        runtime_name: "test",
        extension_id,
        tools,
        http,
        manager: None,
        policy,
        js_runtime: None,
        interceptor: None,
    }
}

fn make_ctx_with_manager<'a>(
    tools: &'a ToolRegistry,
    http: &'a HttpConnector,
    policy: &'a ExtensionPolicy,
    extension_id: Option<&'a str>,
    manager: ExtensionManager,
) -> HostCallContext<'a> {
    HostCallContext {
        runtime_name: "test",
        extension_id,
        tools,
        http,
        manager: Some(manager),
        policy,
        js_runtime: None,
        interceptor: None,
    }
}

fn make_call(
    call_id: &str,
    method: &str,
    capability: &str,
    params: serde_json::Value,
) -> HostCallPayload {
    HostCallPayload {
        call_id: call_id.to_string(),
        capability: capability.to_string(),
        method: method.to_string(),
        params,
        timeout_ms: None,
        cancel_token: None,
        context: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Config-based policy resolution (resolve_extension_policy)
// ═══════════════════════════════════════════════════════════════════════════

mod config_resolution {
    use super::*;

    #[test]
    fn default_config_resolves_to_standard() {
        let config = Config::default();
        let policy = config.resolve_extension_policy(None);
        let standard = PolicyProfile::Standard.to_policy();
        assert_eq!(policy.mode, standard.mode);
        assert_eq!(policy.default_caps, standard.default_caps);
        assert_eq!(policy.deny_caps, standard.deny_caps);
    }

    #[test]
    fn cli_override_safe_profile() {
        let config = Config::default();
        let policy = config.resolve_extension_policy(Some("safe"));
        assert_eq!(policy.mode, ExtensionPolicyMode::Strict);
        assert!(policy.deny_caps.contains(&"exec".to_string()));
        assert!(policy.deny_caps.contains(&"env".to_string()));
    }

    #[test]
    fn cli_override_permissive_profile() {
        let config = Config::default();
        let policy = config.resolve_extension_policy(Some("permissive"));
        assert_eq!(policy.mode, ExtensionPolicyMode::Permissive);
        assert!(policy.deny_caps.is_empty());
    }

    #[test]
    fn cli_override_unknown_name_falls_to_standard() {
        let config = Config::default();
        let policy = config.resolve_extension_policy(Some("nonsense"));
        let standard = PolicyProfile::Standard.to_policy();
        assert_eq!(policy.mode, standard.mode);
    }

    #[test]
    fn cli_override_case_insensitive() {
        let config = Config::default();
        let safe = config.resolve_extension_policy(Some("SAFE"));
        assert_eq!(safe.mode, ExtensionPolicyMode::Strict);

        let perm = config.resolve_extension_policy(Some("Permissive"));
        assert_eq!(perm.mode, ExtensionPolicyMode::Permissive);
    }

    #[test]
    fn config_profile_used_when_no_cli() {
        let config = Config {
            extension_policy: Some(ExtensionPolicyConfig {
                profile: Some("safe".to_string()),
                allow_dangerous: None,
            }),
            ..Default::default()
        };
        let policy = config.resolve_extension_policy(None);
        assert_eq!(policy.mode, ExtensionPolicyMode::Strict);
    }

    #[test]
    fn cli_overrides_config_profile() {
        let config = Config {
            extension_policy: Some(ExtensionPolicyConfig {
                profile: Some("safe".to_string()),
                allow_dangerous: None,
            }),
            ..Default::default()
        };
        // CLI says "permissive", config says "safe": CLI wins.
        let policy = config.resolve_extension_policy(Some("permissive"));
        assert_eq!(policy.mode, ExtensionPolicyMode::Permissive);
    }

    #[test]
    fn allow_dangerous_removes_exec_env_from_deny_caps() {
        let config = Config {
            extension_policy: Some(ExtensionPolicyConfig {
                profile: None,
                allow_dangerous: Some(true),
            }),
            ..Default::default()
        };
        let policy = config.resolve_extension_policy(None);
        assert!(
            !policy.deny_caps.contains(&"exec".to_string()),
            "exec should be removed when allow_dangerous=true"
        );
        assert!(
            !policy.deny_caps.contains(&"env".to_string()),
            "env should be removed when allow_dangerous=true"
        );
    }

    #[test]
    fn allow_dangerous_false_retains_deny_caps() {
        let config = Config {
            extension_policy: Some(ExtensionPolicyConfig {
                profile: None,
                allow_dangerous: Some(false),
            }),
            ..Default::default()
        };
        let policy = config.resolve_extension_policy(None);
        assert!(policy.deny_caps.contains(&"exec".to_string()));
        assert!(policy.deny_caps.contains(&"env".to_string()));
    }

    #[test]
    fn allow_dangerous_with_safe_profile() {
        // Even with "safe" profile, allow_dangerous removes exec/env from deny.
        let config = Config {
            extension_policy: Some(ExtensionPolicyConfig {
                profile: Some("safe".to_string()),
                allow_dangerous: Some(true),
            }),
            ..Default::default()
        };
        let policy = config.resolve_extension_policy(None);
        assert_eq!(policy.mode, ExtensionPolicyMode::Strict);
        assert!(
            !policy.deny_caps.contains(&"exec".to_string()),
            "allow_dangerous should remove exec even in safe profile"
        );
    }

    #[test]
    fn no_extension_policy_config_uses_defaults() {
        let config = Config {
            extension_policy: None,
            ..Default::default()
        };
        let policy = config.resolve_extension_policy(None);
        let standard = PolicyProfile::Standard.to_policy();
        assert_eq!(policy.mode, standard.mode);
        assert_eq!(policy.default_caps, standard.default_caps);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. ExtensionPolicyConfig deserialization and structure
// ═══════════════════════════════════════════════════════════════════════════

mod config_deserialization {
    use super::*;

    #[test]
    fn extension_policy_config_from_json() {
        let json = r#"{"extensionPolicy": {"profile": "safe", "allowDangerous": true}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        let epc = config.extension_policy.expect("should have policy config");
        assert_eq!(epc.profile, Some("safe".to_string()));
        assert_eq!(epc.allow_dangerous, Some(true));
    }

    #[test]
    fn extension_policy_config_snake_case() {
        let json = r#"{"extension_policy": {"profile": "permissive", "allow_dangerous": false}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        let epc = config.extension_policy.expect("should have policy config");
        assert_eq!(epc.profile, Some("permissive".to_string()));
        assert_eq!(epc.allow_dangerous, Some(false));
    }

    #[test]
    fn extension_policy_config_missing_is_none() {
        let json = r#"{}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.extension_policy.is_none());
    }

    #[test]
    fn extension_policy_config_partial_fields() {
        let json = r#"{"extensionPolicy": {"profile": "safe"}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        let epc = config.extension_policy.expect("should have policy config");
        assert_eq!(epc.profile, Some("safe".to_string()));
        assert_eq!(epc.allow_dangerous, None);
    }

    #[test]
    fn extension_policy_config_roundtrip() {
        let config = Config {
            extension_policy: Some(ExtensionPolicyConfig {
                profile: Some("safe".to_string()),
                allow_dangerous: Some(true),
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        let epc = back.extension_policy.expect("roundtrip");
        assert_eq!(epc.profile, Some("safe".to_string()));
        assert_eq!(epc.allow_dangerous, Some(true));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Per-extension scoped enforcement (evaluate_for)
// ═══════════════════════════════════════════════════════════════════════════

mod per_extension_scoped {
    use super::*;

    #[test]
    fn scoped_deny_blocks_allowed_cap_for_one_extension() {
        let mut policy = ExtensionPolicy::default();
        policy.per_extension.insert(
            "untrusted-ext".to_string(),
            ExtensionOverride {
                deny: vec!["http".to_string(), "write".to_string()],
                ..Default::default()
            },
        );

        // For untrusted-ext: http and write are denied despite being in default_caps.
        for cap in ["http", "write"] {
            let check = policy.evaluate_for(cap, Some("untrusted-ext"));
            assert_eq!(
                check.decision,
                PolicyDecision::Deny,
                "{cap} should be denied for untrusted-ext"
            );
            assert_eq!(check.reason, "extension_deny");
        }

        // For a different extension: http and write are still allowed.
        for cap in ["http", "write"] {
            let check = policy.evaluate_for(cap, Some("other-ext"));
            assert_eq!(
                check.decision,
                PolicyDecision::Allow,
                "{cap} should be allowed for other-ext"
            );
        }
    }

    #[test]
    fn scoped_allow_grants_non_default_cap() {
        let mut policy = ExtensionPolicy::default();
        policy.deny_caps.clear(); // Remove global denies for clarity.
        policy.per_extension.insert(
            "privileged-ext".to_string(),
            ExtensionOverride {
                allow: vec!["ui".to_string(), "log".to_string()],
                ..Default::default()
            },
        );

        // ui and log are NOT in default_caps. In Prompt mode, they'd normally prompt.
        // But for privileged-ext, they are in extension_allow.
        for cap in ["ui", "log"] {
            let check = policy.evaluate_for(cap, Some("privileged-ext"));
            assert_eq!(
                check.decision,
                PolicyDecision::Allow,
                "{cap} should be allowed for privileged-ext"
            );
            assert_eq!(check.reason, "extension_allow");
        }

        // For other extensions: prompt (default mode is Prompt).
        for cap in ["ui", "log"] {
            let check = policy.evaluate_for(cap, Some("other-ext"));
            assert_eq!(
                check.decision,
                PolicyDecision::Prompt,
                "{cap} should prompt for other-ext"
            );
        }
    }

    #[test]
    fn scoped_mode_override_strict_restricts_extension() {
        let mut policy = ExtensionPolicy::default();
        policy.deny_caps.clear();
        policy.per_extension.insert(
            "sandboxed".to_string(),
            ExtensionOverride {
                mode: Some(ExtensionPolicyMode::Strict),
                ..Default::default()
            },
        );

        // Global mode = Prompt. "tool" (not in default_caps) would prompt.
        let check = policy.evaluate_for("tool", None);
        assert_eq!(check.decision, PolicyDecision::Prompt);

        // For sandboxed: Strict mode → deny.
        let check = policy.evaluate_for("tool", Some("sandboxed"));
        assert_eq!(check.decision, PolicyDecision::Deny);
        assert_eq!(check.reason, "not_in_default_caps");
    }

    #[test]
    fn scoped_mode_override_permissive_relaxes_extension() {
        let mut policy = ExtensionPolicy::default();
        policy.deny_caps.clear();
        policy.per_extension.insert(
            "free-ext".to_string(),
            ExtensionOverride {
                mode: Some(ExtensionPolicyMode::Permissive),
                ..Default::default()
            },
        );

        // "tool" not in default_caps. Global Prompt → prompts.
        let check = policy.evaluate_for("tool", None);
        assert_eq!(check.decision, PolicyDecision::Prompt);

        // For free-ext: Permissive → allow.
        let check = policy.evaluate_for("tool", Some("free-ext"));
        assert_eq!(check.decision, PolicyDecision::Allow);
        assert_eq!(check.reason, "permissive");
    }

    #[test]
    fn scoped_deny_wins_over_scoped_allow_for_same_cap() {
        let mut policy = ExtensionPolicy::default();
        policy.deny_caps.clear();
        policy.per_extension.insert(
            "conflicted".to_string(),
            ExtensionOverride {
                allow: vec!["exec".to_string()],
                deny: vec!["exec".to_string()],
                ..Default::default()
            },
        );

        // Extension deny takes highest precedence (layer 1).
        let check = policy.evaluate_for("exec", Some("conflicted"));
        assert_eq!(check.decision, PolicyDecision::Deny);
        assert_eq!(check.reason, "extension_deny");
    }

    #[test]
    fn multiple_extensions_independent_scoping() {
        let mut policy = ExtensionPolicy::default();
        policy.deny_caps.clear();

        policy.per_extension.insert(
            "reader-only".to_string(),
            ExtensionOverride {
                deny: vec!["write".to_string(), "exec".to_string()],
                ..Default::default()
            },
        );
        policy.per_extension.insert(
            "writer-only".to_string(),
            ExtensionOverride {
                deny: vec!["read".to_string(), "exec".to_string()],
                ..Default::default()
            },
        );

        // reader-only: read allowed, write denied.
        assert_eq!(
            policy
                .evaluate_for("read", Some("reader-only"))
                .decision,
            PolicyDecision::Allow
        );
        assert_eq!(
            policy
                .evaluate_for("write", Some("reader-only"))
                .decision,
            PolicyDecision::Deny
        );

        // writer-only: write allowed, read denied.
        assert_eq!(
            policy
                .evaluate_for("write", Some("writer-only"))
                .decision,
            PolicyDecision::Allow
        );
        assert_eq!(
            policy
                .evaluate_for("read", Some("writer-only"))
                .decision,
            PolicyDecision::Deny
        );
    }

    #[test]
    fn scoped_allow_cannot_bypass_global_deny_caps() {
        let mut policy = ExtensionPolicy::default(); // deny_caps: [exec, env]
        policy.per_extension.insert(
            "sneaky-ext".to_string(),
            ExtensionOverride {
                allow: vec!["exec".to_string(), "env".to_string()],
                ..Default::default()
            },
        );

        // Global deny_caps is layer 2, extension allow is layer 3 → deny wins.
        assert_eq!(
            policy
                .evaluate_for("exec", Some("sneaky-ext"))
                .decision,
            PolicyDecision::Deny
        );
        assert_eq!(
            policy
                .evaluate_for("exec", Some("sneaky-ext"))
                .reason,
            "deny_caps"
        );
    }

    #[test]
    fn evaluate_for_with_no_override_same_as_evaluate() {
        let policy = ExtensionPolicy::default();
        for cap in ["read", "write", "http", "exec", "env", "ui", "tool"] {
            let a = policy.evaluate(cap);
            let b = policy.evaluate_for(cap, Some("no-override-ext"));
            assert_eq!(
                a.decision, b.decision,
                "evaluate and evaluate_for should agree for {cap} without overrides"
            );
            assert_eq!(a.reason, b.reason);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Prompt cache semantics (ExtensionManager)
// ═══════════════════════════════════════════════════════════════════════════

mod prompt_cache {
    use super::*;

    #[test]
    fn cache_populated_and_retrieved() {
        let manager = ExtensionManager::new();
        manager.cache_policy_prompt_decision("ext-a", "exec", true);

        let cached = manager.cached_policy_prompt_decision("ext-a", "exec");
        assert_eq!(cached, Some(true));
    }

    #[test]
    fn cache_miss_returns_none() {
        let manager = ExtensionManager::new();
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-a", "exec"),
            None
        );
    }

    #[test]
    fn cache_keyed_by_extension_and_capability() {
        let manager = ExtensionManager::new();
        manager.cache_policy_prompt_decision("ext-a", "exec", true);
        manager.cache_policy_prompt_decision("ext-a", "http", false);
        manager.cache_policy_prompt_decision("ext-b", "exec", false);

        assert_eq!(
            manager.cached_policy_prompt_decision("ext-a", "exec"),
            Some(true)
        );
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-a", "http"),
            Some(false)
        );
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-b", "exec"),
            Some(false)
        );
        // Different ext+cap: miss.
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-b", "http"),
            None
        );
    }

    #[test]
    fn cache_overwrite_updates_decision() {
        let manager = ExtensionManager::new();
        manager.cache_policy_prompt_decision("ext-a", "exec", true);
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-a", "exec"),
            Some(true)
        );

        // Overwrite with deny.
        manager.cache_policy_prompt_decision("ext-a", "exec", false);
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-a", "exec"),
            Some(false)
        );
    }

    #[test]
    fn revoke_clears_extension_cache() {
        let manager = ExtensionManager::new();
        manager.cache_policy_prompt_decision("ext-a", "exec", true);
        manager.cache_policy_prompt_decision("ext-a", "http", true);
        manager.cache_policy_prompt_decision("ext-b", "exec", false);

        manager.revoke_extension_permissions("ext-a");

        // ext-a entries cleared.
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-a", "exec"),
            None
        );
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-a", "http"),
            None
        );
        // ext-b unaffected.
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-b", "exec"),
            Some(false)
        );
    }

    #[test]
    fn reset_all_clears_all_cache_entries() {
        let manager = ExtensionManager::new();
        manager.cache_policy_prompt_decision("ext-a", "exec", true);
        manager.cache_policy_prompt_decision("ext-b", "http", false);

        manager.reset_all_permissions();

        assert_eq!(
            manager.cached_policy_prompt_decision("ext-a", "exec"),
            None
        );
        assert_eq!(
            manager.cached_policy_prompt_decision("ext-b", "http"),
            None
        );
        assert!(manager.list_permissions().is_empty());
    }

    #[test]
    fn list_permissions_reflects_cache() {
        let manager = ExtensionManager::new();
        manager.cache_policy_prompt_decision("ext-a", "exec", true);
        manager.cache_policy_prompt_decision("ext-a", "http", false);

        let perms = manager.list_permissions();
        assert!(perms.contains_key("ext-a"));
        let ext_a = &perms["ext-a"];
        assert_eq!(ext_a.get("exec"), Some(&true));
        assert_eq!(ext_a.get("http"), Some(&false));
    }

    #[test]
    fn revoke_nonexistent_extension_is_noop() {
        let manager = ExtensionManager::new();
        manager.cache_policy_prompt_decision("ext-a", "exec", true);

        // Revoking a nonexistent extension should not panic or affect others.
        manager.revoke_extension_permissions("nonexistent");

        assert_eq!(
            manager.cached_policy_prompt_decision("ext-a", "exec"),
            Some(true)
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. required_capability_for_host_call: tool name → capability mapping
// ═══════════════════════════════════════════════════════════════════════════

mod tool_capability_mapping {
    use super::*;

    fn tool_call(tool_name: &str) -> HostCallPayload {
        HostCallPayload {
            call_id: format!("test-tool-{tool_name}"),
            capability: "tool".to_string(),
            method: "tool".to_string(),
            params: json!({"name": tool_name, "input": {}}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        }
    }

    #[test]
    fn tool_read_maps_to_read() {
        assert_eq!(
            required_capability_for_host_call(&tool_call("read")).as_deref(),
            Some("read")
        );
    }

    #[test]
    fn tool_grep_maps_to_read() {
        assert_eq!(
            required_capability_for_host_call(&tool_call("grep")).as_deref(),
            Some("read")
        );
    }

    #[test]
    fn tool_find_maps_to_read() {
        assert_eq!(
            required_capability_for_host_call(&tool_call("find")).as_deref(),
            Some("read")
        );
    }

    #[test]
    fn tool_ls_maps_to_read() {
        assert_eq!(
            required_capability_for_host_call(&tool_call("ls")).as_deref(),
            Some("read")
        );
    }

    #[test]
    fn tool_write_maps_to_write() {
        assert_eq!(
            required_capability_for_host_call(&tool_call("write")).as_deref(),
            Some("write")
        );
    }

    #[test]
    fn tool_edit_maps_to_write() {
        assert_eq!(
            required_capability_for_host_call(&tool_call("edit")).as_deref(),
            Some("write")
        );
    }

    #[test]
    fn tool_bash_maps_to_exec() {
        assert_eq!(
            required_capability_for_host_call(&tool_call("bash")).as_deref(),
            Some("exec")
        );
    }

    #[test]
    fn tool_unknown_maps_to_tool() {
        assert_eq!(
            required_capability_for_host_call(&tool_call("custom-tool")).as_deref(),
            Some("tool")
        );
    }

    #[test]
    fn tool_name_case_insensitive() {
        assert_eq!(
            required_capability_for_host_call(&tool_call("READ")).as_deref(),
            Some("read")
        );
        assert_eq!(
            required_capability_for_host_call(&tool_call("BASH")).as_deref(),
            Some("exec")
        );
        assert_eq!(
            required_capability_for_host_call(&tool_call("Edit")).as_deref(),
            Some("write")
        );
    }

    #[test]
    fn tool_name_trimmed() {
        let mut call = tool_call("read");
        call.params = json!({"name": "  read  ", "input": {}});
        assert_eq!(
            required_capability_for_host_call(&call).as_deref(),
            Some("read")
        );
    }

    #[test]
    fn tool_empty_name_returns_none() {
        let mut call = tool_call("");
        call.params = json!({"name": "", "input": {}});
        assert!(required_capability_for_host_call(&call).is_none());
    }

    #[test]
    fn tool_missing_name_returns_none() {
        let call = HostCallPayload {
            call_id: "test-no-name".to_string(),
            capability: "tool".to_string(),
            method: "tool".to_string(),
            params: json!({"input": {}}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        assert!(required_capability_for_host_call(&call).is_none());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. FsOp parsing and capability mapping
// ═══════════════════════════════════════════════════════════════════════════

mod fs_op_mapping {
    use super::*;

    fn fs_call(op: &str) -> HostCallPayload {
        HostCallPayload {
            call_id: format!("test-fs-{op}"),
            capability: "read".to_string(),
            method: "fs".to_string(),
            params: json!({"op": op, "path": "/tmp/test"}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        }
    }

    #[test]
    fn fs_read_maps_to_read() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("read")).as_deref(),
            Some("read")
        );
    }

    #[test]
    fn fs_list_maps_to_read() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("list")).as_deref(),
            Some("read")
        );
    }

    #[test]
    fn fs_readdir_maps_to_read() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("readdir")).as_deref(),
            Some("read")
        );
    }

    #[test]
    fn fs_stat_maps_to_read() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("stat")).as_deref(),
            Some("read")
        );
    }

    #[test]
    fn fs_write_maps_to_write() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("write")).as_deref(),
            Some("write")
        );
    }

    #[test]
    fn fs_mkdir_maps_to_write() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("mkdir")).as_deref(),
            Some("write")
        );
    }

    #[test]
    fn fs_delete_maps_to_write() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("delete")).as_deref(),
            Some("write")
        );
    }

    #[test]
    fn fs_remove_maps_to_write() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("remove")).as_deref(),
            Some("write")
        );
    }

    #[test]
    fn fs_rm_maps_to_write() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("rm")).as_deref(),
            Some("write")
        );
    }

    #[test]
    fn fs_op_case_insensitive() {
        assert_eq!(
            required_capability_for_host_call(&fs_call("READ")).as_deref(),
            Some("read")
        );
        assert_eq!(
            required_capability_for_host_call(&fs_call("DELETE")).as_deref(),
            Some("write")
        );
    }

    #[test]
    fn fs_unknown_op_returns_none() {
        assert!(required_capability_for_host_call(&fs_call("truncate")).is_none());
    }

    #[test]
    fn fs_empty_op_returns_none() {
        assert!(required_capability_for_host_call(&fs_call("")).is_none());
    }

    #[test]
    fn fs_missing_op_returns_none() {
        let call = HostCallPayload {
            call_id: "test-fs-no-op".to_string(),
            capability: "read".to_string(),
            method: "fs".to_string(),
            params: json!({"path": "/tmp/test"}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        assert!(required_capability_for_host_call(&call).is_none());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Direct method → capability mapping
// ═══════════════════════════════════════════════════════════════════════════

mod method_capability_mapping {
    use super::*;

    fn method_call(method: &str) -> HostCallPayload {
        HostCallPayload {
            call_id: format!("test-method-{method}"),
            capability: method.to_string(),
            method: method.to_string(),
            params: json!({}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        }
    }

    #[test]
    fn all_direct_methods_map_correctly() {
        let expected = [
            ("exec", "exec"),
            ("env", "env"),
            ("http", "http"),
            ("session", "session"),
            ("ui", "ui"),
            ("events", "events"),
            ("log", "log"),
        ];
        for (method, expected_cap) in expected {
            assert_eq!(
                required_capability_for_host_call(&method_call(method)).as_deref(),
                Some(expected_cap),
                "method {method} should map to {expected_cap}"
            );
        }
    }

    #[test]
    fn unknown_method_returns_none() {
        assert!(required_capability_for_host_call(&method_call("compute")).is_none());
        assert!(required_capability_for_host_call(&method_call("gpu")).is_none());
    }

    #[test]
    fn method_case_insensitive() {
        assert_eq!(
            required_capability_for_host_call(&method_call("EXEC")).as_deref(),
            Some("exec")
        );
        assert_eq!(
            required_capability_for_host_call(&method_call("Http")).as_deref(),
            Some("http")
        );
    }

    #[test]
    fn method_trimmed() {
        let call = HostCallPayload {
            call_id: "test-trim".to_string(),
            capability: "exec".to_string(),
            method: "  exec  ".to_string(),
            params: json!({}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        assert_eq!(
            required_capability_for_host_call(&call).as_deref(),
            Some("exec")
        );
    }

    #[test]
    fn empty_method_returns_none() {
        let call = HostCallPayload {
            call_id: "test-empty".to_string(),
            capability: "".to_string(),
            method: "".to_string(),
            params: json!({}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        assert!(required_capability_for_host_call(&call).is_none());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Dispatch validation edge cases
// ═══════════════════════════════════════════════════════════════════════════

mod dispatch_validation {
    use super::*;

    #[test]
    fn empty_call_id_returns_invalid_request() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy::default();
        let ctx = make_ctx(&tools, &http, &policy, None);

        let call = HostCallPayload {
            call_id: String::new(),
            capability: "read".to_string(),
            method: "tool".to_string(),
            params: json!({"name": "read", "input": {}}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("error");
            assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
        });
    }

    #[test]
    fn non_object_params_returns_invalid_request() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy::default();
        let ctx = make_ctx(&tools, &http, &policy, None);

        let call = HostCallPayload {
            call_id: "bad-params".to_string(),
            capability: "read".to_string(),
            method: "tool".to_string(),
            params: json!("not an object"),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("error");
            assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
            assert_eq!(result.call_id, "bad-params");
        });
    }

    #[test]
    fn empty_capability_returns_invalid_request() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy::default();
        let ctx = make_ctx(&tools, &http, &policy, None);

        let call = HostCallPayload {
            call_id: "empty-cap".to_string(),
            capability: String::new(),
            method: "tool".to_string(),
            params: json!({}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("error");
            assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
        });
    }

    #[test]
    fn empty_method_returns_invalid_request() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy::default();
        let ctx = make_ctx(&tools, &http, &policy, None);

        let call = HostCallPayload {
            call_id: "empty-method".to_string(),
            capability: "read".to_string(),
            method: String::new(),
            params: json!({}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("error");
            assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
        });
    }

    #[test]
    fn whitespace_only_call_id_returns_invalid_request() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy::default();
        let ctx = make_ctx(&tools, &http, &policy, None);

        let call = HostCallPayload {
            call_id: "   ".to_string(),
            capability: "read".to_string(),
            method: "tool".to_string(),
            params: json!({}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("error");
            assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. Scoped enforcement through dispatch
// ═══════════════════════════════════════════════════════════════════════════

mod scoped_dispatch {
    use super::*;

    #[test]
    fn dispatch_denied_cap_with_extension_id() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy::default();
        let ctx = make_ctx(&tools, &http, &policy, Some("my-extension"));

        // exec is in deny_caps by default.
        let call = make_call("scoped-exec", "exec", "exec", json!({"cmd": "ls"}));

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("error");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(err.message.contains("exec"));
            assert!(err.message.contains("deny_caps"));
        });
    }

    #[test]
    fn dispatch_allowed_cap_passes_to_handler() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy::default();
        let ctx = make_ctx(&tools, &http, &policy, Some("good-ext"));

        // read is in default_caps.
        let call = make_call(
            "scoped-read",
            "tool",
            "read",
            json!({"name": "read", "input": {"path": "/nonexistent"}}),
        );

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            // Should NOT be denied by policy.
            if result.is_error {
                let err = result.error.as_ref().unwrap();
                assert_ne!(
                    err.code,
                    HostCallErrorCode::Denied,
                    "read should pass policy"
                );
            }
        });
    }

    #[test]
    fn dispatch_prompt_without_manager_falls_to_deny() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        // Custom policy: exec NOT in deny_caps, NOT in default_caps → Prompt.
        let policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Prompt,
            deny_caps: Vec::new(),
            default_caps: vec!["read".to_string()],
            ..Default::default()
        };
        // No manager → prompt resolution falls back to deny.
        let ctx = make_ctx(&tools, &http, &policy, Some("test-ext"));

        let call = make_call("prompt-deny", "exec", "exec", json!({"cmd": "ls"}));

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error, "prompt without manager should deny");
            let err = result.error.expect("error");
            assert_eq!(err.code, HostCallErrorCode::Denied);
        });
    }

    #[test]
    fn dispatch_prompt_with_cached_allow_succeeds() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Prompt,
            deny_caps: Vec::new(),
            default_caps: vec!["read".to_string()],
            ..Default::default()
        };

        let manager = ExtensionManager::new();
        // Pre-populate the cache with an allow decision for exec + test-ext.
        manager.cache_policy_prompt_decision("test-ext", "exec", true);

        let ctx = make_ctx_with_manager(&tools, &http, &policy, Some("test-ext"), manager);

        let call = make_call("cached-allow", "exec", "exec", json!({"cmd": "ls"}));

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            // Should NOT be denied (cached allow).
            if result.is_error {
                let err = result.error.as_ref().unwrap();
                assert_ne!(
                    err.code,
                    HostCallErrorCode::Denied,
                    "exec should be allowed via cache"
                );
            }
        });
    }

    #[test]
    fn dispatch_prompt_with_cached_deny_blocks() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Prompt,
            deny_caps: Vec::new(),
            default_caps: vec!["read".to_string()],
            ..Default::default()
        };

        let manager = ExtensionManager::new();
        manager.cache_policy_prompt_decision("test-ext", "exec", false);

        let ctx = make_ctx_with_manager(&tools, &http, &policy, Some("test-ext"), manager);

        let call = make_call("cached-deny", "exec", "exec", json!({"cmd": "ls"}));

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error, "cached deny should block");
            let err = result.error.expect("error");
            assert_eq!(err.code, HostCallErrorCode::Denied);
        });
    }

    #[test]
    fn dispatch_prompt_cache_keyed_by_extension_id() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Prompt,
            deny_caps: Vec::new(),
            default_caps: vec!["read".to_string()],
            ..Default::default()
        };

        let manager = ExtensionManager::new();
        // Cache allow for ext-a, but NOT for ext-b.
        manager.cache_policy_prompt_decision("ext-a", "exec", true);

        // ext-a: cached allow → should pass.
        let ctx_a =
            make_ctx_with_manager(&tools, &http, &policy, Some("ext-a"), manager.clone());
        let call_a = make_call("ext-a-exec", "exec", "exec", json!({"cmd": "ls"}));

        run_async(async {
            let result = dispatch_host_call_shared(&ctx_a, call_a).await;
            if result.is_error {
                let err = result.error.as_ref().unwrap();
                assert_ne!(
                    err.code,
                    HostCallErrorCode::Denied,
                    "ext-a should pass via cache"
                );
            }
        });

        // ext-b: no cache → prompt → no manager UI → deny.
        let ctx_b =
            make_ctx_with_manager(&tools, &http, &policy, Some("ext-b"), manager);
        let call_b = make_call("ext-b-exec", "exec", "exec", json!({"cmd": "ls"}));

        run_async(async {
            let result = dispatch_host_call_shared(&ctx_b, call_b).await;
            assert!(result.is_error, "ext-b should be denied (no cache hit)");
            let err = result.error.expect("error");
            assert_eq!(err.code, HostCallErrorCode::Denied);
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Policy profile coverage
// ═══════════════════════════════════════════════════════════════════════════

mod policy_profiles {
    use super::*;

    #[test]
    fn safe_profile_denies_all_dangerous_caps() {
        let policy = PolicyProfile::Safe.to_policy();
        for cap in Capability::dangerous_list() {
            let check = policy.evaluate(cap.as_str());
            assert_eq!(
                check.decision,
                PolicyDecision::Deny,
                "Safe profile should deny {cap}"
            );
        }
    }

    #[test]
    fn safe_profile_denies_unknown_caps() {
        let policy = PolicyProfile::Safe.to_policy();
        // ui, log, tool are not in default_caps. Strict mode → deny.
        for cap in ["ui", "log", "tool"] {
            let check = policy.evaluate(cap);
            assert_eq!(
                check.decision,
                PolicyDecision::Deny,
                "Safe/Strict should deny {cap}"
            );
        }
    }

    #[test]
    fn standard_profile_prompts_for_unknown_caps() {
        let policy = PolicyProfile::Standard.to_policy();
        for cap in ["ui", "log", "tool"] {
            let check = policy.evaluate(cap);
            assert_eq!(
                check.decision,
                PolicyDecision::Prompt,
                "Standard should prompt for {cap}"
            );
        }
    }

    #[test]
    fn permissive_profile_allows_everything_except_nothing() {
        let policy = PolicyProfile::Permissive.to_policy();
        assert!(policy.deny_caps.is_empty(), "Permissive has no deny_caps");
        for cap in ["exec", "env", "ui", "log", "tool", "read", "custom"] {
            let check = policy.evaluate(cap);
            assert_eq!(
                check.decision,
                PolicyDecision::Allow,
                "Permissive should allow {cap}"
            );
        }
    }

    #[test]
    fn all_profiles_allow_default_safe_caps() {
        let safe_caps = ["read", "write", "http", "events", "session"];
        for profile in [
            PolicyProfile::Safe,
            PolicyProfile::Standard,
            PolicyProfile::Permissive,
        ] {
            let policy = profile.to_policy();
            for cap in &safe_caps {
                let check = policy.evaluate(cap);
                assert_eq!(
                    check.decision,
                    PolicyDecision::Allow,
                    "{profile:?} should allow {cap}"
                );
            }
        }
    }
}
