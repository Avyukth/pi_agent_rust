use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

const MANIFEST_PATH: &str = "docs/franken-node-kernel-extraction-boundary-manifest.json";
const EXPECTED_SCHEMA: &str = "pi.frankennode.kernel_extraction_boundary_manifest.v1";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_manifest() -> Value {
    let path = repo_root().join(MANIFEST_PATH);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as JSON: {err}", path.display()))
}

fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn as_array<'a>(value: &'a Value, pointer: &str) -> &'a [Value] {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map_or_else(
            || panic!("expected JSON array at pointer {pointer}"),
            Vec::as_slice,
        )
}

fn non_empty_string_set(value: &Value, pointer: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for entry in as_array(value, pointer) {
        let raw = entry
            .as_str()
            .unwrap_or_else(|| panic!("expected string entry at {pointer}"));
        let normalized = raw.trim();
        assert!(
            !normalized.is_empty(),
            "entry at {pointer} must be non-empty"
        );
        out.insert(normalized.to_string());
    }
    out
}

fn module_ownership_index(manifest: &Value) -> HashMap<String, String> {
    let mut ownership = HashMap::new();
    for domain in as_array(manifest, "/boundary_domains") {
        let domain_id = domain
            .get("domain_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .expect("every boundary domain must include non-empty domain_id");
        for module in as_array(domain, "/current_modules") {
            let module_path = module
                .as_str()
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .expect("every current_modules entry must be non-empty string");
            let prior = ownership.insert(module_path.to_string(), domain_id.to_string());
            assert!(
                prior.is_none(),
                "module {module_path} appears in multiple ownership domains: {prior:?} and {domain_id}"
            );
        }
    }
    ownership
}

#[test]
fn kernel_boundary_manifest_exists_and_is_valid_json() {
    let path = repo_root().join(MANIFEST_PATH);
    assert!(
        path.is_file(),
        "missing kernel extraction boundary manifest artifact: {}",
        path.display()
    );
    let _ = load_manifest();
}

#[test]
fn kernel_boundary_manifest_has_expected_schema_and_linkage() {
    let manifest = load_manifest();
    assert_eq!(
        manifest["schema"],
        Value::String(EXPECTED_SCHEMA.to_string())
    );

    let version = manifest["contract_version"]
        .as_str()
        .expect("contract_version must be present");
    assert!(
        parse_semver(version).is_some(),
        "contract_version must be semantic version x.y.z, got: {version}"
    );

    assert_eq!(
        manifest["bead_id"],
        Value::String("bd-3ar8v.7.2".to_string())
    );
    assert_eq!(
        manifest["support_bead_id"],
        Value::String("bd-3ar8v.7.2.1".to_string())
    );
    assert_eq!(
        manifest["target_project_root"],
        Value::String("/dp/franken_node".to_string())
    );
}

#[test]
fn kernel_boundary_manifest_covers_required_core_modules() {
    let manifest = load_manifest();
    let ownership = module_ownership_index(&manifest);

    for required_module in [
        "src/agent_cx.rs",
        "src/scheduler.rs",
        "src/hostcall_queue.rs",
        "src/hostcall_amac.rs",
        "src/extensions.rs",
        "src/extensions_js.rs",
        "src/session.rs",
    ] {
        assert!(
            ownership.contains_key(required_module),
            "required runtime module missing from boundary ownership map: {required_module}"
        );
    }
}

#[test]
fn kernel_boundary_manifest_domain_entries_are_complete() {
    let manifest = load_manifest();
    let domains = as_array(&manifest, "/boundary_domains");
    assert!(
        domains.len() >= 6,
        "boundary_domains should define at least six extraction ownership domains"
    );

    for domain in domains {
        let domain_id = domain
            .get("domain_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .expect("domain_id must be present");
        assert!(!domain_id.is_empty(), "domain_id must be non-empty");

        let target_crate = domain
            .get("target_crate")
            .and_then(Value::as_str)
            .map(str::trim)
            .expect("target_crate must be present");
        assert!(
            !target_crate.is_empty(),
            "target_crate must be non-empty for domain {domain_id}"
        );

        let current_modules = as_array(domain, "/current_modules");
        assert!(
            !current_modules.is_empty(),
            "current_modules must not be empty for domain {domain_id}"
        );

        let target_modules = as_array(domain, "/target_modules");
        assert!(
            !target_modules.is_empty(),
            "target_modules must not be empty for domain {domain_id}"
        );

        let invariants = as_array(domain, "/invariants");
        assert!(
            !invariants.is_empty(),
            "invariants must not be empty for domain {domain_id}"
        );

        let forbidden = as_array(domain, "/forbidden_cross_boundary_refs");
        assert!(
            !forbidden.is_empty(),
            "forbidden_cross_boundary_refs must not be empty for domain {domain_id}"
        );
    }
}

#[test]
fn kernel_boundary_manifest_enforces_fail_closed_ownership_rules() {
    let manifest = load_manifest();
    let ownership_rules = &manifest["ownership_rules"];
    assert_eq!(
        ownership_rules["require_full_module_coverage"].as_bool(),
        Some(true),
        "ownership_rules.require_full_module_coverage must be true"
    );
    assert_eq!(
        ownership_rules["disallow_duplicate_module_ownership"].as_bool(),
        Some(true),
        "ownership_rules.disallow_duplicate_module_ownership must be true"
    );
    assert_eq!(
        ownership_rules["require_explicit_deferred_modules"].as_bool(),
        Some(true),
        "ownership_rules.require_explicit_deferred_modules must be true"
    );

    let banned_pairs = as_array(ownership_rules, "/banned_cross_boundary_pairs");
    assert!(
        !banned_pairs.is_empty(),
        "ownership_rules.banned_cross_boundary_pairs must not be empty"
    );
    for pair in banned_pairs {
        for required in ["from_domain", "to_domain", "reason"] {
            let value = pair
                .get(required)
                .and_then(Value::as_str)
                .map_or("", str::trim);
            assert!(
                !value.is_empty(),
                "banned_cross_boundary_pairs entries must include non-empty {required}"
            );
        }
    }
}

#[test]
fn kernel_boundary_manifest_deferred_modules_are_explicit_and_actionable() {
    let manifest = load_manifest();
    let deferred = as_array(&manifest, "/deferred_modules");
    assert!(
        !deferred.is_empty(),
        "deferred_modules must be non-empty when require_explicit_deferred_modules is true"
    );
    for entry in deferred {
        let module_path = entry
            .get("module_path")
            .and_then(Value::as_str)
            .map_or("", str::trim);
        assert!(
            module_path.starts_with("src/")
                && std::path::Path::new(module_path)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("rs")),
            "deferred module_path must be a src/*.rs path: {module_path}"
        );

        let reason = entry
            .get("reason")
            .and_then(Value::as_str)
            .map_or("", str::trim);
        assert!(
            !reason.is_empty(),
            "deferred entry reason must be non-empty"
        );

        let follow_up_bead = entry
            .get("follow_up_bead")
            .and_then(Value::as_str)
            .map_or("", str::trim);
        assert!(
            follow_up_bead.starts_with("bd-"),
            "deferred entry follow_up_bead must look like bead id, got: {follow_up_bead}"
        );
    }
}

#[test]
fn kernel_boundary_manifest_declares_drift_checks_reintegration_and_logging_fields() {
    let manifest = load_manifest();

    let checks = non_empty_string_set(&manifest, "/drift_detection_contract/required_checks");
    for required in [
        "kernel_boundary.all_modules_mapped_or_deferred",
        "kernel_boundary.no_duplicate_domain_ownership",
        "kernel_boundary.banned_cross_boundary_pairs_absent",
        "kernel_boundary.reintegration_target_list_complete",
    ] {
        assert!(
            checks.contains(required),
            "drift_detection_contract.required_checks missing {required}"
        );
    }

    assert_eq!(
        manifest["drift_detection_contract"]["failure_policy"],
        Value::String("hard_fail".to_string()),
        "drift_detection_contract.failure_policy must be hard_fail"
    );

    assert_eq!(
        manifest["reintegration_linkage"]["required_bead"],
        Value::String("bd-3ar8v.7.13".to_string()),
        "reintegration linkage must point to bd-3ar8v.7.13"
    );

    let replacement_targets =
        non_empty_string_set(&manifest, "/reintegration_linkage/replacement_targets");
    for required in ["src/agent_cx.rs", "src/hostcall_queue.rs", "src/session.rs"] {
        assert!(
            replacement_targets.contains(required),
            "reintegration replacement_targets missing {required}"
        );
    }

    let logging_fields =
        non_empty_string_set(&manifest, "/structured_logging_contract/required_fields");
    for required in [
        "run_id",
        "domain_id",
        "module_path",
        "decision",
        "reason",
        "timestamp_utc",
    ] {
        assert!(
            logging_fields.contains(required),
            "structured_logging_contract.required_fields missing {required}"
        );
    }
}
