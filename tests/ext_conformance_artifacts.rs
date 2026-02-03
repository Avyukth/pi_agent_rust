use pi::extensions::CompatibilityScanner;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_files_recursive(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn relative_posix(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn digest_artifact_dir(dir: &Path) -> io::Result<String> {
    let mut files = Vec::new();
    collect_files_recursive(dir, &mut files)?;
    files.sort_by_key(|left| relative_posix(dir, left));

    let mut hasher = Sha256::new();
    for path in files {
        let rel = relative_posix(dir, &path);
        hasher.update(b"file\0");
        hasher.update(rel.as_bytes());
        hasher.update(b"\0");
        hasher.update(&fs::read(&path)?);
        hasher.update(b"\0");
    }

    Ok(hex_lower(&hasher.finalize()))
}

#[test]
fn test_compat_scanner_unit_fixture_ordering() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    fs::write(
        root.join("b.ts"),
        "import fs from 'fs';\npi.tool('read', {});\nnew Function('return 1');\n",
    )
    .expect("write b.ts");

    fs::create_dir_all(root.join("sub")).expect("mkdir sub");
    fs::write(
        root.join("sub/a.ts"),
        "import { spawn } from 'child_process';\nprocess.env.PATH;\n",
    )
    .expect("write sub/a.ts");

    let scanner = CompatibilityScanner::new(root.to_path_buf());
    let ledger = scanner.scan_root().expect("scan root");
    let text = ledger.to_json_pretty().expect("ledger json");
    insta::assert_snapshot!("compat_scanner_unit_fixture_ordering", text);
}

#[test]
fn test_ext_conformance_artifacts_match_manifest_checksums() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let manifest_path = repo_root.join("docs/extension-sample.json");
    let manifest_bytes = fs::read(&manifest_path).expect("read docs/extension-sample.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("parse docs/extension-sample.json");

    let items = manifest
        .get("items")
        .and_then(serde_json::Value::as_array)
        .expect("docs/extension-sample.json: items[]");

    for item in items {
        let id = item
            .get("id")
            .and_then(serde_json::Value::as_str)
            .expect("docs/extension-sample.json: items[].id");

        let expected = item
            .pointer("/checksum/sha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        assert!(
            !expected.is_empty(),
            "docs/extension-sample.json: missing checksum.sha256 for {id}"
        );

        let artifact_dir = repo_root.join("tests/ext_conformance/artifacts").join(id);
        assert!(
            artifact_dir.is_dir(),
            "missing artifact directory for {id}: {}",
            artifact_dir.display()
        );

        let actual =
            digest_artifact_dir(&artifact_dir).unwrap_or_else(|err| panic!("digest {id}: {err}"));
        assert_eq!(actual, expected, "artifact checksum mismatch for {id}");
    }
}

#[test]
fn test_ext_conformance_pinned_sample_compat_ledger_snapshot() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_path = repo_root.join("docs/extension-sample.json");
    let manifest_bytes = fs::read(&manifest_path).expect("read docs/extension-sample.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("parse docs/extension-sample.json");

    let items = manifest
        .get("items")
        .and_then(serde_json::Value::as_array)
        .expect("docs/extension-sample.json: items[]");

    let mut ids = items
        .iter()
        .map(|item| {
            item.get("id")
                .and_then(serde_json::Value::as_str)
                .expect("docs/extension-sample.json: items[].id")
                .to_string()
        })
        .collect::<Vec<_>>();
    ids.sort();

    let mut ledgers: BTreeMap<String, pi::extensions::CompatLedger> = BTreeMap::new();
    for id in ids {
        let artifact_dir = repo_root.join("tests/ext_conformance/artifacts").join(&id);
        assert!(
            artifact_dir.is_dir(),
            "missing artifact directory for {id}: {}",
            artifact_dir.display()
        );

        let scanner = CompatibilityScanner::new(artifact_dir);
        let ledger = scanner
            .scan_root()
            .unwrap_or_else(|err| panic!("scan {id}: {err}"));
        ledgers.insert(id, ledger);
    }

    let text = serde_json::to_string_pretty(&ledgers).expect("serialize ledgers");
    insta::assert_snapshot!("compat_scanner_pinned_sample_ledger", text);
}
