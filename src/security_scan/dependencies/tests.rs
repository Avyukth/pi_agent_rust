use super::*;

fn cargo(source: Option<&str>, name: &str, version: &str) -> String {
    let source = source.map_or_else(String::new, |source| format!("source = {source:?}\n"));
    format!("[[package]]\nname = {name:?}\nversion = {version:?}\n{source}")
}

#[test]
fn cargo_inventory_does_not_send_private_git_or_workspace_identities() {
    let text = format!("version = 4\n{}{}{}{}",
        cargo(Some("registry+https://github.com/rust-lang/crates.io-index"), "public-crate", "1.2.3"),
        cargo(None, "private-workspace", "0.1.0"),
        cargo(Some("git+https://token-secret@example.invalid/private#deadbeef"), "private-git", "1.0.0"),
        cargo(Some("registry+https://example.invalid/index"), "private-registry", "1.0.0"));
    let mut builder = Builder::default();
    parse_cargo(&text, "Cargo.lock", &mut builder).unwrap();
    let inventory = builder.finish(vec![]);
    assert_eq!(inventory.packages.len(), 1);
    assert_eq!(inventory.packages[0].name, "public-crate");
    assert_eq!(inventory.packages[0].ecosystem, "crates.io");
    assert_eq!(inventory.excluded.len(), 3);
    let rendered = serde_json::to_string(&inventory).unwrap();
    for private in ["token-secret", "private-workspace", "private-git", "private-registry", "example.invalid"] {
        assert!(!rendered.contains(private));
    }
}

#[test]
fn identical_queries_are_deduplicated_without_losing_lockfile_locations() {
    let mut builder = Builder::default();
    for path in ["Cargo.lock", "nested/Cargo.lock", "Cargo.lock"] {
        for version in ["1.2.3", "2.0.0-beta.1+build"] {
            parse_cargo(&cargo(Some("sparse+https://index.crates.io/"), "some_crate", version), path, &mut builder).unwrap();
        }
    }
    let inventory = builder.finish(vec![]);
    assert_eq!(inventory.packages.len(), 2);
    assert_eq!(inventory.packages[0].locations.len(), 2);
    assert_eq!(inventory.packages[1].locations.len(), 2);
}

#[test]
fn npm_scopes_aliases_and_nested_installs_keep_actual_package_identity() {
    for version in [2, 3] {
        let mut builder = Builder::default();
        let text = serde_json::json!({"lockfileVersion":version,"packages":{
            "":{"name":"workspace","version":"1.0.0"},
            "node_modules/alias":{"name":"real-package","version":"1.2.3","resolved":"https://registry.npmjs.org/real-package/-/real-package-1.2.3.tgz"},
            "node_modules/parent/node_modules/real-package":{"version":"1.2.3","resolved":"https://registry.npmjs.org/real-package/-/real-package-1.2.3.tgz"},
            "node_modules/@scope/pkg":{"version":"2.0.0","resolved":"https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz","dev":true}
        }}).to_string();
        parse_npm(&text, "package-lock.json", &mut builder).unwrap();
        let inventory = builder.finish(vec![]);
        assert_eq!(inventory.packages.len(), 2);
        assert!(inventory.excluded.is_empty());
        let alias = inventory.packages.iter().find(|package| package.name == "real-package").unwrap();
        assert_eq!(alias.locations.len(), 2);
        assert!(inventory.packages.iter().any(|package| package.name == "@scope/pkg"));
    }
}

#[test]
fn npm_unknown_or_nonpublic_origins_are_excluded_without_inference() {
    let mut builder = Builder::default();
    let text = serde_json::json!({"lockfileVersion":3,"packages":{
        "node_modules/private":{"version":"1.0.0","resolved":"https://user:password@example.invalid/private.tgz"},
        "node_modules/unknown":{"version":"1.0.0"},
        "node_modules/git":{"version":"1.0.0","resolved":"git+https://github.com/example/repo#sha"},
        "node_modules/link":{"link":true,"resolved":"packages/local"},
        "packages/local":{"name":"local","version":"1.0.0"},
        "node_modules/evil":{"version":"1.0.0","resolved":"https://registry.npmjs.org.evil.invalid/a"}
    }}).to_string();
    parse_npm(&text, "package-lock.json", &mut builder).unwrap();
    let inventory = builder.finish(vec![]);
    assert!(inventory.packages.is_empty());
    assert_eq!(inventory.excluded.len(), 6);
    assert!(!serde_json::to_string(&inventory).unwrap().contains("password"));
}

#[test]
fn malformed_or_unknown_lockfile_formats_never_become_empty_success() {
    for text in ["", "version = 999\npackage = []", "[[package]]\nname='missing-version'"] {
        assert!(parse_cargo(text, "Cargo.lock", &mut Builder::default()).is_err());
    }
    for text in ["{", "{}", r#"{"lockfileVersion":1,"dependencies":{}}"#,
        r#"{"lockfileVersion":4,"packages":{}}"#, r#"{"lockfileVersion":3,"packages":[]}"#] {
        assert!(parse_npm(text, "package-lock.json", &mut Builder::default()).is_err());
    }
}

#[test]
fn unpinned_versions_are_exclusions_not_fuzzy_osv_queries() {
    let mut builder = Builder::default();
    for version in ["^1.0.0", "latest", "file:private", "1.2", "git+https://example.invalid"] {
        builder.add("npm", "package", version, Location { lockfile:"package-lock.json".into(), package_path:None }).unwrap();
    }
    assert!(builder.packages.is_empty());
    assert_eq!(builder.excluded.len(), 5);
}

#[test]
fn selected_paths_are_normalized_but_cannot_escape_or_select_arbitrary_files() {
    assert_eq!(normalized_path("./nested//Cargo.lock").unwrap(), "nested/Cargo.lock");
    for path in ["", ".", "../Cargo.lock", "/tmp/Cargo.lock", "a/../Cargo.lock",
        "C:\\Cargo.lock", "a\\Cargo.lock", "secret.txt", "\0Cargo.lock", "bad\n/Cargo.lock"] {
        assert!(normalized_path(path).is_err(), "{path:?}");
    }
}

#[test]
fn entry_and_unique_package_bounds_fail_explicitly() {
    let mut builder = Builder { entries:MAX_ENTRIES, ..Builder::default() };
    assert!(builder.entry().is_err());
    for index in 0..MAX_PACKAGES {
        builder.packages.insert(("npm".into(), format!("pkg-{index}"), "1.0.0".into()), BTreeSet::new());
    }
    assert!(builder.add("npm", "one-more", "1.0.0", Location { lockfile:"package-lock.json".into(), package_path:None }).is_err());
}

#[cfg(all(unix, not(any(target_os = "espidf", target_os = "redox"))))]
mod filesystem {
    use super::*;

    #[test]
    fn actual_inventory_deduplicates_paths_and_hashes_the_bytes_it_reads() {
        let dir = tempfile::tempdir().unwrap();
        let text = cargo(Some("registry+https://github.com/rust-lang/crates.io-index"), "example", "1.0.0");
        std::fs::write(dir.path().join("Cargo.lock"), &text).unwrap();
        let inventory = inventory(dir.path(), &["Cargo.lock".into(), "./Cargo.lock".into()]).unwrap();
        assert_eq!(inventory.lockfiles.len(), 1);
        assert_eq!(inventory.lockfiles[0].sha256, digest(text.as_bytes()));
        assert_eq!(inventory.packages.len(), 1);
        assert_eq!(inventory.packages[0].locations[0].lockfile, "Cargo.lock");
    }

    #[test]
    fn missing_default_or_explicit_lockfiles_do_not_report_clean() {
        let dir = tempfile::tempdir().unwrap();
        assert!(inventory(dir.path(), &[]).is_err());
        std::fs::write(dir.path().join("Cargo.lock"), cargo(None, "workspace", "1.0.0")).unwrap();
        assert_eq!(inventory(dir.path(), &[]).unwrap().excluded.len(), 1);
        assert!(inventory(dir.path(), &["absent/Cargo.lock".into()]).is_err());
    }

    #[test]
    fn leaf_and_ancestor_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("Cargo.lock"), cargo(None, "private", "1.0.0")).unwrap();
        symlink(outside.path().join("Cargo.lock"), dir.path().join("Cargo.lock")).unwrap();
        assert!(inventory(dir.path(), &[]).is_err());
        symlink(outside.path(), dir.path().join("nested")).unwrap();
        assert!(inventory(dir.path(), &["nested/Cargo.lock".into()]).is_err());
    }

    #[test]
    fn oversized_regular_lockfile_is_rejected_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(dir.path().join("Cargo.lock")).unwrap();
        file.set_len(MAX_FILE_BYTES + 1).unwrap();
        assert!(inventory(dir.path(), &[]).unwrap_err().to_string().contains("4 MiB"));
    }
}
