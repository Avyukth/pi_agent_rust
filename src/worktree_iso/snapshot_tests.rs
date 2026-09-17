//! Real-Git regression cases for launch snapshots and non-mutating diff collection.

use super::*;
use std::fs;
use tempfile::TempDir;

fn repository_at(path: &Path) {
    fs::create_dir_all(path).unwrap();
    git_ok(path, &["init", "-b", "main"]).unwrap();
    git_ok(path, &["config", "user.name", "Isolation Fixture"]).unwrap();
    git_ok(path, &["config", "user.email", "isolation@localhost"]).unwrap();
    git_ok(path, &["config", "commit.gpgSign", "false"]).unwrap();
    fs::write(path.join("base.txt"), "original\n").unwrap();
    git_ok(path, &["add", "."]).unwrap();
    git_ok(path, &["commit", "-m", "initial"]).unwrap();
}

fn repository() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    repository_at(dir.path());
    dir
}

fn index_bytes(repo: &Path) -> Vec<u8> {
    let index = git_ok(repo, &["rev-parse", "--git-path", "index"]).unwrap();
    let index = PathBuf::from(index.trim_end_matches('\n'));
    fs::read(if index.is_absolute() {
        index
    } else {
        repo.join(index)
    })
    .unwrap()
}

#[test]
fn dirty_snapshot_and_collection_preserve_both_real_indexes() {
    let repo = repository();
    fs::write(repo.path().join("base.txt"), "staged parent\n").unwrap();
    git_ok(repo.path(), &["add", "base.txt"]).unwrap();
    fs::write(repo.path().join("base.txt"), "working parent\n").unwrap();
    fs::write(repo.path().join("untracked.bin"), [0, 255, 1, 128]).unwrap();
    let parent_index = index_bytes(repo.path());
    let parent_head = git_ok(repo.path(), &["rev-parse", "HEAD"]).unwrap();
    let handle = isolate(repo.path(), "preserve-staging").unwrap();
    assert_eq!(
        fs::read(handle.path.join("base.txt")).unwrap(),
        b"working parent\n"
    );
    assert_eq!(
        fs::read(handle.path.join("untracked.bin")).unwrap(),
        [0, 255, 1, 128]
    );
    assert_eq!(index_bytes(repo.path()), parent_index);
    assert!(collect_diff(&handle).unwrap().0.is_empty());

    fs::write(handle.path.join("base.txt"), "staged child\n").unwrap();
    git_ok(&handle.path, &["add", "base.txt"]).unwrap();
    fs::write(handle.path.join("base.txt"), "working child\n").unwrap();
    let child_index = index_bytes(&handle.path);
    let (patch, _) = collect_diff(&handle).unwrap();
    assert_eq!(index_bytes(&handle.path), child_index);
    apply_to_parent(&handle, &patch).unwrap();
    assert_eq!(
        fs::read(repo.path().join("base.txt")).unwrap(),
        b"working child\n"
    );
    assert_eq!(index_bytes(repo.path()), parent_index);
    assert_eq!(
        git_ok(repo.path(), &["rev-parse", "HEAD"]).unwrap(),
        parent_head
    );
    drop_worktree(&handle).unwrap();
}

#[test]
fn tracked_ignored_additions_survive_without_copying_ignored_untracked_files() {
    let repo = repository();
    fs::write(repo.path().join(".gitignore"), "*.ignored\n").unwrap();
    fs::write(repo.path().join("tracked.ignored"), "tracked\n").unwrap();
    fs::write(
        repo.path().join("private.ignored"),
        "not part of the snapshot\n",
    )
    .unwrap();
    git_ok(repo.path(), &["add", "-f", "tracked.ignored"]).unwrap();
    let before = index_bytes(repo.path());
    let handle = isolate(repo.path(), "ignored").unwrap();
    assert_eq!(
        fs::read(handle.path.join("tracked.ignored")).unwrap(),
        b"tracked\n"
    );
    assert!(!handle.path.join("private.ignored").exists());
    assert_eq!(index_bytes(repo.path()), before);
    drop_worktree(&handle).unwrap();
}

#[cfg(unix)]
#[test]
fn unusual_untracked_names_and_binary_diffs_round_trip_without_loss() -> std::io::Result<()> {
    use std::os::unix::ffi::OsStringExt as _;

    let repo = repository();
    let mut names = vec![
        std::ffi::OsString::from("line\nbreak.bin"),
        std::ffi::OsString::from("tab\tand\"quote.bin"),
        std::ffi::OsString::from("日本語 space.bin"),
    ];
    let original: Vec<u8> = (0..=255).collect();
    for name in &names {
        fs::write(repo.path().join(name), &original).unwrap();
    }
    let non_utf8 = std::ffi::OsString::from_vec(b"nonutf8-\xff.bin".to_vec());
    match fs::write(repo.path().join(&non_utf8), &original) {
        Ok(()) => names.push(non_utf8),
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::ILSEQ.raw_os_error()) => {
            eprintln!("SKIP non-UTF-8 filename {non_utf8:?}: filesystem returned {error}");
        }
        Err(error) => return Err(error),
    }
    eprintln!("Exercising snapshot filenames: {names:?}");
    let handle = isolate(repo.path(), "filenames").unwrap();
    let changed = [0, 254, 127, 1, 0];
    for name in &names {
        assert_eq!(fs::read(handle.path.join(name)).unwrap(), original);
        fs::write(handle.path.join(name), changed).unwrap();
    }
    let (patch, _) = collect_diff(&handle).unwrap();
    assert!(patch.contains("GIT binary patch"));
    apply_to_parent(&handle, &patch).unwrap();
    for name in &names {
        assert_eq!(fs::read(repo.path().join(name)).unwrap(), changed);
    }
    drop_worktree(&handle).unwrap();
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinks_dangling_links_and_executable_modes_are_not_flattened() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let repo = repository();
    symlink("base.txt", repo.path().join("alias")).unwrap();
    symlink("missing-target", repo.path().join("dangling")).unwrap();
    fs::write(repo.path().join("run.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(
        repo.path().join("run.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let handle = isolate(repo.path(), "file-types").unwrap();
    assert_eq!(
        fs::read_link(handle.path.join("alias")).unwrap(),
        Path::new("base.txt")
    );
    assert_eq!(
        fs::read_link(handle.path.join("dangling")).unwrap(),
        Path::new("missing-target")
    );
    assert_ne!(
        fs::metadata(handle.path.join("run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert!(collect_diff(&handle).unwrap().0.is_empty());
    drop_worktree(&handle).unwrap();
}

#[test]
fn requesting_isolation_from_a_subdirectory_still_captures_the_whole_repo() {
    let repo = repository();
    fs::create_dir(repo.path().join("nested")).unwrap();
    fs::write(repo.path().join("nested/inside.txt"), "inside\n").unwrap();
    fs::write(repo.path().join("outside.txt"), "outside\n").unwrap();
    let handle = isolate(&repo.path().join("nested"), "subdirectory").unwrap();
    assert_eq!(handle.repo_root, repo.path().canonicalize().unwrap());
    assert_eq!(
        fs::read(handle.path.join("outside.txt")).unwrap(),
        b"outside\n"
    );
    assert_eq!(
        fs::read(handle.path.join("nested/inside.txt")).unwrap(),
        b"inside\n"
    );
    drop_worktree(&handle).unwrap();
}

#[test]
fn isolation_control_filenames_are_ordinary_user_files() {
    let repo = repository();
    let names = [".pi-iso-parent.patch", ".pi-iso-outgoing.patch"];
    for name in names {
        fs::write(repo.path().join(name), "user-owned contents\n").unwrap();
    }
    fs::write(repo.path().join("base.txt"), "parent dirty\n").unwrap();
    let handle = isolate(repo.path(), "control-names").unwrap();
    for name in names {
        assert_eq!(
            fs::read(handle.path.join(name)).unwrap(),
            b"user-owned contents\n"
        );
    }
    fs::write(handle.path.join("child.txt"), "child\n").unwrap();
    let (patch, _) = collect_diff(&handle).unwrap();
    assert!(!patch.contains(".pi-iso-"));
    apply_to_parent(&handle, &patch).unwrap();
    for name in names {
        assert_eq!(
            fs::read(repo.path().join(name)).unwrap(),
            b"user-owned contents\n"
        );
        assert_eq!(
            fs::read(handle.path.join(name)).unwrap(),
            b"user-owned contents\n"
        );
    }
    assert_eq!(
        collect_diff(&handle).unwrap().0,
        patch,
        "collection must not introduce its own patch file"
    );
    drop_worktree(&handle).unwrap();
}

#[cfg(unix)]
#[test]
fn internal_baselines_do_not_require_user_identity_signing_or_commit_hooks() {
    use std::os::unix::fs::PermissionsExt as _;

    let repo = repository();
    let hooks = tempfile::tempdir().unwrap();
    for name in ["pre-commit", "post-commit", "post-checkout"] {
        let path = hooks.path().join(name);
        fs::write(&path, "#!/bin/sh\nexit 77\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    git_ok(
        repo.path(),
        &["config", "core.hooksPath", hooks.path().to_str().unwrap()],
    )
    .unwrap();
    git_ok(repo.path(), &["config", "user.name", ""]).unwrap();
    git_ok(repo.path(), &["config", "user.email", ""]).unwrap();
    git_ok(repo.path(), &["config", "user.useConfigOnly", "true"]).unwrap();
    git_ok(repo.path(), &["config", "commit.gpgSign", "true"]).unwrap();
    git_ok(
        repo.path(),
        &["config", "gpg.program", "/not/a/real/signer"],
    )
    .unwrap();
    let head = git_ok(repo.path(), &["rev-parse", "HEAD"]).unwrap();
    let handle = isolate(repo.path(), "internal-baseline").unwrap();
    fs::write(handle.path.join("child.txt"), "child\n").unwrap();
    assert!(collect_diff(&handle).unwrap().0.contains("child.txt"));
    assert_eq!(git_ok(repo.path(), &["rev-parse", "HEAD"]).unwrap(), head);
    drop_worktree(&handle).unwrap();
}

#[test]
fn unsupported_submodules_and_sparse_checkouts_fail_before_creating_worktrees() {
    let repo = repository();
    let head = git_ok(repo.path(), &["rev-parse", "HEAD"]).unwrap();
    git_ok(
        repo.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},vendor", head.trim()),
        ],
    )
    .unwrap();
    let before = git_ok(repo.path(), &["worktree", "list", "--porcelain"]).unwrap();
    let index = index_bytes(repo.path());
    let error = isolate(repo.path(), "gitlink").unwrap_err();
    assert!(
        error.to_string().contains("PI_ISO_SUBMODULE_UNSUPPORTED"),
        "{error}"
    );
    assert_eq!(
        git_ok(repo.path(), &["worktree", "list", "--porcelain"]).unwrap(),
        before
    );
    assert_eq!(index_bytes(repo.path()), index);

    let sparse = repository();
    git_ok(sparse.path(), &["config", "core.sparseCheckout", "true"]).unwrap();
    let before = git_ok(sparse.path(), &["worktree", "list", "--porcelain"]).unwrap();
    let error = isolate(sparse.path(), "sparse").unwrap_err();
    assert!(
        error.to_string().contains("PI_ISO_SPARSE_UNSUPPORTED"),
        "{error}"
    );
    assert_eq!(
        git_ok(sparse.path(), &["worktree", "list", "--porcelain"]).unwrap(),
        before
    );
}

#[test]
fn a_linked_parent_worktree_keeps_its_own_index_and_head() {
    let repo = repository();
    let outer = tempfile::tempdir().unwrap();
    let linked = outer.path().join("linked");
    git_ok(
        repo.path(),
        &[
            "worktree",
            "add",
            "-b",
            "linked-parent",
            linked.to_str().unwrap(),
        ],
    )
    .unwrap();
    fs::write(linked.join("base.txt"), "linked staged\n").unwrap();
    git_ok(&linked, &["add", "base.txt"]).unwrap();
    fs::write(linked.join("base.txt"), "linked actual\n").unwrap();
    let index = index_bytes(&linked);
    let head = git_ok(&linked, &["rev-parse", "HEAD"]).unwrap();
    let handle = isolate(&linked, "linked-child").unwrap();
    assert_eq!(
        fs::read(handle.path.join("base.txt")).unwrap(),
        b"linked actual\n"
    );
    assert_eq!(index_bytes(&linked), index);
    assert_eq!(git_ok(&linked, &["rev-parse", "HEAD"]).unwrap(), head);
    assert_eq!(
        fs::read(repo.path().join("base.txt")).unwrap(),
        b"original\n"
    );
    drop_worktree(&handle).unwrap();
    git_ok(
        repo.path(),
        &["worktree", "remove", "--force", linked.to_str().unwrap()],
    )
    .unwrap();
}

#[test]
fn non_utf8_text_diffs_fail_instead_of_replacing_bytes_lossily() {
    let repo = repository();
    let handle = isolate(repo.path(), "text-encoding").unwrap();
    fs::write(handle.path.join("base.txt"), [b'a', 255, b'\n']).unwrap();
    let error = collect_diff(&handle).unwrap_err();
    assert!(
        error.to_string().contains("PI_ISO_TEXT_ENCODING"),
        "{error}"
    );
    assert_eq!(
        fs::read(repo.path().join("base.txt")).unwrap(),
        b"original\n"
    );
    assert_eq!(
        fs::read(handle.path.join("base.txt")).unwrap(),
        [b'a', 255, b'\n']
    );
    drop_worktree(&handle).unwrap();
}

#[test]
fn foreign_branch_in_a_prefix_named_directory_is_not_reaped() {
    let repo = repository();
    let outer = tempfile::tempdir().unwrap();
    let foreign = outer.path().join("pi-iso-user-owned");
    git_ok(
        repo.path(),
        &[
            "worktree",
            "add",
            "-b",
            "user-owned",
            foreign.to_str().unwrap(),
        ],
    )
    .unwrap();
    let reaped = reap_stale(repo.path(), Duration::ZERO).unwrap();
    assert!(!reaped.iter().any(|path| Path::new(path) == foreign));
    assert!(foreign.join("base.txt").exists());
    git_ok(
        repo.path(),
        &["worktree", "remove", "--force", foreign.to_str().unwrap()],
    )
    .unwrap();
}
