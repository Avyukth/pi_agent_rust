//! E2E: Built-in tool execution with artifact logging (bd-2xyv).
//!
//! Tests all 7 built-in tools (read, write, edit, bash, grep, find, ls) via direct
//! `ToolRegistry::get(name).execute()` calls against real file system operations in
//! temp directories. No mocks, no network, fully deterministic.

mod common;

use common::TestHarness;
use pi::error::Error;
use pi::model::ContentBlock;
use pi::tools::ToolRegistry;
use serde_json::json;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_registry(cwd: &Path) -> ToolRegistry {
    ToolRegistry::new(
        &["read", "write", "edit", "bash", "grep", "find", "ls"],
        cwd,
        None,
    )
}

/// Extract the first text content from a `ToolOutput`.
fn first_text(content: &[ContentBlock]) -> &str {
    content
        .iter()
        .find_map(|b| match b {
            ContentBlock::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .unwrap_or("")
}

/// Check if `rg` (ripgrep) is available on this machine.
fn rg_available() -> bool {
    std::process::Command::new("rg")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Check if `fd` or `fdfind` is available on this machine.
fn fd_available() -> bool {
    std::process::Command::new("fd")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
        || std::process::Command::new("fdfind")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
}

// ===========================================================================
// Read Tool
// ===========================================================================

#[test]
fn read_text_file_basic() {
    let h = TestHarness::new("read_text_file_basic");
    let file = h.create_file("hello.txt", "line one\nline two\nline three\n");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("read").unwrap();
        tool.execute("call-1", json!({"path": file.display().to_string()}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", format!("text={text}"));

    // Line-numbered cat-n format: "    1→line one"
    assert!(text.contains("1→line one"), "should contain line 1");
    assert!(text.contains("2→line two"), "should contain line 2");
    assert!(text.contains("3→line three"), "should contain line 3");
    assert!(!result.is_error);
}

#[test]
fn read_with_offset_and_limit() {
    let h = TestHarness::new("read_with_offset_and_limit");
    let mut content = String::new();
    for i in 1..=20 {
        use std::fmt::Write as _;
        let _ = writeln!(&mut content, "line {i}");
    }
    let file = h.create_file("lines.txt", &content);
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("read").unwrap();
        tool.execute(
            "call-2",
            json!({"path": file.display().to_string(), "offset": 5, "limit": 6}),
            None,
        )
        .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", format!("text={text}"));

    // offset=5 means start at line 5, limit=6 means show 6 lines (5-10)
    assert!(text.contains("5→line 5"), "should start at line 5");
    assert!(text.contains("10→line 10"), "should include line 10");
    assert!(!text.contains("4→"), "should not include line 4");
    assert!(!text.contains("11→line 11"), "should not include line 11");
}

#[test]
fn read_large_file_truncation() {
    let h = TestHarness::new("read_large_file_truncation");
    // Create a file with 3000 lines - should be truncated at 2000 lines
    let mut content = String::new();
    for i in 1..=3000 {
        use std::fmt::Write as _;
        let _ = writeln!(&mut content, "line number {i}");
    }
    let file = h.create_file("big.txt", &content);
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("read").unwrap();
        tool.execute("call-3", json!({"path": file.display().to_string()}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);

    // Should contain truncation notice
    assert!(
        text.contains("Use offset=") || text.contains("Showing lines"),
        "should indicate truncation"
    );
    // Should contain line 1 but not line 3000
    assert!(
        text.contains("1→line number 1"),
        "should contain first line"
    );
    assert!(
        !text.contains("3000→"),
        "should not contain line 3000 (truncated)"
    );
}

#[test]
fn read_missing_file_error() {
    let h = TestHarness::new("read_missing_file_error");
    let registry = make_registry(h.temp_dir());
    let missing = h.temp_path("does_not_exist.txt");

    let output = common::run_async(async move {
        let tool = registry.get("read").unwrap();
        tool.execute(
            "call-4",
            json!({"path": missing.display().to_string()}),
            None,
        )
        .await
    });

    let err = output.unwrap_err();
    h.log().info("result", format!("error={err}"));
    assert!(
        matches!(err, Error::Tool { .. }),
        "should be a Tool error, got: {err}"
    );
}

#[test]
fn read_binary_file_returns_image() {
    let h = TestHarness::new("read_binary_file_returns_image");

    // Minimal valid 1x1 PNG
    let png_bytes: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, // bit depth, color, etc
        0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
        0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, // data
        0xE2, 0x21, 0xBC, 0x33, // CRC
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND
        0xAE, 0x42, 0x60, 0x82,
    ];
    let file = h.create_file("tiny.png", png_bytes);
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("read").unwrap();
        tool.execute("call-5", json!({"path": file.display().to_string()}), None)
            .await
    });

    let result = output.unwrap();
    h.log()
        .info("result", format!("blocks={}", result.content.len()));

    // Should return at least one Image block
    let has_image = result
        .content
        .iter()
        .any(|b| matches!(b, ContentBlock::Image(_)));
    assert!(has_image, "should contain an Image content block");
    assert!(!result.is_error);
}

// ===========================================================================
// Write Tool
// ===========================================================================

#[test]
fn write_new_file() {
    let h = TestHarness::new("write_new_file");
    let target = h.temp_path("sub/dir/new_file.txt");
    let registry = make_registry(h.temp_dir());

    let target_str = target.display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("write").unwrap();
        tool.execute(
            "call-6",
            json!({"path": target_str, "content": "hello world"}),
            None,
        )
        .await
    });

    let result = output.unwrap();
    h.log()
        .info("result", first_text(&result.content).to_string());

    assert!(!result.is_error);
    assert!(target.exists(), "file should be created");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "hello world",
        "content should match"
    );
}

#[test]
fn write_overwrite_existing() {
    let h = TestHarness::new("write_overwrite_existing");
    let file = h.create_file("existing.txt", "old content");
    let registry = make_registry(h.temp_dir());

    let file_str = file.display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("write").unwrap();
        tool.execute(
            "call-7",
            json!({"path": file_str, "content": "new content"}),
            None,
        )
        .await
    });

    let result = output.unwrap();
    assert!(!result.is_error);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "new content",
        "should overwrite with new content"
    );
}

#[test]
fn write_reports_byte_count() {
    let h = TestHarness::new("write_reports_byte_count");
    let file = h.temp_path("count.txt");
    let registry = make_registry(h.temp_dir());

    let file_str = file.display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("write").unwrap();
        tool.execute(
            "call-8",
            json!({"path": file_str, "content": "abcde"}),
            None,
        )
        .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    // "Successfully wrote 5 bytes to ..."
    assert!(
        text.contains("5 bytes"),
        "should report byte count, got: {text}"
    );
}

// ===========================================================================
// Edit Tool
// ===========================================================================

#[test]
fn edit_exact_match() {
    let h = TestHarness::new("edit_exact_match");
    let file = h.create_file("editable.txt", "Hello World\nFoo Bar\n");
    let registry = make_registry(h.temp_dir());

    let file_str = file.display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("edit").unwrap();
        tool.execute(
            "call-9",
            json!({
                "path": file_str,
                "oldText": "Foo Bar",
                "newText": "Baz Qux"
            }),
            None,
        )
        .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    assert!(text.contains("Successfully replaced"), "should succeed");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "Hello World\nBaz Qux\n"
    );

    // Details should contain a diff
    assert!(result.details.is_some(), "should have details with diff");
    let details = result.details.unwrap();
    assert!(details.get("diff").is_some(), "details should contain diff");
}

#[test]
fn edit_text_not_found_error() {
    let h = TestHarness::new("edit_text_not_found_error");
    let file = h.create_file("nope.txt", "Hello World\n");
    let registry = make_registry(h.temp_dir());

    let file_str = file.display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("edit").unwrap();
        tool.execute(
            "call-10",
            json!({
                "path": file_str,
                "oldText": "does not exist in file",
                "newText": "replacement"
            }),
            None,
        )
        .await
    });

    let err = output.unwrap_err();
    h.log().info("result", format!("error={err}"));
    assert!(
        matches!(err, Error::Tool { .. }),
        "should be Tool error: {err}"
    );
    assert!(
        err.to_string().contains("Could not find"),
        "message should say text not found: {err}"
    );
}

#[test]
fn edit_ambiguous_match_error() {
    let h = TestHarness::new("edit_ambiguous_match_error");
    let file = h.create_file("ambig.txt", "apple\norange\napple\n");
    let registry = make_registry(h.temp_dir());

    let file_str = file.display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("edit").unwrap();
        tool.execute(
            "call-11",
            json!({
                "path": file_str,
                "oldText": "apple",
                "newText": "banana"
            }),
            None,
        )
        .await
    });

    let err = output.unwrap_err();
    h.log().info("result", format!("error={err}"));
    assert!(
        matches!(err, Error::Tool { .. }),
        "should be Tool error: {err}"
    );
    assert!(
        err.to_string().contains("occurrences"),
        "message should mention multiple occurrences: {err}"
    );
}

#[test]
fn edit_preserves_line_endings() {
    let h = TestHarness::new("edit_preserves_line_endings");
    // CRLF content
    let file = h.create_file("crlf.txt", "line1\r\nline2\r\nline3\r\n");
    let registry = make_registry(h.temp_dir());

    let file_str = file.display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("edit").unwrap();
        tool.execute(
            "call-12",
            json!({
                "path": file_str,
                "oldText": "line2",
                "newText": "replaced"
            }),
            None,
        )
        .await
    });

    let result = output.unwrap();
    assert!(!result.is_error);

    let on_disk = std::fs::read(&file).unwrap();
    let on_disk_str = String::from_utf8_lossy(&on_disk);
    h.log().info("result", format!("on_disk={on_disk_str:?}"));
    // CRLF should be preserved
    assert!(
        on_disk_str.contains("\r\n"),
        "should preserve CRLF line endings"
    );
    assert!(
        on_disk_str.contains("replaced"),
        "should contain replaced text"
    );
}

// ===========================================================================
// Bash Tool
// ===========================================================================

#[test]
fn bash_simple_command() {
    let h = TestHarness::new("bash_simple_command");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("bash").unwrap();
        tool.execute("call-13", json!({"command": "echo hello"}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    assert!(text.contains("hello"), "should contain 'hello'");
    assert!(!result.is_error);
}

#[test]
fn bash_nonzero_exit() {
    let h = TestHarness::new("bash_nonzero_exit");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("bash").unwrap();
        tool.execute(
            "call-14",
            json!({"command": "echo stderr_msg >&2; exit 42"}),
            None,
        )
        .await
    });

    // Non-zero exit returns Error::Tool
    let err = output.unwrap_err();
    h.log().info("result", format!("error={err}"));
    assert!(
        matches!(err, Error::Tool { .. }),
        "should be Tool error: {err}"
    );
}

#[test]
fn bash_timeout() {
    let h = TestHarness::new("bash_timeout");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("bash").unwrap();
        tool.execute(
            "call-15",
            json!({"command": "sleep 300", "timeout": 1}),
            None,
        )
        .await
    });

    // Timeout should result in an error (cancelled)
    let err = output.unwrap_err();
    h.log().info("result", format!("error={err}"));
    assert!(
        matches!(err, Error::Tool { .. }),
        "should be Tool error: {err}"
    );
}

#[test]
fn bash_large_output_truncation() {
    let h = TestHarness::new("bash_large_output_truncation");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("bash").unwrap();
        // Generate >50KB of output (each line ~11 bytes x 6000 > 60KB)
        tool.execute("call-16", json!({"command": "seq 1 6000"}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", format!("text_len={}", text.len()));

    // The output should be present (bash tool keeps tail)
    assert!(!text.is_empty(), "should have output");
}

// ===========================================================================
// Grep Tool
// ===========================================================================

#[test]
fn grep_basic_match() {
    if !rg_available() {
        eprintln!("SKIP: ripgrep (rg) not installed");
        return;
    }

    let h = TestHarness::new("grep_basic_match");
    h.create_file("a.txt", "hello world\ngoodbye world\n");
    h.create_file("b.txt", "no match here\nhello again\n");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("grep").unwrap();
        tool.execute("call-17", json!({"pattern": "hello"}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    // Should have file:line format matches
    assert!(text.contains("hello"), "should contain matching text");
    assert!(!result.is_error);
}

#[test]
fn grep_case_insensitive() {
    if !rg_available() {
        eprintln!("SKIP: ripgrep (rg) not installed");
        return;
    }

    let h = TestHarness::new("grep_case_insensitive");
    h.create_file("mixed.txt", "Hello World\nHELLO WORLD\nhello world\n");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("grep").unwrap();
        tool.execute(
            "call-18",
            json!({"pattern": "hello", "ignoreCase": true}),
            None,
        )
        .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    // All three lines should match with case insensitive
    assert!(text.contains("Hello World"), "should match mixed case");
    assert!(text.contains("HELLO WORLD"), "should match upper case");
    assert!(text.contains("hello world"), "should match lower case");
}

#[test]
fn grep_no_matches() {
    if !rg_available() {
        eprintln!("SKIP: ripgrep (rg) not installed");
        return;
    }

    let h = TestHarness::new("grep_no_matches");
    h.create_file("data.txt", "alpha\nbeta\ngamma\n");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("grep").unwrap();
        tool.execute("call-19", json!({"pattern": "zzz_no_match_zzz"}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    assert!(
        text.contains("No matches found"),
        "should report no matches, got: {text}"
    );
    assert!(!result.is_error, "no matches is not an error");
}

#[test]
fn grep_with_context() {
    if !rg_available() {
        eprintln!("SKIP: ripgrep (rg) not installed");
        return;
    }

    let h = TestHarness::new("grep_with_context");
    h.create_file("ctx.txt", "line1\nline2\nTARGET\nline4\nline5\n");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("grep").unwrap();
        tool.execute("call-20", json!({"pattern": "TARGET", "context": 1}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    // Context lines use '-N-' format, match lines use ':N:'
    assert!(text.contains("TARGET"), "should contain match");
    assert!(text.contains("line2"), "should contain context before");
    assert!(text.contains("line4"), "should contain context after");
}

// ===========================================================================
// Find Tool
// ===========================================================================

#[test]
fn find_glob_pattern() {
    if !fd_available() {
        eprintln!("SKIP: fd/fdfind not installed");
        return;
    }

    let h = TestHarness::new("find_glob_pattern");
    h.create_file("one.txt", "");
    h.create_file("two.txt", "");
    h.create_file("three.rs", "");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("find").unwrap();
        tool.execute("call-21", json!({"pattern": "*.txt"}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    assert!(text.contains("one.txt"), "should find one.txt");
    assert!(text.contains("two.txt"), "should find two.txt");
    assert!(!text.contains("three.rs"), "should not find .rs files");
    assert!(!result.is_error);
}

#[test]
fn find_no_matches() {
    if !fd_available() {
        eprintln!("SKIP: fd/fdfind not installed");
        return;
    }

    let h = TestHarness::new("find_no_matches");
    h.create_file("data.txt", "");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("find").unwrap();
        tool.execute("call-22", json!({"pattern": "*.zzz_no_match"}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    assert!(
        text.contains("No files found"),
        "should report no files found, got: {text}"
    );
    assert!(!result.is_error, "no matches is not an error");
}

#[test]
fn find_with_limit() {
    if !fd_available() {
        eprintln!("SKIP: fd/fdfind not installed");
        return;
    }

    let h = TestHarness::new("find_with_limit");
    for i in 0..10 {
        h.create_file(format!("file_{i:02}.txt"), "");
    }
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("find").unwrap();
        tool.execute("call-23", json!({"pattern": "*.txt", "limit": 3}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    // Count the number of .txt entries
    let txt_count = text.lines().filter(|l| l.contains(".txt")).count();
    assert!(
        txt_count <= 3,
        "should return at most 3 results, got {txt_count}"
    );
}

#[test]
fn find_directory_suffix() {
    if !fd_available() {
        eprintln!("SKIP: fd/fdfind not installed");
        return;
    }

    let h = TestHarness::new("find_directory_suffix");
    h.create_dir("subdir_a");
    h.create_dir("subdir_b");
    h.create_file("subdir_a/keep.txt", "");
    h.create_file("subdir_b/keep.txt", "");
    let registry = make_registry(h.temp_dir());

    let output = common::run_async(async move {
        let tool = registry.get("find").unwrap();
        tool.execute("call-24", json!({"pattern": "subdir_*"}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    // Directories should have '/' suffix
    assert!(
        text.lines()
            .any(|line| line.starts_with("subdir_") && line.ends_with('/')),
        "directories should have '/' suffix, got: {text}"
    );
}

// ===========================================================================
// Ls Tool
// ===========================================================================

#[test]
fn ls_directory_contents() {
    let h = TestHarness::new("ls_directory_contents");
    h.create_file("alpha.txt", "");
    h.create_file("beta.txt", "");
    h.create_dir("gamma_dir");
    let registry = make_registry(h.temp_dir());

    let dir_path = h.temp_dir().display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("ls").unwrap();
        tool.execute("call-25", json!({"path": dir_path}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    assert!(text.contains("alpha.txt"), "should list alpha.txt");
    assert!(text.contains("beta.txt"), "should list beta.txt");
    assert!(
        text.contains("gamma_dir/"),
        "should list gamma_dir with / suffix"
    );
    assert!(!result.is_error);
}

#[test]
fn ls_empty_directory() {
    let h = TestHarness::new("ls_empty_directory");
    let empty = h.create_dir("empty_dir");
    let registry = make_registry(h.temp_dir());

    let dir_str = empty.display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("ls").unwrap();
        tool.execute("call-26", json!({"path": dir_str}), None)
            .await
    });

    let result = output.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    assert!(
        text.contains("(empty directory)"),
        "should show empty directory message, got: {text}"
    );
}

#[test]
fn ls_nonexistent_path_error() {
    let h = TestHarness::new("ls_nonexistent_path_error");
    let registry = make_registry(h.temp_dir());
    let missing = h.temp_path("not_a_dir");

    let dir_str = missing.display().to_string();
    let output = common::run_async(async move {
        let tool = registry.get("ls").unwrap();
        tool.execute("call-27", json!({"path": dir_str}), None)
            .await
    });

    let err = output.unwrap_err();
    h.log().info("result", format!("error={err}"));
    assert!(
        matches!(err, Error::Tool { .. }),
        "should be Tool error: {err}"
    );
}

// ===========================================================================
// Cross-tool
// ===========================================================================

#[test]
fn write_edit_read_cycle() {
    let h = TestHarness::new("write_edit_read_cycle");
    let file_path = h.temp_path("cycle.txt");
    let file_str = file_path.display().to_string();
    let registry = make_registry(h.temp_dir());

    // Step 1: Write a file
    let write_file = file_str.clone();
    let write_reg = make_registry(h.temp_dir());
    let write_result = common::run_async(async move {
        let tool = write_reg.get("write").unwrap();
        tool.execute(
            "call-w",
            json!({"path": write_file, "content": "alpha\nbeta\ngamma\n"}),
            None,
        )
        .await
    });
    assert!(!write_result.unwrap().is_error, "write should succeed");

    // Step 2: Edit the file
    let edit_file = file_str.clone();
    let edit_reg = make_registry(h.temp_dir());
    let edit_result = common::run_async(async move {
        let tool = edit_reg.get("edit").unwrap();
        tool.execute(
            "call-e",
            json!({
                "path": edit_file,
                "oldText": "beta",
                "newText": "BETA_REPLACED"
            }),
            None,
        )
        .await
    });
    assert!(!edit_result.unwrap().is_error, "edit should succeed");

    // Step 3: Read the file back
    let read_file = file_str;
    let read_result = common::run_async(async move {
        let tool = registry.get("read").unwrap();
        tool.execute("call-r", json!({"path": read_file}), None)
            .await
    });
    let result = read_result.unwrap();
    let text = first_text(&result.content);
    h.log().info("result", text.to_string());

    assert!(
        text.contains("BETA_REPLACED"),
        "should see edited content: {text}"
    );
    assert!(text.contains("alpha"), "should still have alpha");
    assert!(text.contains("gamma"), "should still have gamma");
    assert!(!text.contains("\nbeta\n"), "original beta should be gone");
}
