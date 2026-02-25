//! OQ1 Verification: LLM tool selection accuracy at 34 tools (bd-2u3).
//!
//! Benchmark corpus: 50 prompts that SHOULD trigger browser tools + 50 that SHOULD NOT.
//! Tests against Pi's provider abstraction (Claude, GPT-4, Gemini).
//!
//! Pass criteria (from PLAN.md OQ1):
//! - Tool selection accuracy >= 95% at full registry (7 builtin + 21 browser)
//! - No regression > 2% from 7-tool baseline
//! - Latency increase < 200ms p95 from added schema tokens
//!
//! Gated on PI_OQ1_BENCHMARK=1 (requires live API keys).
//!
//! Run:
//! ```bash
//! # Corpus validation (always)
//! cargo test --test oq1_tool_selection
//!
//! # Full benchmark (requires API keys)
//! PI_OQ1_BENCHMARK=1 cargo test --test oq1_tool_selection -- --nocapture --ignored
//! ```

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark Corpus
// ═══════════════════════════════════════════════════════════════════════════

/// A benchmark prompt with expected tool selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkPrompt {
    /// The user prompt text.
    prompt: &'static str,
    /// Expected tool name (or "none" if no tool should be called).
    expected_tool: &'static str,
    /// Whether this prompt should trigger a browser tool.
    is_browser_positive: bool,
    /// Category for analysis.
    category: &'static str,
}

/// 50 prompts that SHOULD trigger browser tools.
const BROWSER_POSITIVE_PROMPTS: &[BenchmarkPrompt] = &[
    BenchmarkPrompt { prompt: "Navigate to https://example.com and read the page", expected_tool: "navigate", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "Take a screenshot of the current page", expected_tool: "screenshot", is_browser_positive: true, category: "capture" },
    BenchmarkPrompt { prompt: "Click the submit button on the page", expected_tool: "computer", is_browser_positive: true, category: "interaction" },
    BenchmarkPrompt { prompt: "Fill in the email field with test@example.com", expected_tool: "form_input", is_browser_positive: true, category: "interaction" },
    BenchmarkPrompt { prompt: "Read the page content and tell me what's there", expected_tool: "read_page", is_browser_positive: true, category: "reading" },
    BenchmarkPrompt { prompt: "Search for 'login button' on the page", expected_tool: "find", is_browser_positive: true, category: "reading" },
    BenchmarkPrompt { prompt: "Execute document.title in the browser console", expected_tool: "javascript", is_browser_positive: true, category: "devtools" },
    BenchmarkPrompt { prompt: "Show me the console messages from the page", expected_tool: "read_console_messages", is_browser_positive: true, category: "devtools" },
    BenchmarkPrompt { prompt: "What network requests has the page made?", expected_tool: "read_network_requests", is_browser_positive: true, category: "devtools" },
    BenchmarkPrompt { prompt: "Open a new browser tab", expected_tool: "tabs_create", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "What tabs are currently open?", expected_tool: "tabs_context", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "Resize the browser window to 1920x1080", expected_tool: "resize_window", is_browser_positive: true, category: "window" },
    BenchmarkPrompt { prompt: "Press Ctrl+A to select all text on the page", expected_tool: "shortcuts_execute", is_browser_positive: true, category: "shortcuts" },
    BenchmarkPrompt { prompt: "What keyboard shortcuts are available?", expected_tool: "shortcuts_list", is_browser_positive: true, category: "shortcuts" },
    BenchmarkPrompt { prompt: "Start observing console errors on this page", expected_tool: "observe", is_browser_positive: true, category: "observation" },
    BenchmarkPrompt { prompt: "Stop observing the page I set up earlier", expected_tool: "unobserve", is_browser_positive: true, category: "observation" },
    BenchmarkPrompt { prompt: "What observers are currently active?", expected_tool: "observers", is_browser_positive: true, category: "observation" },
    BenchmarkPrompt { prompt: "Get the raw text content of the current page", expected_tool: "get_page_text", is_browser_positive: true, category: "reading" },
    BenchmarkPrompt { prompt: "Upload the image file to the avatar input", expected_tool: "upload_image", is_browser_positive: true, category: "interaction" },
    BenchmarkPrompt { prompt: "Switch to Chrome browser", expected_tool: "switch_browser", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "Go to google.com", expected_tool: "navigate", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "What does the webpage look like?", expected_tool: "screenshot", is_browser_positive: true, category: "capture" },
    BenchmarkPrompt { prompt: "Type 'hello world' into the search box", expected_tool: "computer", is_browser_positive: true, category: "interaction" },
    BenchmarkPrompt { prompt: "Scroll down the page", expected_tool: "computer", is_browser_positive: true, category: "interaction" },
    BenchmarkPrompt { prompt: "Check the checkbox for 'Remember me'", expected_tool: "form_input", is_browser_positive: true, category: "interaction" },
    BenchmarkPrompt { prompt: "Read the accessibility tree of the current page", expected_tool: "read_page", is_browser_positive: true, category: "reading" },
    BenchmarkPrompt { prompt: "Find all buttons on the page", expected_tool: "find", is_browser_positive: true, category: "reading" },
    BenchmarkPrompt { prompt: "Run console.log('test') in the browser", expected_tool: "javascript", is_browser_positive: true, category: "devtools" },
    BenchmarkPrompt { prompt: "Are there any JavaScript errors on this page?", expected_tool: "read_console_messages", is_browser_positive: true, category: "devtools" },
    BenchmarkPrompt { prompt: "Show me the API calls this page is making", expected_tool: "read_network_requests", is_browser_positive: true, category: "devtools" },
    BenchmarkPrompt { prompt: "Open https://github.com in a new tab", expected_tool: "tabs_create", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "List all open browser tabs", expected_tool: "tabs_context", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "Make the browser window 800x600 pixels", expected_tool: "resize_window", is_browser_positive: true, category: "window" },
    BenchmarkPrompt { prompt: "Hit Escape key on the page", expected_tool: "shortcuts_execute", is_browser_positive: true, category: "shortcuts" },
    BenchmarkPrompt { prompt: "Watch this page for any navigation events", expected_tool: "observe", is_browser_positive: true, category: "observation" },
    BenchmarkPrompt { prompt: "Cancel observer obs-1", expected_tool: "unobserve", is_browser_positive: true, category: "observation" },
    BenchmarkPrompt { prompt: "Navigate back to the previous page", expected_tool: "navigate", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "Reload the current page", expected_tool: "navigate", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "Right-click on the image element", expected_tool: "computer", is_browser_positive: true, category: "interaction" },
    BenchmarkPrompt { prompt: "Select 'Option B' from the dropdown menu", expected_tool: "form_input", is_browser_positive: true, category: "interaction" },
    BenchmarkPrompt { prompt: "Find elements with class 'error-message'", expected_tool: "find", is_browser_positive: true, category: "reading" },
    BenchmarkPrompt { prompt: "Record a GIF of me navigating through the site", expected_tool: "gif_creator", is_browser_positive: true, category: "capture" },
    BenchmarkPrompt { prompt: "Execute window.scrollTo(0, document.body.scrollHeight)", expected_tool: "javascript", is_browser_positive: true, category: "devtools" },
    BenchmarkPrompt { prompt: "Monitor this page for DOM changes", expected_tool: "observe", is_browser_positive: true, category: "observation" },
    BenchmarkPrompt { prompt: "How many active observers are running?", expected_tool: "observers", is_browser_positive: true, category: "observation" },
    BenchmarkPrompt { prompt: "Close the current tab and switch to the next one", expected_tool: "navigate", is_browser_positive: true, category: "navigation" },
    BenchmarkPrompt { prompt: "Double-click on the table header to sort", expected_tool: "computer", is_browser_positive: true, category: "interaction" },
    BenchmarkPrompt { prompt: "Extract the text from the article body", expected_tool: "get_page_text", is_browser_positive: true, category: "reading" },
    BenchmarkPrompt { prompt: "Check if there are any 404 network errors", expected_tool: "read_network_requests", is_browser_positive: true, category: "devtools" },
    BenchmarkPrompt { prompt: "Set the date picker to 2025-01-15", expected_tool: "form_input", is_browser_positive: true, category: "interaction" },
];

/// 50 prompts that should NOT trigger browser tools (should use builtin or no tool).
const BROWSER_NEGATIVE_PROMPTS: &[BenchmarkPrompt] = &[
    BenchmarkPrompt { prompt: "Read the file src/main.rs", expected_tool: "read", is_browser_positive: false, category: "file_ops" },
    BenchmarkPrompt { prompt: "Edit line 42 of config.toml to change the port to 8080", expected_tool: "edit", is_browser_positive: false, category: "file_ops" },
    BenchmarkPrompt { prompt: "Write a new file called test.py with a hello world program", expected_tool: "write", is_browser_positive: false, category: "file_ops" },
    BenchmarkPrompt { prompt: "Run cargo test", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Search for 'TODO' in all Rust files", expected_tool: "grep", is_browser_positive: false, category: "search" },
    BenchmarkPrompt { prompt: "Find all .toml files in the project", expected_tool: "find", is_browser_positive: false, category: "search" },
    BenchmarkPrompt { prompt: "List files in the src directory", expected_tool: "ls", is_browser_positive: false, category: "file_ops" },
    BenchmarkPrompt { prompt: "What does the function parse_config do?", expected_tool: "read", is_browser_positive: false, category: "code_understanding" },
    BenchmarkPrompt { prompt: "Run git status to see pending changes", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Install the serde dependency", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "What is the meaning of life?", expected_tool: "none", is_browser_positive: false, category: "general" },
    BenchmarkPrompt { prompt: "Explain how async/await works in Rust", expected_tool: "none", is_browser_positive: false, category: "general" },
    BenchmarkPrompt { prompt: "Refactor the error handling in parser.rs", expected_tool: "edit", is_browser_positive: false, category: "code_change" },
    BenchmarkPrompt { prompt: "Create a new module for database operations", expected_tool: "write", is_browser_positive: false, category: "code_change" },
    BenchmarkPrompt { prompt: "Run the linter on the project", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Check if port 3000 is in use", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "What files were changed in the last commit?", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Show me the contents of README.md", expected_tool: "read", is_browser_positive: false, category: "file_ops" },
    BenchmarkPrompt { prompt: "Find where the User struct is defined", expected_tool: "grep", is_browser_positive: false, category: "search" },
    BenchmarkPrompt { prompt: "Delete the temporary build artifacts", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "How many lines of code are in this project?", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Add a new test for the login function", expected_tool: "edit", is_browser_positive: false, category: "code_change" },
    BenchmarkPrompt { prompt: "What version of Rust is installed?", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Summarize this project for me", expected_tool: "none", is_browser_positive: false, category: "general" },
    BenchmarkPrompt { prompt: "Fix the compilation error on line 58", expected_tool: "edit", is_browser_positive: false, category: "code_change" },
    BenchmarkPrompt { prompt: "Read the error log from the last failed test", expected_tool: "read", is_browser_positive: false, category: "file_ops" },
    BenchmarkPrompt { prompt: "What operating system am I running?", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Rename the variable 'x' to 'count' in parser.rs", expected_tool: "edit", is_browser_positive: false, category: "code_change" },
    BenchmarkPrompt { prompt: "Find all functions that return Result", expected_tool: "grep", is_browser_positive: false, category: "search" },
    BenchmarkPrompt { prompt: "Write a bash script to deploy the application", expected_tool: "write", is_browser_positive: false, category: "code_change" },
    BenchmarkPrompt { prompt: "List the project dependencies", expected_tool: "read", is_browser_positive: false, category: "file_ops" },
    BenchmarkPrompt { prompt: "What is the database schema?", expected_tool: "read", is_browser_positive: false, category: "code_understanding" },
    BenchmarkPrompt { prompt: "Run npm install && npm run build", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Search for security vulnerabilities in the code", expected_tool: "grep", is_browser_positive: false, category: "search" },
    BenchmarkPrompt { prompt: "How do I configure the database connection?", expected_tool: "none", is_browser_positive: false, category: "general" },
    BenchmarkPrompt { prompt: "Create a migration file for adding a users table", expected_tool: "write", is_browser_positive: false, category: "code_change" },
    BenchmarkPrompt { prompt: "Show me the git log of recent changes", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Check if all tests pass on the CI pipeline", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "What environment variables are set?", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Add error handling to the API endpoint", expected_tool: "edit", is_browser_positive: false, category: "code_change" },
    BenchmarkPrompt { prompt: "Explain the difference between Box and Rc in Rust", expected_tool: "none", is_browser_positive: false, category: "general" },
    BenchmarkPrompt { prompt: "Find all TODO comments in the codebase", expected_tool: "grep", is_browser_positive: false, category: "search" },
    BenchmarkPrompt { prompt: "Compress the log files in /var/log", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "Read the first 50 lines of the config file", expected_tool: "read", is_browser_positive: false, category: "file_ops" },
    BenchmarkPrompt { prompt: "What imports does main.rs use?", expected_tool: "read", is_browser_positive: false, category: "code_understanding" },
    BenchmarkPrompt { prompt: "Set up a pre-commit hook for formatting", expected_tool: "write", is_browser_positive: false, category: "code_change" },
    BenchmarkPrompt { prompt: "Kill the process running on port 8080", expected_tool: "bash", is_browser_positive: false, category: "shell" },
    BenchmarkPrompt { prompt: "What are the available make targets?", expected_tool: "read", is_browser_positive: false, category: "file_ops" },
    BenchmarkPrompt { prompt: "Find files larger than 1MB in the repo", expected_tool: "find", is_browser_positive: false, category: "search" },
    BenchmarkPrompt { prompt: "How should I structure the authentication module?", expected_tool: "none", is_browser_positive: false, category: "general" },
];

// ═══════════════════════════════════════════════════════════════════════════
// Corpus Validation (always run)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_corpus_has_50_positive_prompts() {
    assert_eq!(
        BROWSER_POSITIVE_PROMPTS.len(),
        50,
        "should have exactly 50 browser-positive prompts"
    );
}

#[test]
fn test_corpus_has_50_negative_prompts() {
    assert_eq!(
        BROWSER_NEGATIVE_PROMPTS.len(),
        50,
        "should have exactly 50 browser-negative prompts"
    );
}

#[test]
fn test_corpus_positive_prompts_all_browser_positive() {
    for (i, prompt) in BROWSER_POSITIVE_PROMPTS.iter().enumerate() {
        assert!(
            prompt.is_browser_positive,
            "positive prompt [{i}] should be browser_positive=true: '{}'",
            prompt.prompt
        );
        assert_ne!(
            prompt.expected_tool, "none",
            "positive prompt [{i}] should have a specific tool, not 'none': '{}'",
            prompt.prompt
        );
    }
}

#[test]
fn test_corpus_negative_prompts_all_browser_negative() {
    for (i, prompt) in BROWSER_NEGATIVE_PROMPTS.iter().enumerate() {
        assert!(
            !prompt.is_browser_positive,
            "negative prompt [{i}] should be browser_positive=false: '{}'",
            prompt.prompt
        );
    }
}

#[test]
fn test_corpus_covers_all_browser_tools() {
    use std::collections::HashSet;

    let all_browser_tool_names: HashSet<&str> = [
        "navigate", "tabs_create", "tabs_context", "switch_browser",
        "read_page", "get_page_text", "find",
        "computer", "form_input",
        "screenshot", "gif_creator", "javascript", "read_console_messages", "read_network_requests",
        "resize_window", "shortcuts_execute", "shortcuts_list", "upload_image",
        "observe", "unobserve", "observers",
    ].into_iter().collect();

    let covered: HashSet<&str> = BROWSER_POSITIVE_PROMPTS
        .iter()
        .map(|p| p.expected_tool)
        .collect();

    let missing: Vec<&&str> = all_browser_tool_names.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "positive corpus should cover all browser tools, missing: {:?}",
        missing
    );
}

#[test]
fn test_corpus_covers_all_builtin_tools() {
    use std::collections::HashSet;

    let builtin_tools: HashSet<&str> = ["read", "bash", "edit", "write", "grep", "find", "ls"]
        .into_iter()
        .collect();

    let covered: HashSet<&str> = BROWSER_NEGATIVE_PROMPTS
        .iter()
        .filter(|p| p.expected_tool != "none")
        .map(|p| p.expected_tool)
        .collect();

    let missing: Vec<&&str> = builtin_tools.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "negative corpus should cover all builtin tools, missing: {:?}",
        missing
    );
}

#[test]
fn test_corpus_categories_diverse() {
    use std::collections::HashSet;

    let positive_categories: HashSet<&str> = BROWSER_POSITIVE_PROMPTS
        .iter()
        .map(|p| p.category)
        .collect();
    let negative_categories: HashSet<&str> = BROWSER_NEGATIVE_PROMPTS
        .iter()
        .map(|p| p.category)
        .collect();

    assert!(positive_categories.len() >= 5, "positive prompts should span >= 5 categories");
    assert!(negative_categories.len() >= 4, "negative prompts should span >= 4 categories");
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark Result Types
// ═══════════════════════════════════════════════════════════════════════════

/// Result from a single benchmark prompt evaluation.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
struct PromptResult {
    prompt: String,
    expected_tool: String,
    actual_tool: String,
    correct: bool,
    is_browser_positive: bool,
    latency_ms: u64,
    provider: String,
    model: String,
}

/// Aggregate benchmark results for a provider.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
struct BenchmarkReport {
    provider: String,
    model: String,
    total_prompts: usize,
    overall_accuracy: f64,
    browser_positive_accuracy: f64,
    browser_negative_accuracy: f64,
    p95_latency_ms: u64,
    per_tool_confusion: Vec<ToolConfusion>,
}

/// Per-tool confusion analysis.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
struct ToolConfusion {
    expected_tool: String,
    correct_count: usize,
    total_count: usize,
    accuracy: f64,
    confused_with: Vec<(String, usize)>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Full Benchmark (requires PI_OQ1_BENCHMARK=1 + API keys)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[ignore]
fn test_oq1_full_benchmark() {
    if std::env::var("PI_OQ1_BENCHMARK").is_err() {
        eprintln!("[SKIP] requires PI_OQ1_BENCHMARK=1 and valid API keys");
        return;
    }

    let total = BROWSER_POSITIVE_PROMPTS.len() + BROWSER_NEGATIVE_PROMPTS.len();
    eprintln!("[OQ1] Running benchmark with {total} prompts...");
    eprintln!("[OQ1] Provider: Claude (requires ANTHROPIC_API_KEY)");
    eprintln!("[OQ1] Pass criteria: accuracy >= 95%, regression < 2%, latency < 200ms p95");

    // TODO: Wire to Pi's provider abstraction for live evaluation
    // 1. Build 7-tool registry, run all 100 prompts, record baseline
    // 2. Build 28-tool registry, run all 100 prompts, record full
    // 3. Compare accuracy, latency, per-tool confusion
    // 4. Apply threshold: if < 90%, flag need for context-dependent filtering

    eprintln!("[OQ1] Benchmark scaffold ready — live provider wiring pending");
}
