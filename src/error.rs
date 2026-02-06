//! Error types for the Pi application.

use thiserror::Error;

/// Result type alias using our error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the Pi application.
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Session errors
    #[error("Session error: {0}")]
    Session(String),

    /// Session not found
    #[error("Session not found: {path}")]
    SessionNotFound { path: String },

    /// Provider/API errors
    #[error("Provider error: {provider}: {message}")]
    Provider { provider: String, message: String },

    /// Authentication errors
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Tool execution errors
    #[error("Tool error: {tool}: {message}")]
    Tool { tool: String, message: String },

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Extension errors
    #[error("Extension error: {0}")]
    Extension(String),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] Box<std::io::Error>),

    /// JSON errors
    #[error("JSON error: {0}")]
    Json(#[from] Box<serde_json::Error>),

    /// SQLite errors
    #[error("SQLite error: {0}")]
    Sqlite(#[from] Box<sqlmodel_core::Error>),

    /// User aborted operation
    #[error("Operation aborted")]
    Aborted,

    /// API errors (generic)
    #[error("API error: {0}")]
    Api(String),
}

impl Error {
    /// Create a configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Create a session error.
    pub fn session(message: impl Into<String>) -> Self {
        Self::Session(message.into())
    }

    /// Create a provider error.
    pub fn provider(provider: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Provider {
            provider: provider.into(),
            message: message.into(),
        }
    }

    /// Create an authentication error.
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth(message.into())
    }

    /// Create a tool error.
    pub fn tool(tool: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Tool {
            tool: tool.into(),
            message: message.into(),
        }
    }

    /// Create a validation error.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    /// Create an extension error.
    pub fn extension(message: impl Into<String>) -> Self {
        Self::Extension(message.into())
    }

    /// Create an API error.
    pub fn api(message: impl Into<String>) -> Self {
        Self::Api(message.into())
    }

    /// Map this error to a hostcall taxonomy code.
    ///
    /// The hostcall ABI requires every error to be one of:
    /// `timeout`, `denied`, `io`, `invalid_request`, or `internal`.
    pub fn hostcall_error_code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "invalid_request",
            Self::Io(_) => "io",
            Self::Json(_) => "internal",
            Self::Session(_) | Self::SessionNotFound { .. } => "io",
            Self::Sqlite(_) => "io",
            Self::Auth(_) => "denied",
            Self::Aborted => "timeout",
            Self::Extension(_)
            | Self::Config(_)
            | Self::Provider { .. }
            | Self::Tool { .. }
            | Self::Api(_) => "internal",
        }
    }

    /// Map internal errors to a stable, user-facing hint taxonomy.
    #[must_use]
    pub fn hints(&self) -> ErrorHints {
        match self {
            Self::Config(message) => config_hints(message),
            Self::Session(message) => session_hints(message),
            Self::SessionNotFound { path } => build_hints(
                "Session file not found.",
                vec![
                    "Use `pi --continue` to open the most recent session.".to_string(),
                    "Verify the path or move the session back into the sessions directory."
                        .to_string(),
                ],
                vec![("path", path.clone())],
            ),
            Self::Provider { provider, message } => provider_hints(provider, message),
            Self::Auth(message) => auth_hints(message),
            Self::Tool { tool, message } => tool_hints(tool, message),
            Self::Validation(message) => build_hints(
                "Validation failed for input or config.",
                vec![
                    "Check the specific fields mentioned in the error.".to_string(),
                    "Review CLI flags or settings for typos.".to_string(),
                ],
                vec![("details", message.clone())],
            ),
            Self::Extension(message) => build_hints(
                "Extension failed to load or run.",
                vec![
                    "Try `--no-extensions` to isolate the issue.".to_string(),
                    "Check the extension manifest and dependencies.".to_string(),
                ],
                vec![("details", message.clone())],
            ),
            Self::Io(err) => io_hints(err),
            Self::Json(err) => build_hints(
                "JSON parsing failed.",
                vec![
                    "Validate the JSON syntax (no trailing commas).".to_string(),
                    "Check that the file is UTF-8 and not truncated.".to_string(),
                ],
                vec![("details", err.to_string())],
            ),
            Self::Sqlite(err) => sqlite_hints(err),
            Self::Aborted => build_hints(
                "Operation aborted.",
                Vec::new(),
                vec![(
                    "details",
                    "Operation cancelled by user or runtime.".to_string(),
                )],
            ),
            Self::Api(message) => build_hints(
                "API request failed.",
                vec![
                    "Check your network connection and retry.".to_string(),
                    "Verify your API key and provider selection.".to_string(),
                ],
                vec![("details", message.clone())],
            ),
        }
    }
}

/// Structured hints for error remediation.
#[derive(Debug, Clone)]
pub struct ErrorHints {
    /// Brief summary of the error category.
    pub summary: String,
    /// Actionable hints for the user.
    pub hints: Vec<String>,
    /// Key-value context pairs for display.
    pub context: Vec<(String, String)>,
}

fn build_hints(summary: &str, hints: Vec<String>, context: Vec<(&str, String)>) -> ErrorHints {
    ErrorHints {
        summary: summary.to_string(),
        hints,
        context: context
            .into_iter()
            .map(|(label, value)| (label.to_string(), value))
            .collect(),
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn config_hints(message: &str) -> ErrorHints {
    let lower = message.to_lowercase();
    if contains_any(&lower, &["json", "parse", "serde"]) {
        return build_hints(
            "Configuration file is not valid JSON.",
            vec![
                "Fix JSON formatting in the active settings file.".to_string(),
                "Run `pi config` to see which settings file is in use.".to_string(),
            ],
            vec![("details", message.to_string())],
        );
    }
    if contains_any(&lower, &["missing", "not found", "no such file"]) {
        return build_hints(
            "Configuration file is missing.",
            vec![
                "Create `~/.pi/agent/settings.json` or set `PI_CONFIG_PATH`.".to_string(),
                "Run `pi config` to confirm the resolved path.".to_string(),
            ],
            vec![("details", message.to_string())],
        );
    }
    build_hints(
        "Configuration error.",
        vec![
            "Review your settings file for incorrect values.".to_string(),
            "Run `pi config` to verify settings precedence.".to_string(),
        ],
        vec![("details", message.to_string())],
    )
}

fn session_hints(message: &str) -> ErrorHints {
    let lower = message.to_lowercase();
    if contains_any(&lower, &["empty session file", "empty session"]) {
        return build_hints(
            "Session file is empty or corrupted.",
            vec![
                "Start a new session with `pi --no-session`.".to_string(),
                "Inspect the session file for truncation.".to_string(),
            ],
            vec![("details", message.to_string())],
        );
    }
    if contains_any(&lower, &["failed to read", "read dir", "read session"]) {
        return build_hints(
            "Failed to read session data.",
            vec![
                "Check file permissions for the sessions directory.".to_string(),
                "Verify `PI_SESSIONS_DIR` if you set it.".to_string(),
            ],
            vec![("details", message.to_string())],
        );
    }
    build_hints(
        "Session error.",
        vec![
            "Try `pi --continue` or specify `--session <path>`.".to_string(),
            "Check session file integrity in the sessions directory.".to_string(),
        ],
        vec![("details", message.to_string())],
    )
}

fn provider_hints(provider: &str, message: &str) -> ErrorHints {
    let lower = message.to_lowercase();
    let key_hint = provider_key_hint(provider);
    let context = vec![
        ("provider", provider.to_string()),
        ("details", message.to_string()),
    ];

    if contains_any(
        &lower,
        &["401", "unauthorized", "invalid api key", "api key"],
    ) {
        return build_hints(
            "Provider authentication failed.",
            vec![key_hint, "If using OAuth, run `/login` again.".to_string()],
            context,
        );
    }
    if contains_any(&lower, &["403", "forbidden"]) {
        return build_hints(
            "Provider access forbidden.",
            vec![
                "Verify the account has access to the requested model.".to_string(),
                "Check organization/project permissions for the API key.".to_string(),
            ],
            context,
        );
    }
    if contains_any(&lower, &["429", "rate limit", "too many requests"]) {
        return build_hints(
            "Provider rate limited the request.",
            vec![
                "Wait and retry, or reduce request rate.".to_string(),
                "Consider smaller max_tokens to lower load.".to_string(),
            ],
            context,
        );
    }
    if contains_any(&lower, &["529", "overloaded"]) {
        return build_hints(
            "Provider is overloaded.",
            vec![
                "Retry after a short delay.".to_string(),
                "Switch to a different model if available.".to_string(),
            ],
            context,
        );
    }
    if contains_any(&lower, &["timeout", "timed out"]) {
        return build_hints(
            "Provider request timed out.",
            vec![
                "Check network stability and retry.".to_string(),
                "Lower max_tokens to shorten responses.".to_string(),
            ],
            context,
        );
    }
    if contains_any(&lower, &["400", "bad request", "invalid request"]) {
        return build_hints(
            "Provider rejected the request.",
            vec![
                "Check model name, tools schema, and request size.".to_string(),
                "Reduce message size or tool payloads.".to_string(),
            ],
            context,
        );
    }
    if contains_any(&lower, &["500", "internal server error", "server error"]) {
        return build_hints(
            "Provider encountered a server error.",
            vec![
                "Retry after a short delay.".to_string(),
                "If persistent, try a different model/provider.".to_string(),
            ],
            context,
        );
    }
    build_hints(
        "Provider request failed.",
        vec![
            key_hint,
            "Check network connectivity and provider status.".to_string(),
        ],
        context,
    )
}

fn provider_key_hint(provider: &str) -> String {
    match provider.to_lowercase().as_str() {
        "anthropic" => "Set `ANTHROPIC_API_KEY` (or use `/login anthropic`).".to_string(),
        "openai" => "Set `OPENAI_API_KEY` for OpenAI requests.".to_string(),
        "gemini" | "google" => "Set `GOOGLE_API_KEY` for Gemini requests.".to_string(),
        "azure" | "azure_openai" | "azure-openai" => {
            "Set `AZURE_OPENAI_API_KEY` for Azure OpenAI.".to_string()
        }
        _ => format!("Check API key configuration for provider `{provider}`."),
    }
}

fn auth_hints(message: &str) -> ErrorHints {
    let lower = message.to_lowercase();
    if contains_any(
        &lower,
        &["missing authorization code", "authorization code"],
    ) {
        return build_hints(
            "OAuth login did not complete.",
            vec![
                "Run `/login` again to restart the flow.".to_string(),
                "Ensure the browser redirect URL was opened.".to_string(),
            ],
            vec![("details", message.to_string())],
        );
    }
    if contains_any(&lower, &["token exchange failed", "invalid token response"]) {
        return build_hints(
            "OAuth token exchange failed.",
            vec![
                "Retry `/login` to refresh credentials.".to_string(),
                "Check network connectivity during the login flow.".to_string(),
            ],
            vec![("details", message.to_string())],
        );
    }
    build_hints(
        "Authentication error.",
        vec![
            "Verify API keys or run `/login`.".to_string(),
            "Check auth.json permissions in the Pi config directory.".to_string(),
        ],
        vec![("details", message.to_string())],
    )
}

fn tool_hints(tool: &str, message: &str) -> ErrorHints {
    let lower = message.to_lowercase();
    if contains_any(&lower, &["not found", "no such file", "command not found"]) {
        return build_hints(
            "Tool executable or target not found.",
            vec![
                "Check PATH and tool installation.".to_string(),
                "Verify the tool input path exists.".to_string(),
            ],
            vec![("tool", tool.to_string()), ("details", message.to_string())],
        );
    }
    build_hints(
        "Tool execution failed.",
        vec![
            "Check the tool output for details.".to_string(),
            "Re-run with simpler inputs to isolate the failure.".to_string(),
        ],
        vec![("tool", tool.to_string()), ("details", message.to_string())],
    )
}

fn io_hints(err: &std::io::Error) -> ErrorHints {
    let details = err.to_string();
    match err.kind() {
        std::io::ErrorKind::NotFound => build_hints(
            "Required file or directory not found.",
            vec![
                "Verify the path exists and is spelled correctly.".to_string(),
                "Check `PI_CONFIG_PATH` or `PI_SESSIONS_DIR` overrides.".to_string(),
            ],
            vec![
                ("error_kind", format!("{:?}", err.kind())),
                ("details", details),
            ],
        ),
        std::io::ErrorKind::PermissionDenied => build_hints(
            "Permission denied while accessing a file.",
            vec![
                "Check file permissions or ownership.".to_string(),
                "Try a different location with write access.".to_string(),
            ],
            vec![
                ("error_kind", format!("{:?}", err.kind())),
                ("details", details),
            ],
        ),
        std::io::ErrorKind::TimedOut => build_hints(
            "I/O operation timed out.",
            vec![
                "Check network or filesystem latency.".to_string(),
                "Retry after confirming connectivity.".to_string(),
            ],
            vec![
                ("error_kind", format!("{:?}", err.kind())),
                ("details", details),
            ],
        ),
        std::io::ErrorKind::ConnectionRefused => build_hints(
            "Connection refused.",
            vec![
                "Check network connectivity or proxy settings.".to_string(),
                "Verify the target service is reachable.".to_string(),
            ],
            vec![
                ("error_kind", format!("{:?}", err.kind())),
                ("details", details),
            ],
        ),
        _ => build_hints(
            "I/O error occurred.",
            vec![
                "Check file paths and permissions.".to_string(),
                "Retry after resolving any transient issues.".to_string(),
            ],
            vec![
                ("error_kind", format!("{:?}", err.kind())),
                ("details", details),
            ],
        ),
    }
}

fn sqlite_hints(err: &sqlmodel_core::Error) -> ErrorHints {
    let details = err.to_string();
    let lower = details.to_lowercase();
    if contains_any(&lower, &["database is locked", "busy"]) {
        return build_hints(
            "SQLite database is locked.",
            vec![
                "Close other Pi instances using the same database.".to_string(),
                "Retry once the lock clears.".to_string(),
            ],
            vec![("details", details)],
        );
    }
    build_hints(
        "SQLite error.",
        vec![
            "Ensure the database path is writable.".to_string(),
            "Check for schema or migration issues.".to_string(),
        ],
        vec![("details", details)],
    )
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(Box::new(value))
    }
}

impl From<asupersync::sync::LockError> for Error {
    fn from(value: asupersync::sync::LockError) -> Self {
        match value {
            asupersync::sync::LockError::Cancelled => Self::Aborted,
            asupersync::sync::LockError::Poisoned => Self::session(value.to_string()),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(Box::new(value))
    }
}

impl From<sqlmodel_core::Error> for Error {
    fn from(value: sqlmodel_core::Error) -> Self {
        Self::Sqlite(Box::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Constructor tests ──────────────────────────────────────────────

    #[test]
    fn error_config_constructor() {
        let err = Error::config("bad config");
        assert!(matches!(err, Error::Config(ref msg) if msg == "bad config"));
    }

    #[test]
    fn error_session_constructor() {
        let err = Error::session("session corrupted");
        assert!(matches!(err, Error::Session(ref msg) if msg == "session corrupted"));
    }

    #[test]
    fn error_provider_constructor() {
        let err = Error::provider("anthropic", "timeout");
        assert!(matches!(err, Error::Provider { ref provider, ref message }
            if provider == "anthropic" && message == "timeout"));
    }

    #[test]
    fn error_auth_constructor() {
        let err = Error::auth("missing key");
        assert!(matches!(err, Error::Auth(ref msg) if msg == "missing key"));
    }

    #[test]
    fn error_tool_constructor() {
        let err = Error::tool("bash", "exit code 1");
        assert!(matches!(err, Error::Tool { ref tool, ref message }
            if tool == "bash" && message == "exit code 1"));
    }

    #[test]
    fn error_validation_constructor() {
        let err = Error::validation("field required");
        assert!(matches!(err, Error::Validation(ref msg) if msg == "field required"));
    }

    #[test]
    fn error_extension_constructor() {
        let err = Error::extension("manifest invalid");
        assert!(matches!(err, Error::Extension(ref msg) if msg == "manifest invalid"));
    }

    #[test]
    fn error_api_constructor() {
        let err = Error::api("404 not found");
        assert!(matches!(err, Error::Api(ref msg) if msg == "404 not found"));
    }

    // ─── Display message tests ──────────────────────────────────────────

    #[test]
    fn error_config_display() {
        let err = Error::config("missing settings.json");
        let msg = err.to_string();
        assert!(msg.contains("Configuration error"));
        assert!(msg.contains("missing settings.json"));
    }

    #[test]
    fn error_session_display() {
        let err = Error::session("tree corrupted");
        let msg = err.to_string();
        assert!(msg.contains("Session error"));
        assert!(msg.contains("tree corrupted"));
    }

    #[test]
    fn error_session_not_found_display() {
        let err = Error::SessionNotFound {
            path: "/home/user/.pi/sessions/abc.jsonl".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Session not found"));
        assert!(msg.contains("/home/user/.pi/sessions/abc.jsonl"));
    }

    #[test]
    fn error_provider_display() {
        let err = Error::provider("openai", "429 too many requests");
        let msg = err.to_string();
        assert!(msg.contains("Provider error"));
        assert!(msg.contains("openai"));
        assert!(msg.contains("429 too many requests"));
    }

    #[test]
    fn error_auth_display() {
        let err = Error::auth("API key expired");
        let msg = err.to_string();
        assert!(msg.contains("Authentication error"));
        assert!(msg.contains("API key expired"));
    }

    #[test]
    fn error_tool_display() {
        let err = Error::tool("read", "file not found: /tmp/x.txt");
        let msg = err.to_string();
        assert!(msg.contains("Tool error"));
        assert!(msg.contains("read"));
        assert!(msg.contains("file not found: /tmp/x.txt"));
    }

    #[test]
    fn error_validation_display() {
        let err = Error::validation("temperature must be 0-2");
        let msg = err.to_string();
        assert!(msg.contains("Validation error"));
        assert!(msg.contains("temperature must be 0-2"));
    }

    #[test]
    fn error_extension_display() {
        let err = Error::extension("manifest parse failed");
        let msg = err.to_string();
        assert!(msg.contains("Extension error"));
        assert!(msg.contains("manifest parse failed"));
    }

    #[test]
    fn error_aborted_display() {
        let err = Error::Aborted;
        let msg = err.to_string();
        assert!(msg.contains("Operation aborted"));
    }

    #[test]
    fn error_api_display() {
        let err = Error::api("GitHub API error 403");
        let msg = err.to_string();
        assert!(msg.contains("API error"));
        assert!(msg.contains("GitHub API error 403"));
    }

    #[test]
    fn error_io_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let err = Error::from(io_err);
        let msg = err.to_string();
        assert!(msg.contains("IO error"));
    }

    #[test]
    fn error_json_display() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = Error::from(json_err);
        let msg = err.to_string();
        assert!(msg.contains("JSON error"));
    }

    // ─── From impls ─────────────────────────────────────────────────────

    #[test]
    fn error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn error_from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid").unwrap_err();
        let err: Error = json_err.into();
        assert!(matches!(err, Error::Json(_)));
    }

    // ─── Hints method tests (error.rs hints) ────────────────────────────

    #[test]
    fn hints_config_json_parse_error() {
        let err = Error::config("JSON parse error in settings.json");
        let h = err.hints();
        assert!(h.summary.contains("not valid JSON"));
        assert!(h.hints.iter().any(|s| s.contains("JSON formatting")));
    }

    #[test]
    fn hints_config_missing_file() {
        let err = Error::config("config file not found: ~/.pi/settings");
        let h = err.hints();
        assert!(h.summary.contains("missing"));
    }

    #[test]
    fn hints_config_generic() {
        let err = Error::config("unknown config issue");
        let h = err.hints();
        assert!(h.summary.contains("Configuration error"));
    }

    #[test]
    fn hints_session_empty() {
        let err = Error::session("empty session file");
        let h = err.hints();
        assert!(h.summary.contains("empty") || h.summary.contains("corrupted"));
    }

    #[test]
    fn hints_session_read_failure() {
        let err = Error::session("failed to read session directory");
        let h = err.hints();
        assert!(h.summary.contains("Failed to read"));
    }

    #[test]
    fn hints_session_not_found() {
        let err = Error::SessionNotFound {
            path: "/tmp/session.jsonl".to_string(),
        };
        let h = err.hints();
        assert!(h.summary.contains("not found"));
        assert!(
            h.context
                .iter()
                .any(|(k, v)| k == "path" && v.contains("/tmp/session.jsonl"))
        );
    }

    #[test]
    fn hints_provider_401() {
        let err = Error::provider("anthropic", "HTTP 401 unauthorized");
        let h = err.hints();
        assert!(h.summary.contains("authentication failed"));
        assert!(h.hints.iter().any(|s| s.contains("ANTHROPIC_API_KEY")));
    }

    #[test]
    fn hints_provider_403() {
        let err = Error::provider("openai", "403 forbidden");
        let h = err.hints();
        assert!(h.summary.contains("forbidden"));
    }

    #[test]
    fn hints_provider_429() {
        let err = Error::provider("anthropic", "429 rate limit");
        let h = err.hints();
        assert!(h.summary.contains("rate limited"));
    }

    #[test]
    fn hints_provider_529() {
        let err = Error::provider("anthropic", "529 overloaded");
        let h = err.hints();
        assert!(h.summary.contains("overloaded"));
    }

    #[test]
    fn hints_provider_timeout() {
        let err = Error::provider("openai", "request timed out");
        let h = err.hints();
        assert!(h.summary.contains("timed out"));
    }

    #[test]
    fn hints_provider_400() {
        let err = Error::provider("gemini", "400 bad request");
        let h = err.hints();
        assert!(h.summary.contains("rejected"));
    }

    #[test]
    fn hints_provider_500() {
        let err = Error::provider("cohere", "500 internal server error");
        let h = err.hints();
        assert!(h.summary.contains("server error"));
    }

    #[test]
    fn hints_provider_generic() {
        let err = Error::provider("custom", "unknown issue");
        let h = err.hints();
        assert!(h.summary.contains("failed"));
        assert!(h.context.iter().any(|(k, _)| k == "provider"));
    }

    #[test]
    fn hints_provider_key_hint_openai() {
        let err = Error::provider("openai", "401 invalid api key");
        let h = err.hints();
        assert!(h.hints.iter().any(|s| s.contains("OPENAI_API_KEY")));
    }

    #[test]
    fn hints_provider_key_hint_gemini() {
        let err = Error::provider("gemini", "401 api key invalid");
        let h = err.hints();
        assert!(h.hints.iter().any(|s| s.contains("GOOGLE_API_KEY")));
    }

    #[test]
    fn hints_provider_key_hint_azure() {
        let err = Error::provider("azure_openai", "401 unauthorized");
        let h = err.hints();
        assert!(h.hints.iter().any(|s| s.contains("AZURE_OPENAI_API_KEY")));
    }

    #[test]
    fn hints_provider_key_hint_unknown() {
        let err = Error::provider("my-proxy", "401 unauthorized");
        let h = err.hints();
        assert!(h.hints.iter().any(|s| s.contains("my-proxy")));
    }

    #[test]
    fn hints_auth_authorization_code() {
        let err = Error::auth("missing authorization code");
        let h = err.hints();
        assert!(h.summary.contains("OAuth"));
    }

    #[test]
    fn hints_auth_token_exchange() {
        let err = Error::auth("token exchange failed");
        let h = err.hints();
        assert!(h.summary.contains("token exchange"));
    }

    #[test]
    fn hints_auth_generic() {
        let err = Error::auth("unknown auth issue");
        let h = err.hints();
        assert!(h.summary.contains("Authentication error"));
    }

    #[test]
    fn hints_tool_not_found() {
        let err = Error::tool("bash", "command not found: xyz");
        let h = err.hints();
        assert!(h.summary.contains("not found"));
    }

    #[test]
    fn hints_tool_generic() {
        let err = Error::tool("read", "unexpected error");
        let h = err.hints();
        assert!(h.summary.contains("execution failed"));
    }

    #[test]
    fn hints_validation() {
        let err = Error::validation("invalid input");
        let h = err.hints();
        assert!(h.summary.contains("Validation"));
    }

    #[test]
    fn hints_extension() {
        let err = Error::extension("load error");
        let h = err.hints();
        assert!(h.summary.contains("Extension"));
    }

    #[test]
    fn hints_io_not_found() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let err = Error::from(io_err);
        let h = err.hints();
        assert!(h.summary.contains("not found"));
    }

    #[test]
    fn hints_io_permission_denied() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = Error::from(io_err);
        let h = err.hints();
        assert!(h.summary.contains("Permission denied"));
    }

    #[test]
    fn hints_io_timed_out() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let err = Error::from(io_err);
        let h = err.hints();
        assert!(h.summary.contains("timed out"));
    }

    #[test]
    fn hints_io_connection_refused() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err = Error::from(io_err);
        let h = err.hints();
        assert!(h.summary.contains("Connection refused"));
    }

    #[test]
    fn hints_io_generic() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "something");
        let err = Error::from(io_err);
        let h = err.hints();
        assert!(h.summary.contains("I/O error"));
    }

    #[test]
    fn hints_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("broken").unwrap_err();
        let err = Error::from(json_err);
        let h = err.hints();
        assert!(h.summary.contains("JSON"));
    }

    #[test]
    fn hints_aborted() {
        let err = Error::Aborted;
        let h = err.hints();
        assert!(h.summary.contains("aborted"));
    }

    #[test]
    fn hints_api() {
        let err = Error::api("connection reset");
        let h = err.hints();
        assert!(h.summary.contains("API"));
    }
}
