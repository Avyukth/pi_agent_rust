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
