//! Chrome browser tool configuration (PLAN §4.7).
//!
//! The `ChromeConfig` struct lives under the optional `"chrome"` key in Pi's
//! main settings JSON. When absent, browser tools are disabled (S1 safety
//! invariant).
//!
//! ## Coupling Invariant
//!
//! The ESL journal TTL must be large enough to survive a full reconnect cycle
//! plus a safety margin:
//!
//! ```text
//! journal_ttl_ms >= lease_ttl_ms + (max_reconnect_attempts + 1) * socket_timeout_ms + 10_000
//! ```
//!
//! This is validated at parse time via [`ChromeConfig::validate`].

use serde::{Deserialize, Serialize};

// ============================================================================
// Defaults (interview-locked from PLAN §4.7)
// ============================================================================

/// Default socket timeout in milliseconds.
pub const DEFAULT_SOCKET_TIMEOUT_MS: u64 = 5_000;

/// Default maximum reconnection attempts before disabling browser tools.
pub const DEFAULT_MAX_RECONNECT_ATTEMPTS: u8 = 3;

/// Default native host idle timeout in seconds.
pub const DEFAULT_NATIVE_HOST_IDLE_TIMEOUT_S: u64 = 30;

/// Default ESL request journal TTL in seconds.
pub const DEFAULT_REQUEST_JOURNAL_TTL_S: u64 = 60;

/// Default ESL lease TTL in milliseconds (matches protocol.rs auth_ok).
pub const DEFAULT_LEASE_TTL_MS: u64 = 30_000;

/// Safety margin for the coupling invariant (milliseconds).
const COUPLING_SAFETY_MARGIN_MS: u64 = 10_000;

// ============================================================================
// Voice defaults (from VOICE-BUILD-SPEC §6.9 + README §Configuration)
// ============================================================================

/// Default STT timeout after PTT release (seconds).
pub const DEFAULT_STT_TIMEOUT_S: u64 = 5;

/// Default TTS speech rate multiplier (1.0 = normal).
pub const DEFAULT_TTS_RATE: f64 = 1.0;

/// Default TTS pitch multiplier (1.0 = normal).
pub const DEFAULT_TTS_PITCH: f64 = 1.0;

// ============================================================================
// VoiceConfig
// ============================================================================

/// Voice configuration, nested under `ChromeConfig.voice`.
///
/// When absent (or `enabled: false`), voice tools are not registered and
/// all voice functionality is disabled (VS1 safety invariant).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VoiceConfig {
    /// Master enable/disable for voice tools.
    pub enabled: bool,

    /// Max seconds to wait for STT result after PTT release.
    pub stt_timeout_s: u64,

    /// TTS speech rate multiplier (1.0 = normal).
    pub tts_rate: f64,

    /// TTS pitch multiplier (1.0 = normal).
    pub tts_pitch: f64,

    /// Preferred OS voice name (None = system default).
    pub tts_voice_name: Option<String>,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            stt_timeout_s: DEFAULT_STT_TIMEOUT_S,
            tts_rate: DEFAULT_TTS_RATE,
            tts_pitch: DEFAULT_TTS_PITCH,
            tts_voice_name: None,
        }
    }
}

// ============================================================================
// ChromeConfig
// ============================================================================

/// Browser tool configuration, deserialized from the `"chrome"` key in Pi
/// settings JSON. All fields are optional with interview-locked defaults.
///
/// Absence of the `"chrome"` key (or `enabled: false`) means browser tools
/// are disabled — the agent will not attempt to connect to a native host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChromeConfig {
    /// Master enable/disable for browser tools.
    pub enabled: bool,

    /// Voice configuration. When absent or `enabled: false`, voice tools
    /// are not registered (VS1 safety invariant: `--chrome-voice` opt-in).
    pub voice: VoiceConfig,

    /// Socket timeout for native host connections (milliseconds).
    pub socket_timeout_ms: u64,

    /// Maximum reconnection attempts before disabling browser tools.
    pub max_reconnect_attempts: u8,

    /// Native host idle timeout (seconds). Host exits if no activity.
    pub native_host_idle_timeout_s: u64,

    /// ESL request journal TTL (seconds). Must satisfy the coupling invariant.
    pub request_journal_ttl_s: u64,

    /// ESL lease TTL (milliseconds). Overrides the default from auth_ok.
    pub lease_ttl_ms: u64,
}

impl Default for ChromeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            voice: VoiceConfig::default(),
            socket_timeout_ms: DEFAULT_SOCKET_TIMEOUT_MS,
            max_reconnect_attempts: DEFAULT_MAX_RECONNECT_ATTEMPTS,
            native_host_idle_timeout_s: DEFAULT_NATIVE_HOST_IDLE_TIMEOUT_S,
            request_journal_ttl_s: DEFAULT_REQUEST_JOURNAL_TTL_S,
            lease_ttl_ms: DEFAULT_LEASE_TTL_MS,
        }
    }
}

impl ChromeConfig {
    /// Validate the coupling invariant and all configuration values.
    ///
    /// Returns `Ok(())` if valid, or a descriptive error string if violated.
    ///
    /// The coupling invariant ensures the ESL journal outlives a full reconnect
    /// cycle:
    ///
    /// ```text
    /// journal_ttl_ms >= lease_ttl_ms + (max_reconnect + 1) * socket_timeout_ms + 10_000
    /// ```
    pub fn validate(&self) -> Result<(), ChromeConfigError> {
        // Socket timeout must be positive
        if self.socket_timeout_ms == 0 {
            return Err(ChromeConfigError::InvalidValue {
                field: "socket_timeout_ms",
                reason: "must be > 0",
            });
        }

        // Journal TTL must be positive
        if self.request_journal_ttl_s == 0 {
            return Err(ChromeConfigError::InvalidValue {
                field: "request_journal_ttl_s",
                reason: "must be > 0",
            });
        }

        // Coupling invariant
        let journal_ttl_ms = self.request_journal_ttl_s.saturating_mul(1000);
        let reconnect_window_ms =
            (u64::from(self.max_reconnect_attempts) + 1).saturating_mul(self.socket_timeout_ms);
        let min_journal_ttl_ms = self
            .lease_ttl_ms
            .saturating_add(reconnect_window_ms)
            .saturating_add(COUPLING_SAFETY_MARGIN_MS);

        if journal_ttl_ms < min_journal_ttl_ms {
            return Err(ChromeConfigError::CouplingInvariantViolation {
                journal_ttl_ms,
                min_required_ms: min_journal_ttl_ms,
                lease_ttl_ms: self.lease_ttl_ms,
                reconnect_window_ms,
            });
        }

        Ok(())
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Errors from ChromeConfig validation.
#[derive(Debug, Clone)]
pub enum ChromeConfigError {
    /// A configuration field has an invalid value.
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },

    /// The ESL coupling invariant is violated.
    CouplingInvariantViolation {
        journal_ttl_ms: u64,
        min_required_ms: u64,
        lease_ttl_ms: u64,
        reconnect_window_ms: u64,
    },
}

impl std::fmt::Display for ChromeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidValue { field, reason } => {
                write!(f, "chrome config: {field} {reason}")
            }
            Self::CouplingInvariantViolation {
                journal_ttl_ms,
                min_required_ms,
                lease_ttl_ms,
                reconnect_window_ms,
            } => {
                write!(
                    f,
                    "chrome config: ESL coupling invariant violated — \
                     journal_ttl_ms ({journal_ttl_ms}) < min required ({min_required_ms}). \
                     Formula: journal_ttl_ms >= lease_ttl_ms ({lease_ttl_ms}) + \
                     reconnect_window_ms ({reconnect_window_ms}) + 10000"
                )
            }
        }
    }
}

impl std::error::Error for ChromeConfigError {}

// ============================================================================
// Error-to-ToolOutput conversion for browser errors
// ============================================================================

use super::protocol::ProtocolErrorCode;
use crate::model::{ContentBlock, TextContent};
use crate::tools::ToolOutput;

/// Convert a protocol error code into a ToolOutput with is_error=true.
///
/// Maps each browser error to a human-readable message and preserves the
/// `retryable` flag as guidance in the details.
pub fn browser_error_to_tool_output(
    code: ProtocolErrorCode,
    message: &str,
    retryable: bool,
) -> ToolOutput {
    ToolOutput {
        content: vec![ContentBlock::Text(TextContent::new(format!(
            "Browser error [{code}]: {message}",
            code = error_code_display(code),
        )))],
        details: Some(serde_json::json!({
            "error_code": error_code_display(code),
            "message": message,
            "retryable": retryable,
        })),
        is_error: true,
    }
}

/// Whether a protocol error code is retryable by default.
///
/// This is host guidance only — ESL/execution-class policy may override.
/// `CHROME_BRIDGE_EXECUTION_INDETERMINATE` is always non-retryable for
/// non-idempotent operations (fail-closed).
pub const fn is_retryable(code: ProtocolErrorCode) -> bool {
    matches!(
        code,
        ProtocolErrorCode::ChromeBridgeDisconnected
            | ProtocolErrorCode::ChromeBridgeTimeout
            | ProtocolErrorCode::ScreenshotFailed
    )
}

/// Display string for a protocol error code (SCREAMING_SNAKE_CASE).
const fn error_code_display(code: ProtocolErrorCode) -> &'static str {
    match code {
        ProtocolErrorCode::ChromeNotFound => "CHROME_NOT_FOUND",
        ProtocolErrorCode::ExtensionNotInstalled => "EXTENSION_NOT_INSTALLED",
        ProtocolErrorCode::ChromeBridgeDisconnected => "CHROME_BRIDGE_DISCONNECTED",
        ProtocolErrorCode::ChromeBridgeAuthFailed => "CHROME_BRIDGE_AUTH_FAILED",
        ProtocolErrorCode::ChromeBridgeBusy => "CHROME_BRIDGE_BUSY",
        ProtocolErrorCode::ChromeBridgeProtocolMismatch => "CHROME_BRIDGE_PROTOCOL_MISMATCH",
        ProtocolErrorCode::ChromeBridgeTimeout => "CHROME_BRIDGE_TIMEOUT",
        ProtocolErrorCode::ChromeBridgeExecutionIndeterminate => {
            "CHROME_BRIDGE_EXECUTION_INDETERMINATE"
        }
        ProtocolErrorCode::TabNotFound => "TAB_NOT_FOUND",
        ProtocolErrorCode::ElementNotFound => "ELEMENT_NOT_FOUND",
        ProtocolErrorCode::NavigationFailed => "NAVIGATION_FAILED",
        ProtocolErrorCode::ScreenshotFailed => "SCREENSHOT_FAILED",
        ProtocolErrorCode::JavascriptError => "JAVASCRIPT_ERROR",
        ProtocolErrorCode::ObserverTabClosed => "OBSERVER_TAB_CLOSED",
        ProtocolErrorCode::ObserverLimitReached => "OBSERVER_LIMIT_REACHED",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Default config tests
    // -----------------------------------------------------------------------

    #[test]
    fn defaults_are_valid() {
        let config = ChromeConfig::default();
        config.validate().expect("default config must be valid");
    }

    #[test]
    fn defaults_match_plan_values() {
        let config = ChromeConfig::default();
        assert!(config.enabled);
        assert_eq!(config.socket_timeout_ms, 5_000);
        assert_eq!(config.max_reconnect_attempts, 3);
        assert_eq!(config.native_host_idle_timeout_s, 30);
        assert_eq!(config.request_journal_ttl_s, 60);
        assert_eq!(config.lease_ttl_ms, 30_000);
    }

    #[test]
    fn absent_chrome_key_means_none() {
        let json = serde_json::json!({
            "theme": "dark",
        });
        let chrome: Option<ChromeConfig> = json
            .get("chrome")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        assert!(chrome.is_none(), "absent chrome key should parse as None");
    }

    #[test]
    fn empty_chrome_object_uses_defaults() {
        let config: ChromeConfig = serde_json::from_value(serde_json::json!({}))
            .expect("empty object should parse with defaults");
        assert!(config.enabled);
        assert_eq!(config.socket_timeout_ms, DEFAULT_SOCKET_TIMEOUT_MS);
    }

    #[test]
    fn partial_chrome_object_fills_defaults() {
        let config: ChromeConfig = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "socket_timeout_ms": 10000
        }))
        .expect("partial config should parse");
        assert!(!config.enabled);
        assert_eq!(config.socket_timeout_ms, 10_000);
        assert_eq!(
            config.max_reconnect_attempts,
            DEFAULT_MAX_RECONNECT_ATTEMPTS
        );
    }

    // -----------------------------------------------------------------------
    // Coupling invariant tests
    // -----------------------------------------------------------------------

    #[test]
    fn coupling_invariant_satisfied_with_defaults() {
        // Formula: journal_ttl_ms >= lease_ttl_ms + (max_reconnect + 1) * socket_timeout_ms + 10_000
        // 60_000 >= 30_000 + (3 + 1) * 5_000 + 10_000
        // 60_000 >= 30_000 + 20_000 + 10_000
        // 60_000 >= 60_000  ✓
        let config = ChromeConfig::default();
        config
            .validate()
            .expect("defaults satisfy coupling invariant");
    }

    #[test]
    fn coupling_invariant_violated_with_low_journal_ttl() {
        let config = ChromeConfig {
            request_journal_ttl_s: 30, // 30_000ms < 60_000ms required
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("should violate coupling invariant");
        assert!(
            matches!(err, ChromeConfigError::CouplingInvariantViolation { .. }),
            "expected CouplingInvariantViolation, got: {err}"
        );
    }

    #[test]
    fn coupling_invariant_violated_with_high_socket_timeout() {
        let config = ChromeConfig {
            socket_timeout_ms: 20_000, // (3+1)*20_000 = 80_000 + 30_000 + 10_000 = 120_000 > 60_000
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("should violate coupling invariant");
        assert!(
            matches!(err, ChromeConfigError::CouplingInvariantViolation { .. }),
            "expected CouplingInvariantViolation, got: {err}"
        );
    }

    #[test]
    fn coupling_invariant_satisfied_with_generous_journal_ttl() {
        let config = ChromeConfig {
            request_journal_ttl_s: 120, // 120_000ms >> 60_000ms required
            ..Default::default()
        };
        config
            .validate()
            .expect("generous journal TTL should satisfy invariant");
    }

    #[test]
    fn zero_socket_timeout_rejected() {
        let config = ChromeConfig {
            socket_timeout_ms: 0,
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("zero socket timeout should be rejected");
        assert!(
            matches!(
                err,
                ChromeConfigError::InvalidValue {
                    field: "socket_timeout_ms",
                    ..
                }
            ),
            "expected InvalidValue for socket_timeout_ms, got: {err}"
        );
    }

    #[test]
    fn zero_journal_ttl_rejected() {
        let config = ChromeConfig {
            request_journal_ttl_s: 0,
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("zero journal TTL should be rejected");
        assert!(
            matches!(
                err,
                ChromeConfigError::InvalidValue {
                    field: "request_journal_ttl_s",
                    ..
                }
            ),
            "expected InvalidValue for request_journal_ttl_s, got: {err}"
        );
    }

    #[test]
    fn zero_max_reconnect_still_valid() {
        // With 0 reconnects: (0+1)*5_000 = 5_000. Min = 30_000 + 5_000 + 10_000 = 45_000.
        // Journal = 60_000 >= 45_000 ✓
        let config = ChromeConfig {
            max_reconnect_attempts: 0,
            ..Default::default()
        };
        config
            .validate()
            .expect("zero reconnects should still be valid with default journal");
    }

    // -----------------------------------------------------------------------
    // Error display tests
    // -----------------------------------------------------------------------

    #[test]
    fn coupling_invariant_error_display_is_informative() {
        let err = ChromeConfigError::CouplingInvariantViolation {
            journal_ttl_ms: 30_000,
            min_required_ms: 60_000,
            lease_ttl_ms: 30_000,
            reconnect_window_ms: 20_000,
        };
        let msg = err.to_string();
        assert!(msg.contains("coupling invariant"));
        assert!(msg.contains("30000"));
        assert!(msg.contains("60000"));
    }

    // -----------------------------------------------------------------------
    // Retryable semantics tests
    // -----------------------------------------------------------------------

    #[test]
    fn retryable_codes() {
        assert!(is_retryable(ProtocolErrorCode::ChromeBridgeDisconnected));
        assert!(is_retryable(ProtocolErrorCode::ChromeBridgeTimeout));
        assert!(is_retryable(ProtocolErrorCode::ScreenshotFailed));
    }

    #[test]
    fn non_retryable_codes() {
        assert!(!is_retryable(ProtocolErrorCode::ChromeNotFound));
        assert!(!is_retryable(ProtocolErrorCode::ExtensionNotInstalled));
        assert!(!is_retryable(ProtocolErrorCode::ChromeBridgeAuthFailed));
        assert!(!is_retryable(ProtocolErrorCode::ChromeBridgeBusy));
        assert!(!is_retryable(
            ProtocolErrorCode::ChromeBridgeProtocolMismatch
        ));
        assert!(!is_retryable(ProtocolErrorCode::TabNotFound));
        assert!(!is_retryable(ProtocolErrorCode::ElementNotFound));
        assert!(!is_retryable(ProtocolErrorCode::NavigationFailed));
        assert!(!is_retryable(ProtocolErrorCode::JavascriptError));
        assert!(!is_retryable(ProtocolErrorCode::ObserverTabClosed));
        assert!(!is_retryable(ProtocolErrorCode::ObserverLimitReached));
    }

    #[test]
    fn execution_indeterminate_is_never_retryable() {
        assert!(
            !is_retryable(ProtocolErrorCode::ChromeBridgeExecutionIndeterminate),
            "EXECUTION_INDETERMINATE must be fail-closed (non-retryable)"
        );
    }

    // -----------------------------------------------------------------------
    // Error-to-ToolOutput conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn browser_error_to_tool_output_basic() {
        let output =
            browser_error_to_tool_output(ProtocolErrorCode::TabNotFound, "Tab 42 not found", false);
        assert!(output.is_error);
        match &output.content[0] {
            ContentBlock::Text(tc) => {
                assert!(tc.text.contains("TAB_NOT_FOUND"));
                assert!(tc.text.contains("Tab 42 not found"));
            }
            other => panic!("expected Text, got {other:?}"),
        }
        let details = output.details.unwrap();
        assert_eq!(details["error_code"], "TAB_NOT_FOUND");
        assert_eq!(details["retryable"], false);
    }

    #[test]
    fn browser_error_to_tool_output_retryable() {
        let output = browser_error_to_tool_output(
            ProtocolErrorCode::ChromeBridgeTimeout,
            "Connection timed out",
            true,
        );
        assert!(output.is_error);
        let details = output.details.unwrap();
        assert_eq!(details["retryable"], true);
    }

    // -----------------------------------------------------------------------
    // Error code display roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn all_error_codes_have_display() {
        let codes = [
            ProtocolErrorCode::ChromeNotFound,
            ProtocolErrorCode::ExtensionNotInstalled,
            ProtocolErrorCode::ChromeBridgeDisconnected,
            ProtocolErrorCode::ChromeBridgeAuthFailed,
            ProtocolErrorCode::ChromeBridgeBusy,
            ProtocolErrorCode::ChromeBridgeProtocolMismatch,
            ProtocolErrorCode::ChromeBridgeTimeout,
            ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
            ProtocolErrorCode::TabNotFound,
            ProtocolErrorCode::ElementNotFound,
            ProtocolErrorCode::NavigationFailed,
            ProtocolErrorCode::ScreenshotFailed,
            ProtocolErrorCode::JavascriptError,
            ProtocolErrorCode::ObserverTabClosed,
            ProtocolErrorCode::ObserverLimitReached,
        ];
        for code in &codes {
            let display = error_code_display(*code);
            assert!(
                !display.is_empty(),
                "display must not be empty for {code:?}"
            );
            assert!(
                display.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "display must be SCREAMING_SNAKE_CASE: {display}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn config_serialization_roundtrip() {
        let config = ChromeConfig::default();
        let json = serde_json::to_value(&config).expect("serialize");
        let deserialized: ChromeConfig = serde_json::from_value(json).expect("deserialize");
        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.socket_timeout_ms, deserialized.socket_timeout_ms);
        assert_eq!(
            config.max_reconnect_attempts,
            deserialized.max_reconnect_attempts
        );
    }

    // -----------------------------------------------------------------------
    // VoiceConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn voice_config_defaults_disabled() {
        // VS1: voice defaults to disabled
        let voice = VoiceConfig::default();
        assert!(!voice.enabled, "VS1: voice must default to disabled");
        assert_eq!(voice.stt_timeout_s, 5);
        assert!((voice.tts_rate - 1.0).abs() < f64::EPSILON);
        assert!((voice.tts_pitch - 1.0).abs() < f64::EPSILON);
        assert!(voice.tts_voice_name.is_none());
    }

    #[test]
    fn chrome_config_contains_voice_section() {
        let config = ChromeConfig::default();
        assert!(
            !config.voice.enabled,
            "voice must be disabled by default in ChromeConfig"
        );
    }

    #[test]
    fn voice_config_serialization_roundtrip() {
        let voice = VoiceConfig {
            enabled: true,
            stt_timeout_s: 10,
            tts_rate: 1.5,
            tts_pitch: 0.8,
            tts_voice_name: Some("Samantha".to_string()),
        };
        let json = serde_json::to_value(&voice).expect("serialize");
        let deserialized: VoiceConfig = serde_json::from_value(json).expect("deserialize");
        assert!(deserialized.enabled);
        assert_eq!(deserialized.stt_timeout_s, 10);
        assert!((deserialized.tts_rate - 1.5).abs() < f64::EPSILON);
        assert!((deserialized.tts_pitch - 0.8).abs() < f64::EPSILON);
        assert_eq!(deserialized.tts_voice_name.as_deref(), Some("Samantha"));
    }

    #[test]
    fn voice_config_absent_key_uses_defaults() {
        // Absent "voice" key in chrome config JSON should yield defaults
        let json = serde_json::json!({
            "enabled": true,
            "socket_timeout_ms": 5000
        });
        let config: ChromeConfig = serde_json::from_value(json).expect("parse");
        assert!(!config.voice.enabled, "absent voice key should default to disabled");
        assert_eq!(config.voice.stt_timeout_s, DEFAULT_STT_TIMEOUT_S);
    }

    #[test]
    fn voice_config_partial_json_fills_defaults() {
        let json = serde_json::json!({
            "enabled": true
        });
        let voice: VoiceConfig = serde_json::from_value(json).expect("parse");
        assert!(voice.enabled);
        assert_eq!(voice.stt_timeout_s, DEFAULT_STT_TIMEOUT_S);
        assert!((voice.tts_rate - DEFAULT_TTS_RATE).abs() < f64::EPSILON);
        assert!(voice.tts_voice_name.is_none());
    }

    #[test]
    fn chrome_config_with_voice_section_parses() {
        let json = serde_json::json!({
            "enabled": true,
            "voice": {
                "enabled": true,
                "stt_timeout_s": 8,
                "tts_voice_name": "Alex"
            }
        });
        let config: ChromeConfig = serde_json::from_value(json).expect("parse");
        assert!(config.enabled);
        assert!(config.voice.enabled);
        assert_eq!(config.voice.stt_timeout_s, 8);
        assert_eq!(config.voice.tts_voice_name.as_deref(), Some("Alex"));
    }
}
