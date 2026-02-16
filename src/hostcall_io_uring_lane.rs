//! Deterministic io_uring lane policy for hostcall dispatch.
//!
//! This module intentionally models policy decisions only. It does not perform
//! syscalls or ring operations directly; integration code can consume the
//! decisions and wire them into runtime-specific execution paths.

use serde::{Deserialize, Serialize};

/// Dispatch lane selected for a hostcall attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostcallDispatchLane {
    Fast,
    IoUring,
    Compat,
}

impl HostcallDispatchLane {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::IoUring => "io_uring",
            Self::Compat => "compat",
        }
    }
}

/// Optional signal indicating whether a hostcall is likely IO-dominant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostcallIoHint {
    Unknown,
    IoHeavy,
    CpuBound,
}

impl HostcallIoHint {
    #[must_use]
    pub const fn is_io_heavy(self) -> bool {
        matches!(self, Self::IoHeavy)
    }
}

/// Normalized capability classes used by lane policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostcallCapabilityClass {
    Filesystem,
    Network,
    Execution,
    Session,
    Events,
    Environment,
    Tool,
    Ui,
    Telemetry,
    Unknown,
}

impl HostcallCapabilityClass {
    #[must_use]
    pub fn from_capability(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "read" | "write" | "filesystem" | "fs" => Self::Filesystem,
            "http" | "network" => Self::Network,
            "exec" | "execution" => Self::Execution,
            "session" => Self::Session,
            "events" => Self::Events,
            "env" | "environment" => Self::Environment,
            "tool" => Self::Tool,
            "ui" => Self::Ui,
            "log" | "telemetry" => Self::Telemetry,
            _ => Self::Unknown,
        }
    }
}

/// Explicit fallback reason when io_uring is not selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoUringFallbackReason {
    CompatKillSwitch,
    IoUringDisabled,
    IoUringUnavailable,
    MissingIoHint,
    UnsupportedCapability,
    QueueDepthBudgetExceeded,
}

impl IoUringFallbackReason {
    #[must_use]
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::CompatKillSwitch => "forced_compat_kill_switch",
            Self::IoUringDisabled => "io_uring_disabled",
            Self::IoUringUnavailable => "io_uring_unavailable",
            Self::MissingIoHint => "io_hint_missing",
            Self::UnsupportedCapability => "io_uring_capability_not_supported",
            Self::QueueDepthBudgetExceeded => "io_uring_queue_depth_budget_exceeded",
        }
    }
}

/// Runtime-tunable policy knobs for io_uring lane selection.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoUringLanePolicyConfig {
    pub enabled: bool,
    pub ring_available: bool,
    pub max_queue_depth: usize,
    pub allow_filesystem: bool,
    pub allow_network: bool,
}

impl IoUringLanePolicyConfig {
    /// Conservative profile suitable for production defaults.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            enabled: false,
            ring_available: false,
            max_queue_depth: 256,
            allow_filesystem: true,
            allow_network: true,
        }
    }

    #[must_use]
    pub const fn allow_for_capability(self, capability: HostcallCapabilityClass) -> bool {
        match capability {
            HostcallCapabilityClass::Filesystem => self.allow_filesystem,
            HostcallCapabilityClass::Network => self.allow_network,
            _ => false,
        }
    }
}

impl Default for IoUringLanePolicyConfig {
    fn default() -> Self {
        Self::conservative()
    }
}

/// Inputs consumed by [`decide_io_uring_lane`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoUringLaneDecisionInput {
    pub capability: HostcallCapabilityClass,
    pub io_hint: HostcallIoHint,
    pub queue_depth: usize,
    pub force_compat_lane: bool,
}

/// Deterministic lane decision output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoUringLaneDecision {
    pub lane: HostcallDispatchLane,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<IoUringFallbackReason>,
}

impl IoUringLaneDecision {
    #[must_use]
    pub const fn io_uring() -> Self {
        Self {
            lane: HostcallDispatchLane::IoUring,
            fallback_reason: None,
        }
    }

    #[must_use]
    pub const fn compat(reason: IoUringFallbackReason) -> Self {
        Self {
            lane: HostcallDispatchLane::Compat,
            fallback_reason: Some(reason),
        }
    }

    #[must_use]
    pub const fn fast(reason: IoUringFallbackReason) -> Self {
        Self {
            lane: HostcallDispatchLane::Fast,
            fallback_reason: Some(reason),
        }
    }

    #[must_use]
    pub fn fallback_code(self) -> Option<&'static str> {
        self.fallback_reason.map(IoUringFallbackReason::as_code)
    }
}

/// Decide whether the hostcall should run via the io_uring lane.
///
/// Decision ordering is intentionally strict and deterministic:
/// 1) explicit compatibility kill-switch
/// 2) policy enabled flag
/// 3) ring availability
/// 4) IO-heavy hint presence
/// 5) capability allowlist
/// 6) queue depth budget
#[must_use]
pub const fn decide_io_uring_lane(
    config: IoUringLanePolicyConfig,
    input: IoUringLaneDecisionInput,
) -> IoUringLaneDecision {
    if input.force_compat_lane {
        return IoUringLaneDecision::compat(IoUringFallbackReason::CompatKillSwitch);
    }
    if !config.enabled {
        return IoUringLaneDecision::fast(IoUringFallbackReason::IoUringDisabled);
    }
    if !config.ring_available {
        return IoUringLaneDecision::fast(IoUringFallbackReason::IoUringUnavailable);
    }
    if !input.io_hint.is_io_heavy() {
        return IoUringLaneDecision::fast(IoUringFallbackReason::MissingIoHint);
    }
    if !config.allow_for_capability(input.capability) {
        return IoUringLaneDecision::fast(IoUringFallbackReason::UnsupportedCapability);
    }
    if input.queue_depth >= config.max_queue_depth {
        return IoUringLaneDecision::fast(IoUringFallbackReason::QueueDepthBudgetExceeded);
    }
    IoUringLaneDecision::io_uring()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> IoUringLanePolicyConfig {
        IoUringLanePolicyConfig {
            enabled: true,
            ring_available: true,
            max_queue_depth: 8,
            allow_filesystem: true,
            allow_network: true,
        }
    }

    #[test]
    fn capability_aliases_map_to_expected_classes() {
        assert_eq!(
            HostcallCapabilityClass::from_capability("read"),
            HostcallCapabilityClass::Filesystem
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("http"),
            HostcallCapabilityClass::Network
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("session"),
            HostcallCapabilityClass::Session
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("unknown-cap"),
            HostcallCapabilityClass::Unknown
        );
    }

    #[test]
    fn selects_io_uring_for_io_heavy_allowed_capability_with_budget_headroom() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Network,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 3,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::IoUring);
        assert!(decision.fallback_reason.is_none());
    }

    #[test]
    fn kill_switch_forces_compat_lane() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Filesystem,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 0,
                force_compat_lane: true,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Compat);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::CompatKillSwitch)
        );
        assert_eq!(decision.fallback_code(), Some("forced_compat_kill_switch"));
    }

    #[test]
    fn disabled_policy_falls_back_to_fast_lane() {
        let mut config = enabled_config();
        config.enabled = false;
        let decision = decide_io_uring_lane(
            config,
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Network,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 0,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::IoUringDisabled)
        );
    }

    #[test]
    fn unavailable_ring_falls_back_to_fast_lane() {
        let mut config = enabled_config();
        config.ring_available = false;
        let decision = decide_io_uring_lane(
            config,
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Network,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 0,
                force_compat_lane: false,
            },
        );
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::IoUringUnavailable)
        );
    }

    #[test]
    fn non_io_hint_falls_back_to_fast_lane() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Network,
                io_hint: HostcallIoHint::CpuBound,
                queue_depth: 0,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::MissingIoHint)
        );
    }

    #[test]
    fn unsupported_capability_falls_back_to_fast_lane() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Session,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 0,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::UnsupportedCapability)
        );
    }

    #[test]
    fn queue_depth_budget_exceeded_falls_back_to_fast_lane() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Filesystem,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 8,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::QueueDepthBudgetExceeded)
        );
    }
}
