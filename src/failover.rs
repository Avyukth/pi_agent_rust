//! Cross-model failover machinery (bd-cv653.3.2).
//!
//! When a provider throws a classified transient failure (429/quota/overload
//! after the same-provider retry budget), the next entry of the configured
//! fallback chain continues the turn; the primary is restored after a
//! cooldown. Round-robin credentials rotate multiple keys per provider with
//! session affinity and per-credential backoff. Path-scoped model sets pin
//! model lists per repository root.
//!
//! Classification is deliberately conservative: authentication failures
//! (401/403/invalid key) NEVER trigger failover — they are loud user errors,
//! not provider capacity problems.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Failure classes relevant to failover decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverClass {
    /// Rate limit / quota exhaustion (429, insufficient_quota, …).
    Quota,
    /// Provider overloaded / capacity (529, service_unavailable, overloaded).
    Overload,
    /// Other transient failures after the retry budget is spent.
    Transient,
}

/// Classify an error text for failover. `None` = never fail over (auth and
/// other loud errors). Ordering matters: auth patterns are checked FIRST so
/// a "401 ... quota" message never fails over.
pub fn classify_failover(error_text: &str) -> Option<FailoverClass> {
    const AUTH_PATTERNS: &[&str] = &[
        "401",
        "403",
        "unauthorized",
        "forbidden",
        "invalid api key",
        "invalid_api_key",
        "incorrect api key",
        "authentication failed",
        "permission denied",
        "expired token",
        "missing api key",
    ];
    const QUOTA_PATTERNS: &[&str] = &[
        "429",
        "rate limit",
        "rate_limit",
        "too many requests",
        "quota",
        "insufficient_quota",
        "billing",
        "spending limit",
    ];
    const OVERLOAD_PATTERNS: &[&str] = &[
        "529",
        "503",
        "502",
        "500",
        "overloaded",
        "service unavailable",
        "service_unavailable",
        "capacity",
        "temporarily unavailable",
        "server error",
        "internal error",
    ];

    let text = error_text.to_ascii_lowercase();

    // Auth: loud, user-actionable, never a failover trigger.
    if AUTH_PATTERNS.iter().any(|p| text.contains(p)) {
        return None;
    }

    if QUOTA_PATTERNS.iter().any(|p| text.contains(p)) {
        return Some(FailoverClass::Quota);
    }

    if OVERLOAD_PATTERNS.iter().any(|p| text.contains(p)) {
        return Some(FailoverClass::Overload);
    }

    if crate::error::is_retryable_error(&text.to_ascii_lowercase(), None, None) {
        return Some(FailoverClass::Transient);
    }
    None
}

/// One resolved chain: the specs the controller walks on failure.
#[derive(Debug, Clone)]
pub struct FailoverChain {
    /// Ordered `provider/model` specs after the primary.
    pub entries: Vec<String>,
}

/// Resolve the chain for a role name or an exact `provider/model` spec from
/// `retry.fallbackChains`. Role keys take precedence over exact model specs.
pub fn chain_for<S: std::hash::BuildHasher>(
    chains: &HashMap<String, Vec<String>, S>,
    role: &str,
    provider: &str,
    model_id: &str,
) -> Option<FailoverChain> {
    if let Some(entries) = chains.get(role)
        && !entries.is_empty()
    {
        return Some(FailoverChain {
            entries: entries.clone(),
        });
    }
    let full = format!("{provider}/{model_id}");
    for (key, entries) in chains {
        if key.eq_ignore_ascii_case(&full) && !entries.is_empty() {
            return Some(FailoverChain {
                entries: entries.clone(),
            });
        }
    }
    None
}

/// Cooldown FSM for the primary after a failover.
///
/// The primary stays quiesced until the cooldown elapses; a successful
/// failover-chain turn records the failure time; a fresh `should_use_primary`
/// check restores the primary afterwards.
#[derive(Debug, Clone)]
pub struct CooldownTracker {
    failed_at: Option<Instant>,
    cooldown: Duration,
}

impl CooldownTracker {
    #[must_use]
    pub const fn new(cooldown_secs: u64) -> Self {
        Self {
            failed_at: None,
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// Record that the primary failed at `now`.
    pub const fn record_primary_failure(&mut self, now: Instant) {
        self.failed_at = Some(now);
    }

    /// Whether the primary may be used again at `now`.
    #[must_use]
    pub fn should_use_primary(&self, now: Instant) -> bool {
        self.failed_at
            .is_none_or(|failed| now.duration_since(failed) >= self.cooldown)
    }

    /// Clear the tracker (primary succeeded).
    pub const fn reset(&mut self) {
        self.failed_at = None;
    }

    /// Deterministic test view of the failure timestamp.
    #[cfg(test)]
    pub(crate) fn failed_at(&self) -> Option<Instant> {
        self.failed_at
    }
}

/// Round-robin credential ring (bd-cv653.3.2): multiple keys per provider,
/// stable session affinity by hash, per-credential exponential backoff on 429.
#[derive(Debug, Clone)]
pub struct CredentialRing {
    keys: Vec<String>,
    backoff_until: Vec<Option<Instant>>,
    /// Stable affinity index derived from the session hash at construction.
    affinity: usize,
}

impl CredentialRing {
    /// Build a ring from a non-empty key list with session-affinity index.
    #[must_use]
    pub fn new(keys: Vec<String>, session_hash: u64) -> Option<Self> {
        if keys.is_empty() {
            return None;
        }
        // Hash-first modulo keeps the affinity index within pointer width on
        // every target (no u64→usize truncation).
        let affinity = usize::try_from(session_hash % keys.len() as u64).unwrap_or(0);
        let backoff_until = vec![None; keys.len()];
        Some(Self {
            keys,
            backoff_until,
            affinity,
        })
    }

    /// The current usable key at `now`: the affinity key when healthy, else
    /// the next key without an active backoff; `None` when all are cooling.
    #[must_use]
    pub fn current_key(&self, now: Instant) -> Option<&str> {
        let usable = |idx: usize| self.backoff_until[idx].is_none_or(|until| now >= until);
        if usable(self.affinity) {
            return Some(self.keys[self.affinity].as_str());
        }
        (0..self.keys.len())
            .find(|&idx| usable(idx))
            .map(|idx| self.keys[idx].as_str())
    }

    /// Report a 429 for `key`: exponential backoff `base * 2^strikes` clamped
    /// to `max`. Returns the new backoff expiry for observability.
    pub fn report_rate_limited(
        &mut self,
        key: &str,
        now: Instant,
        base: Duration,
        max: Duration,
    ) -> Option<Instant> {
        let idx = self.keys.iter().position(|k| k == key)?;
        let previous = self.backoff_until[idx];
        let strikes = previous.filter(|until| now < *until).map_or(0, |_| 1);
        let delay = (base * 2_u32.pow(strikes)).min(max);
        let expiry = now + delay;
        self.backoff_until[idx] = Some(expiry);
        Some(expiry)
    }

    /// All keys currently cooling (observability/testing).
    #[must_use]
    pub(crate) fn cooling_count(&self, now: Instant) -> usize {
        self.backoff_until
            .iter()
            .filter(|until| until.is_some_and(|u| now < u))
            .count()
    }

    /// Masked key fingerprints for diagnostics (never logs raw secrets).
    #[must_use]
    pub(crate) fn key_fingerprints(&self) -> Vec<String> {
        self.keys
            .iter()
            .map(|key| {
                let len = key.len();
                let tail: String = key
                    .chars()
                    .rev()
                    .take(2)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                format!("len{len}/..{tail}")
            })
            .collect()
    }
}

/// Stable per-session hash for credential affinity (FNV-1a over the id).
#[must_use]
pub fn session_affinity_hash(session_id: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for byte in session_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Path-scope resolution (bd-cv653.3.2): given cwd and the configured
/// overrides, return the winning override (longest matching prefix), if any.
pub fn best_scope_override<'a>(
    overrides: &'a [crate::config::ModelScopeOverride],
    cwd: &std::path::Path,
) -> Option<&'a crate::config::ModelScopeOverride> {
    overrides
        .iter()
        .filter(|ov| {
            let scope = expand_tilde(&ov.path);
            cwd.starts_with(&scope)
        })
        .max_by_key(|ov| ov.path.len())
}

fn expand_tilde(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return std::path::PathBuf::from(home).join(rest);
    }
    std::path::PathBuf::from(path)
}

/// Whether a provider id is disabled by the effective configuration for cwd.
pub fn provider_is_disabled(
    disabled: &[String],
    scope: Option<&crate::config::ModelScopeOverride>,
    provider: &str,
) -> bool {
    let in_list = |list: &[String]| {
        list.iter()
            .any(|entry| crate::provider_metadata::provider_ids_match(entry.trim(), provider))
    };
    if let Some(scope_list) = scope.and_then(|ov| ov.disabled_providers.as_deref())
        && in_list(scope_list)
    {
        return true;
    }
    in_list(disabled)
}

/// Cursor over a fallback chain that yields only the specs worth considering.
///
/// The live model and any spec already walked earlier in the same chain are
/// skipped: installing either emits a phantom `FailoverStart`/`FailoverEnd`
/// pair and spends a unit of `max_failovers_per_turn` on a no-op (bd-oqo03.1).
/// The walk is bounded by the chain, never by that per-turn cap — bounding the
/// cursor by the cap let malformed, uncredentialed, unconstructible, current
/// or duplicate entries consume the budget and hide a later valid entry.
///
/// Print mode and the RPC server each had their own copy of exactly this
/// cursor arithmetic, and both off-by-one bugs in the family (bd-oqo03,
/// bd-oqo03.1) had to be found and fixed twice. One definition now, so the
/// interactive surfaces can walk a chain without inheriting a third copy
/// (bd-u2qv4).
///
/// [`Self::position`] is the resume point for the NEXT turn: one past the
/// entry last yielded. Callers persist it only once a swap actually commits.
pub struct FailoverWalk<'a> {
    entries: &'a [String],
    position: usize,
    current_provider: &'a str,
    current_model: &'a str,
}

impl<'a> FailoverWalk<'a> {
    /// Start (or resume, via `position`) a walk of `chain` while
    /// `current_provider`/`current_model` are live.
    #[must_use]
    pub const fn new(
        chain: &'a FailoverChain,
        position: usize,
        current_provider: &'a str,
        current_model: &'a str,
    ) -> Self {
        Self {
            entries: chain.entries.as_slice(),
            position,
            current_provider,
            current_model,
        }
    }

    /// The next candidate spec and the chain index it occupies, advancing past
    /// it. The index is captured BEFORE the advance: reporting the post-advance
    /// cursor as the chain index is off by one (bd-oqo03).
    pub fn next_spec(&mut self) -> Option<(usize, &'a str)> {
        while self.position < self.entries.len() {
            let index = self.position;
            let spec = self.entries[index].as_str();
            self.position += 1;
            let is_current = crate::provider_metadata::split_provider_model_spec(spec).is_some_and(
                |(provider, model_id)| {
                    crate::provider_metadata::provider_ids_match(self.current_provider, provider)
                        && self.current_model.eq_ignore_ascii_case(model_id)
                },
            );
            let is_duplicate = self.entries[..index]
                .iter()
                .any(|earlier| earlier.eq_ignore_ascii_case(spec));
            if is_current || is_duplicate {
                continue;
            }
            return Some((index, spec));
        }
        None
    }

    /// Where the next turn resumes: one past the entry last yielded.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }
}

/// Resolve one `provider/model` chain spec against the configured model list.
///
/// A well-formed pair that is simply not configured falls back to an ad-hoc
/// entry. `None` means the spec names nothing usable and the walk should move
/// on.
#[must_use]
pub fn resolve_chain_spec(
    spec: &str,
    available_models: &[crate::models::ModelEntry],
) -> Option<crate::models::ModelEntry> {
    let (provider, model_id) = crate::provider_metadata::split_provider_model_spec(spec)?;
    available_models
        .iter()
        .find(|entry| {
            crate::provider_metadata::provider_ids_match(&entry.model.provider, provider)
                && entry.model.id.eq_ignore_ascii_case(model_id)
        })
        .cloned()
        .or_else(|| crate::models::ad_hoc_model_entry(provider, model_id))
}

// ---------------------------------------------------------------------------
// Shared retry policy (bd-u2qv4)
//
// Print mode (`src/main.rs`) and the RPC server (`src/rpc.rs`) each grew their
// own copy of this policy, and the copies have already drifted. The functions
// below are the single definition both surfaces call, so a third consumer —
// the interactive stacks, which today have no provider retry or failover at
// all — can adopt the same policy instead of becoming a fourth copy.
//
// Everything here is pure: no I/O, no surface types, no session mutation.
// Whether to sleep, what to emit, and how to resume the turn stay with the
// caller, because those genuinely differ per surface.
// ---------------------------------------------------------------------------

/// Exponential backoff delay for same-provider retry `attempt` (1-based).
///
/// `attempt` 0 and 1 both yield `base_delay_ms`; each later attempt doubles,
/// capped at `max_delay_ms`. Saturating throughout so a large attempt count
/// clamps at the cap rather than overflowing.
#[must_use]
pub fn retry_delay_ms(base_delay_ms: u32, max_delay_ms: u32, attempt: u32) -> u32 {
    let base = u64::from(base_delay_ms);
    let max = u64::from(max_delay_ms);
    let shift = attempt.saturating_sub(1);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let delay = base.saturating_mul(multiplier).min(max);
    u32::try_from(delay).unwrap_or(u32::MAX)
}

/// Terminal marker check (bd-8188r): does this error text describe a
/// session-persistence failure?
///
/// Such a failure means provider or tool side effects may already have
/// happened while the durable record is missing or stale. Re-entering the
/// provider — retry, credential rotation, or model failover — could repeat
/// those effects, so callers must treat this as final regardless of what the
/// wrapped prose looks like.
///
/// `contains`, not `starts_with`: the flattened `Display` form embeds the
/// marker after `thiserror`'s own "Session error: " prefix. A false positive
/// merely refuses a retry, which is the safe direction.
#[must_use]
pub fn marks_session_persistence(error_text: &str) -> bool {
    error_text.contains(crate::error::Error::SESSION_PERSISTENCE_PREFIX)
}

/// Whether a completed turn that ended in [`StopReason::Error`] should be
/// retried against the same provider.
///
/// `context_window` is the active model's context window when the caller knows
/// it; supplying it lets [`crate::error::is_retryable_error`] recognise a
/// context overflow, which is never retryable. Print mode passed `None` here
/// while RPC supplied the real window, so the same overflow was retried on one
/// surface and refused on the other; callers that can resolve the window
/// should pass it.
#[must_use]
pub fn error_result_is_retryable(
    message: &crate::model::AssistantMessage,
    context_window: Option<u32>,
) -> bool {
    if !matches!(message.stop_reason, crate::model::StopReason::Error) {
        return false;
    }
    let error_text = message.error_message.as_deref().unwrap_or("Request error");
    // Session-persistence failures are never retryable, even when the wrapped
    // message contains transient-looking prose ("connection reset", "500"):
    // flattening loses the typed boundary, so the stable prefix is checked
    // before any text classification.
    if marks_session_persistence(error_text) {
        return false;
    }
    crate::error::is_retryable_error(error_text, Some(message.usage.input), context_window)
}

/// Whether a failed provider call reported through [`crate::error::Error`]
/// should be retried against the same provider.
///
/// Classifies from the TYPED error first — [`crate::error::Error::is_transient`]
/// walks the source chain for a transient `io::ErrorKind` (connection
/// reset/abort/EOF/broken pipe/timeout) without depending on flattened message
/// text — then falls back to text matching for prose-only errors
/// (pi_agent_rust#118). No usage or context window is available on this path
/// because no response was received.
#[must_use]
pub fn call_error_is_retryable(error: &crate::error::Error) -> bool {
    if error.is_session_persistence() {
        return false;
    }
    error.is_transient() || crate::error::is_retryable_error(&error.to_string(), None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn classify_quota_and_overload_failover() {
        assert_eq!(
            classify_failover("429 Too Many Requests: rate limit exceeded"),
            Some(FailoverClass::Quota)
        );
        assert_eq!(
            classify_failover("insufficient_quota: you exceeded your current quota"),
            Some(FailoverClass::Quota)
        );
        assert_eq!(
            classify_failover("529 the model is overloaded"),
            Some(FailoverClass::Overload)
        );
        assert_eq!(
            classify_failover("503 service unavailable"),
            Some(FailoverClass::Overload)
        );
    }

    #[test]
    fn classify_auth_never_fails_over() {
        assert_eq!(classify_failover("401 unauthorized: invalid api key"), None);
        assert_eq!(classify_failover("403 forbidden"), None);
        // Auth wins even when quota words appear in the same message.
        assert_eq!(classify_failover("401 unauthorized: quota exceeded"), None);
    }

    #[test]
    fn classify_other_errors_do_not_failover() {
        assert_eq!(classify_failover("the model produced invalid JSON"), None);
        assert_eq!(classify_failover("context window exceeded"), None);
    }

    #[test]
    fn chain_lookup_prefers_role_then_exact_model() {
        let mut chains = HashMap::new();
        chains.insert("default".to_string(), vec!["openai/gpt-5-mini".to_string()]);
        chains.insert(
            "anthropic/claude-opus-4-7".to_string(),
            vec!["google/gemini-3-pro".to_string()],
        );
        assert_eq!(
            chain_for(&chains, "default", "anthropic", "claude-opus-4-7")
                .unwrap()
                .entries,
            vec!["openai/gpt-5-mini".to_string()]
        );
        // Non-default role name that is not configured: falls to the exact model key.
        assert_eq!(
            chain_for(&chains, "task", "anthropic", "claude-opus-4-7")
                .unwrap()
                .entries,
            vec!["google/gemini-3-pro".to_string()]
        );
        // The "default" role key matches any model by design; an UNCONFIGURED
        // role + unconfigured exact model yields no chain.
        assert!(chain_for(&chains, "task", "openai", "gpt-5.5").is_none());
    }

    #[test]
    fn cooldown_blocks_primary_until_elapsed() {
        let start = Instant::now();
        let mut tracker = CooldownTracker::new(60);
        assert!(tracker.should_use_primary(start));
        tracker.record_primary_failure(start);
        assert!(!tracker.should_use_primary(start + Duration::from_secs(59)));
        assert!(tracker.should_use_primary(start + Duration::from_secs(60)));
        tracker.record_primary_failure(start);
        tracker.reset();
        assert!(tracker.should_use_primary(start));
    }

    #[test]
    fn credential_ring_affinity_and_backoff() {
        let start = Instant::now();
        let keys = vec!["k1".to_string(), "k2".to_string(), "k3".to_string()];
        let mut ring = CredentialRing::new(keys, session_affinity_hash("sess-1")).unwrap();
        let first = ring.current_key(start).unwrap().to_string();
        // Affinity is stable for the same session id.
        let ring2 = CredentialRing::new(
            vec!["k1".to_string(), "k2".to_string(), "k3".to_string()],
            session_affinity_hash("sess-1"),
        )
        .unwrap();
        assert_eq!(ring2.current_key(start).unwrap(), first);

        // Rate-limit the current key: rotation moves to another key.
        ring.report_rate_limited(
            &first,
            start,
            Duration::from_secs(1),
            Duration::from_secs(60),
        );
        let next = ring.current_key(start).unwrap().to_string();
        assert_ne!(next, first);
        assert_eq!(ring.cooling_count(start), 1);

        // Backoff expiry restores the original key.
        let later = start + Duration::from_secs(2);
        assert_eq!(ring.current_key(later).unwrap(), first);

        // Rate-limit every key: no usable key remains.
        ring.report_rate_limited(
            &first,
            later,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        ring.report_rate_limited(
            &next,
            later,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let third = ["k1", "k2", "k3"]
            .into_iter()
            .find(|k| k != &first && k != &next)
            .unwrap();
        ring.report_rate_limited(
            third,
            later,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        assert!(ring.current_key(later).is_none());
    }

    #[test]
    fn scope_override_longest_prefix_wins() {
        let overrides = vec![
            crate::config::ModelScopeOverride {
                path: "/repo".to_string(),
                enabled_models: None,
                disabled_providers: None,
            },
            crate::config::ModelScopeOverride {
                path: "/repo/a".to_string(),
                enabled_models: Some(vec!["openai/gpt-5.5".to_string()]),
                disabled_providers: None,
            },
        ];
        let winner = best_scope_override(&overrides, Path::new("/repo/a/sub")).unwrap();
        assert_eq!(winner.path, "/repo/a");
        assert!(best_scope_override(&overrides, Path::new("/elsewhere")).is_none());
    }

    #[test]
    fn provider_disable_checks_global_then_scope() {
        let disabled = vec!["anthropic".to_string()];
        assert!(provider_is_disabled(&disabled, None, "anthropic"));
        assert!(provider_is_disabled(&disabled, None, "ANTHROPIC")); // case-insensitive
        assert!(!provider_is_disabled(&disabled, None, "openai"));
        let scope = crate::config::ModelScopeOverride {
            path: "/repo".to_string(),
            enabled_models: None,
            disabled_providers: Some(vec!["openai".to_string()]),
        };
        assert!(provider_is_disabled(&disabled, Some(&scope), "openai"));
        assert!(provider_is_disabled(&disabled, Some(&scope), "anthropic"));
    }

    // -- shared chain walk (bd-u2qv4) --------------------------------------

    fn chain(specs: &[&str]) -> FailoverChain {
        FailoverChain {
            entries: specs.iter().map(|spec| (*spec).to_string()).collect(),
        }
    }

    #[test]
    fn the_walk_skips_the_live_model_and_earlier_duplicates() {
        let chain = chain(&[
            "anthropic/claude-x", // the live model: a no-op swap
            "openai/gpt-y",
            "OpenAI/GPT-Y", // duplicate of the previous, case-insensitively
            "google/gemini-z",
        ]);
        let mut walk = FailoverWalk::new(&chain, 0, "anthropic", "claude-x");
        assert_eq!(walk.next_spec(), Some((1, "openai/gpt-y")));
        assert_eq!(walk.next_spec(), Some((3, "google/gemini-z")));
        assert_eq!(walk.next_spec(), None);
        assert_eq!(walk.position(), 4);
    }

    #[test]
    fn the_yielded_index_is_the_entry_not_the_resume_point() {
        // bd-oqo03: reporting the post-advance cursor as the chain index is
        // off by one, and that index is what reaches the failover event.
        let chain = chain(&["openai/gpt-y", "google/gemini-z"]);
        let mut walk = FailoverWalk::new(&chain, 0, "anthropic", "claude-x");
        let (index, spec) = walk.next_spec().expect("first candidate");
        assert_eq!((index, spec), (0, "openai/gpt-y"));
        assert_eq!(
            walk.position(),
            1,
            "the resume point is one past the entry just yielded"
        );
    }

    #[test]
    fn a_resumed_walk_continues_past_the_persisted_position() {
        // bd-oqo03.1: `position` is durable across turns, so a per-turn cap of
        // one must still reach entry two on the next turn.
        let chain = chain(&["openai/gpt-y", "google/gemini-z"]);
        let mut walk = FailoverWalk::new(&chain, 1, "anthropic", "claude-x");
        assert_eq!(walk.next_spec(), Some((1, "google/gemini-z")));
        assert_eq!(walk.next_spec(), None);
    }

    #[test]
    fn a_malformed_spec_is_yielded_for_the_caller_to_reject() {
        // Resolution, credentials and provider construction stay with the
        // caller; the walk only decides what is worth looking at.
        let chain = chain(&["not-a-spec", "openai/gpt-y"]);
        let mut walk = FailoverWalk::new(&chain, 0, "anthropic", "claude-x");
        assert_eq!(walk.next_spec(), Some((0, "not-a-spec")));
        assert!(resolve_chain_spec("not-a-spec", &[]).is_none());
        assert_eq!(walk.next_spec(), Some((1, "openai/gpt-y")));
    }

    #[test]
    fn an_unconfigured_but_well_formed_spec_resolves_ad_hoc() {
        let resolved = resolve_chain_spec("openai/gpt-y", &[]);
        let entry = resolved.expect("a well-formed spec resolves even when unconfigured");
        assert!(crate::provider_metadata::provider_ids_match(
            &entry.model.provider,
            "openai"
        ));
        assert!(entry.model.id.eq_ignore_ascii_case("gpt-y"));
    }

    // -- shared retry policy (bd-u2qv4) ------------------------------------

    fn errored_message(
        error_message: Option<&str>,
        input_tokens: u64,
    ) -> crate::model::AssistantMessage {
        crate::model::AssistantMessage {
            content: Vec::new(),
            api: "test".to_string(),
            provider: "test".to_string(),
            model: "test".to_string(),
            usage: crate::model::Usage {
                input: input_tokens,
                ..crate::model::Usage::default()
            },
            stop_reason: crate::model::StopReason::Error,
            stop_details: None,
            error_message: error_message.map(str::to_string),
            timestamp: 0,
        }
    }

    #[test]
    fn retry_delay_doubles_from_base_and_caps() {
        assert_eq!(retry_delay_ms(500, 8_000, 0), 500);
        assert_eq!(retry_delay_ms(500, 8_000, 1), 500);
        assert_eq!(retry_delay_ms(500, 8_000, 2), 1_000);
        assert_eq!(retry_delay_ms(500, 8_000, 3), 2_000);
        assert_eq!(retry_delay_ms(500, 8_000, 4), 4_000);
        assert_eq!(retry_delay_ms(500, 8_000, 5), 8_000);
        // Saturates at the cap instead of overflowing the shift.
        assert_eq!(retry_delay_ms(500, 8_000, 30), 8_000);
        assert_eq!(retry_delay_ms(500, 8_000, u32::MAX), 8_000);
    }

    #[test]
    fn session_persistence_marker_is_recognized_after_a_display_prefix() {
        let flattened = format!(
            "Session error: {} could not write session",
            crate::error::Error::SESSION_PERSISTENCE_PREFIX
        );
        assert!(marks_session_persistence(&flattened));
        assert!(!marks_session_persistence("429 rate limit exceeded"));
    }

    #[test]
    fn only_errored_turns_are_retryable() {
        let mut ok = errored_message(None, 0);
        ok.stop_reason = crate::model::StopReason::Stop;
        assert!(!error_result_is_retryable(&ok, None));

        let mut aborted = errored_message(Some("connection reset by peer"), 0);
        aborted.stop_reason = crate::model::StopReason::Aborted;
        assert!(!error_result_is_retryable(&aborted, None));

        assert!(error_result_is_retryable(
            &errored_message(Some("connection reset by peer"), 0),
            None
        ));
    }

    #[test]
    fn a_session_persistence_turn_is_never_retryable_however_transient_it_reads() {
        // The prose alone would classify as retryable; the marker must win,
        // because repeating the turn could repeat side effects already made
        // against a session whose durable record is missing (bd-8188r).
        let text = format!(
            "{} connection reset by peer",
            crate::error::Error::SESSION_PERSISTENCE_PREFIX
        );
        assert!(crate::error::is_retryable_error(
            "connection reset by peer",
            None,
            None
        ));
        assert!(!error_result_is_retryable(
            &errored_message(Some(&text), 0),
            None
        ));
    }

    #[test]
    fn a_context_overflow_is_retryable_only_while_the_window_is_unknown() {
        // The drift this policy exists to remove: RPC supplied the active
        // model's context window here and print mode did not, so the same
        // overflow was refused on one surface and retried forever on the
        // other. The window is what makes the classification possible.
        let overflow = errored_message(Some("prompt is too long: 250000 tokens > 200000"), 250_000);
        assert!(!error_result_is_retryable(&overflow, Some(200_000)));
    }

    #[test]
    fn call_errors_classify_from_the_typed_error_before_its_prose() {
        let persistence = crate::error::Error::session_persistence("write failed");
        assert!(!call_error_is_retryable(&persistence));

        let transient = crate::error::Error::Api("503 service unavailable".to_string());
        assert!(call_error_is_retryable(&transient));

        let loud = crate::error::Error::Api("401 unauthorized: invalid api key".to_string());
        assert!(!call_error_is_retryable(&loud));
    }
}
