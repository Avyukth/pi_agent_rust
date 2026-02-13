use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoringReport {
    pub schema: String,
    pub generated_at: String,
    pub as_of: String,
    pub summary: ScoringSummary,
    pub items: Vec<ScoredCandidate>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoringSummary {
    pub histogram: Vec<ScoreHistogramBucket>,
    pub top_overall: Vec<RankedEntry>,
    pub top_by_source_tier: BTreeMap<String, Vec<RankedEntry>>,
    pub manual_overrides: Vec<ManualOverrideEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreHistogramBucket {
    pub range: String,
    pub count: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RankedEntry {
    pub id: String,
    pub score: u32,
    pub tier: String,
    pub rank: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualOverrideEntry {
    pub id: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateInput {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub source_tier: Option<String>,
    #[serde(default)]
    pub signals: Signals,
    #[serde(default)]
    pub tags: Tags,
    #[serde(default)]
    pub recency: Recency,
    #[serde(default)]
    pub compat: Compatibility,
    #[serde(default)]
    pub license: LicenseInfo,
    #[serde(default)]
    pub gates: Gates,
    #[serde(default)]
    pub risk: RiskInfo,
    #[serde(default)]
    pub manual_override: Option<ManualOverride>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Signals {
    #[serde(default)]
    pub official_listing: Option<bool>,
    #[serde(default)]
    pub pi_mono_example: Option<bool>,
    #[serde(default)]
    pub badlogic_gist: Option<bool>,
    #[serde(default)]
    pub github_stars: Option<u64>,
    #[serde(default)]
    pub github_forks: Option<u64>,
    #[serde(default)]
    pub npm_downloads_month: Option<u64>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub marketplace: Option<MarketplaceSignals>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarketplaceSignals {
    #[serde(default)]
    pub rank: Option<u32>,
    #[serde(default)]
    pub installs_month: Option<u64>,
    #[serde(default)]
    pub featured: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tags {
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub interaction: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recency {
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Compatibility {
    #[serde(default)]
    pub status: Option<CompatStatus>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub required_shims: Vec<String>,
    #[serde(default)]
    pub adjustment: Option<i8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatStatus {
    Unmodified,
    RequiresShims,
    RuntimeGap,
    Blocked,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseInfo {
    #[serde(default)]
    pub spdx: Option<String>,
    #[serde(default)]
    pub redistribution: Option<Redistribution>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Redistribution {
    Ok,
    Restricted,
    Exclude,
    Unknown,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Gates {
    #[serde(default)]
    pub provenance_pinned: Option<bool>,
    #[serde(default)]
    pub deterministic: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskInfo {
    #[serde(default)]
    pub level: Option<RiskLevel>,
    #[serde(default)]
    pub penalty: Option<u8>,
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Moderate,
    High,
    Critical,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualOverride {
    pub reason: String,
    #[serde(default)]
    pub tier: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoredCandidate {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_tier: Option<String>,
    pub score: ScoreBreakdown,
    pub tier: String,
    pub rank: u32,
    pub gates: GateStatus,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub missing_signals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manual_override: Option<ManualOverride>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreBreakdown {
    pub popularity: u32,
    pub adoption: u32,
    pub coverage: u32,
    pub activity: u32,
    pub compatibility: u32,
    pub risk_penalty: u32,
    pub base_total: u32,
    pub final_total: u32,
    pub components: ScoreComponents,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScoreComponents {
    pub popularity: PopularityComponents,
    pub adoption: AdoptionComponents,
    pub coverage: CoverageComponents,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PopularityComponents {
    pub official_visibility: u32,
    pub github_stars: u32,
    pub marketplace_visibility: u32,
    pub references: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdoptionComponents {
    pub npm_downloads: u32,
    pub marketplace_installs: u32,
    pub forks: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CoverageComponents {
    pub runtime_tier: u32,
    pub interaction: u32,
    pub hostcalls: u32,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GateStatus {
    pub provenance_pinned: bool,
    pub license_ok: bool,
    pub deterministic: bool,
    pub unmodified: bool,
    pub passes: bool,
}

pub fn score_candidates(
    inputs: &[CandidateInput],
    as_of: DateTime<Utc>,
    generated_at: DateTime<Utc>,
    top_n: usize,
) -> ScoringReport {
    let mut scored = inputs
        .iter()
        .map(|candidate| score_candidate(candidate, as_of))
        .collect::<Vec<_>>();

    scored.sort_by(|left, right| compare_scored(right, left));
    for (idx, item) in scored.iter_mut().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        {
            item.rank = (idx + 1) as u32;
        }
    }

    let summary = build_summary(&scored, top_n);

    ScoringReport {
        schema: "pi.ext.scoring.v1".to_string(),
        generated_at: generated_at.to_rfc3339(),
        as_of: as_of.to_rfc3339(),
        summary,
        items: scored,
    }
}

fn compare_scored(left: &ScoredCandidate, right: &ScoredCandidate) -> std::cmp::Ordering {
    left.score
        .final_total
        .cmp(&right.score.final_total)
        .then_with(|| left.score.coverage.cmp(&right.score.coverage))
        .then_with(|| left.score.popularity.cmp(&right.score.popularity))
        .then_with(|| left.score.activity.cmp(&right.score.activity))
        .then_with(|| left.id.cmp(&right.id))
}

fn score_candidate(candidate: &CandidateInput, as_of: DateTime<Utc>) -> ScoredCandidate {
    let mut missing = BTreeSet::new();
    let (popularity, popularity_components) = score_popularity(&candidate.signals, &mut missing);
    let (adoption, adoption_components) = score_adoption(&candidate.signals, &mut missing);
    let (coverage, coverage_components) = score_coverage(&candidate.tags);
    let activity = score_activity(&candidate.recency, as_of, &mut missing);
    let compatibility = score_compatibility(&candidate.compat);
    let risk_penalty = score_risk(&candidate.risk);
    let base_total = popularity + adoption + coverage + activity + compatibility;
    let final_total = base_total.saturating_sub(risk_penalty);
    let gates = compute_gates(candidate);
    let tier = compute_tier(candidate, &gates, final_total);
    let missing_signals = missing.into_iter().collect::<Vec<_>>();
    let components = ScoreComponents {
        popularity: popularity_components,
        adoption: adoption_components,
        coverage: coverage_components,
    };
    let score = ScoreBreakdown {
        popularity,
        adoption,
        coverage,
        activity,
        compatibility,
        risk_penalty,
        base_total,
        final_total,
        components,
    };
    let manual_override = candidate.manual_override.clone();
    ScoredCandidate {
        id: candidate.id.clone(),
        name: candidate.name.clone(),
        source_tier: candidate.source_tier.clone(),
        score,
        tier,
        rank: 0,
        gates,
        missing_signals,
        manual_override,
    }
}

fn score_popularity(
    signals: &Signals,
    missing: &mut BTreeSet<String>,
) -> (u32, PopularityComponents) {
    let official_visibility = score_official_visibility(signals, missing);
    let github_stars = score_github_stars(signals, missing);
    let marketplace_visibility = score_marketplace_visibility(signals, missing);
    let references = score_references(signals);
    let total = (official_visibility + github_stars + marketplace_visibility + references).min(30);
    (
        total,
        PopularityComponents {
            official_visibility,
            github_stars,
            marketplace_visibility,
            references,
        },
    )
}

fn score_adoption(signals: &Signals, missing: &mut BTreeSet<String>) -> (u32, AdoptionComponents) {
    let npm_downloads = score_npm_downloads(signals, missing);
    let marketplace_installs = score_marketplace_installs(signals, missing);
    let forks = score_forks(signals, missing);
    let total = (npm_downloads + marketplace_installs + forks).min(15);
    (
        total,
        AdoptionComponents {
            npm_downloads,
            marketplace_installs,
            forks,
        },
    )
}

fn score_coverage(tags: &Tags) -> (u32, CoverageComponents) {
    let runtime_tier = score_runtime_tier(tags);
    let interaction = score_interaction(tags);
    let hostcalls = score_hostcalls(tags);
    let total = (runtime_tier + interaction + hostcalls).min(20);
    (
        total,
        CoverageComponents {
            runtime_tier,
            interaction,
            hostcalls,
        },
    )
}

fn score_official_visibility(signals: &Signals, missing: &mut BTreeSet<String>) -> u32 {
    let listing = signals.official_listing;
    let example = signals.pi_mono_example;
    let gist = signals.badlogic_gist;
    if listing.is_none() && example.is_none() && gist.is_none() {
        missing.insert("signals.official_visibility".to_string());
    }
    if listing.unwrap_or(false) {
        10
    } else if example.unwrap_or(false) {
        8
    } else if gist.unwrap_or(false) {
        6
    } else {
        0
    }
}

fn score_github_stars(signals: &Signals, missing: &mut BTreeSet<String>) -> u32 {
    let Some(stars) = signals.github_stars else {
        missing.insert("signals.github_stars".to_string());
        return 0;
    };
    // Log-linear: 10 * ln(1 + stars) / ln(1 + 5000), clamped to [0, 10]
    #[allow(clippy::cast_precision_loss)]
    let score = 10.0 * (stars as f64).ln_1p() / 5000_f64.ln_1p();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (score.round() as u32).min(10)
    }
}

fn score_marketplace_visibility(signals: &Signals, missing: &mut BTreeSet<String>) -> u32 {
    let Some(marketplace) = signals.marketplace.as_ref() else {
        missing.insert("signals.marketplace.rank".to_string());
        missing.insert("signals.marketplace.featured".to_string());
        return 0;
    };
    let rank_points = match marketplace.rank {
        Some(rank) if rank <= 10 => 6,
        Some(rank) if rank <= 50 => 4,
        Some(rank) if rank <= 100 => 2,
        Some(_) => 0,
        None => {
            missing.insert("signals.marketplace.rank".to_string());
            0
        }
    };
    let featured_points = if marketplace.featured.unwrap_or(false) {
        2
    } else {
        0
    };
    (rank_points + featured_points).min(6)
}

fn score_references(signals: &Signals) -> u32 {
    let unique = signals
        .references
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .collect::<BTreeSet<_>>()
        .len();
    match unique {
        n if n >= 10 => 4,
        n if n >= 5 => 3,
        n if n >= 2 => 2,
        _ => 0,
    }
}

fn score_npm_downloads(signals: &Signals, missing: &mut BTreeSet<String>) -> u32 {
    let Some(downloads) = signals.npm_downloads_month else {
        missing.insert("signals.npm_downloads_month".to_string());
        return 0;
    };
    // Log-linear: 8 * ln(1 + downloads) / ln(1 + 50_000), clamped to [0, 8]
    #[allow(clippy::cast_precision_loss)]
    let score = 8.0 * (downloads as f64).ln_1p() / 50_000_f64.ln_1p();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (score.round() as u32).min(8)
    }
}

fn score_marketplace_installs(signals: &Signals, missing: &mut BTreeSet<String>) -> u32 {
    let Some(marketplace) = signals.marketplace.as_ref() else {
        missing.insert("signals.marketplace.installs_month".to_string());
        return 0;
    };
    let Some(installs) = marketplace.installs_month else {
        missing.insert("signals.marketplace.installs_month".to_string());
        return 0;
    };
    match installs {
        d if d >= 10_000 => 5,
        d if d >= 2_000 => 4,
        d if d >= 500 => 2,
        d if d >= 100 => 1,
        _ => 0,
    }
}

fn score_forks(signals: &Signals, missing: &mut BTreeSet<String>) -> u32 {
    let Some(forks) = signals.github_forks else {
        missing.insert("signals.github_forks".to_string());
        return 0;
    };
    match forks {
        f if f >= 500 => 2,
        f if f >= 200 => 1,
        f if f >= 50 => 1,
        _ => 0,
    }
}

fn score_runtime_tier(tags: &Tags) -> u32 {
    let Some(runtime) = tags.runtime.as_deref() else {
        return 0;
    };
    match runtime {
        "pkg-with-deps" | "provider-ext" => 6,
        "multi-file" => 4,
        "legacy-js" => 2,
        _ => 0,
    }
}

fn score_interaction(tags: &Tags) -> u32 {
    let mut score = 0;
    if tags.interaction.iter().any(|tag| tag == "provider") {
        score += 3;
    }
    if tags.interaction.iter().any(|tag| tag == "ui_integration") {
        score += 2;
    }
    if tags.interaction.iter().any(|tag| tag == "event_hook") {
        score += 2;
    }
    if tags.interaction.iter().any(|tag| tag == "slash_command") {
        score += 1;
    }
    if tags.interaction.iter().any(|tag| tag == "tool_only") {
        score += 1;
    }
    score.min(8)
}

fn score_hostcalls(tags: &Tags) -> u32 {
    let mut score = 0;
    if tags.capabilities.iter().any(|cap| cap == "exec") {
        score += 2;
    }
    if tags.capabilities.iter().any(|cap| cap == "http") {
        score += 2;
    }
    if tags
        .capabilities
        .iter()
        .any(|cap| matches!(cap.as_str(), "read" | "write" | "edit"))
    {
        score += 1;
    }
    if tags.capabilities.iter().any(|cap| cap == "ui") {
        score += 1;
    }
    if tags.capabilities.iter().any(|cap| cap == "session") {
        score += 1;
    }
    score.min(6)
}

fn score_activity(recency: &Recency, as_of: DateTime<Utc>, missing: &mut BTreeSet<String>) -> u32 {
    let Some(updated_at) = recency.updated_at.as_deref() else {
        missing.insert("recency.updated_at".to_string());
        return 0;
    };
    let Ok(parsed) = DateTime::parse_from_rfc3339(updated_at) else {
        missing.insert("recency.updated_at".to_string());
        return 0;
    };
    let updated_at = parsed.with_timezone(&Utc);
    #[allow(clippy::cast_precision_loss)]
    let days = (as_of - updated_at).num_days().max(0) as f64;
    // Exponential decay: 15 * exp(-ln(2) * days / half_life), half_life = 180 days
    let half_life = 180.0_f64;
    let score = 15.0 * (-std::f64::consts::LN_2 * days / half_life).exp();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (score.round() as u32).min(15)
    }
}

fn score_compatibility(compat: &Compatibility) -> u32 {
    let base = match compat.status.unwrap_or_default() {
        CompatStatus::Unmodified => 20,
        CompatStatus::RequiresShims => 15,
        CompatStatus::RuntimeGap => 10,
        CompatStatus::Blocked | CompatStatus::Unknown => 0,
    };
    let adjustment = compat.adjustment.unwrap_or(0);
    let adjusted = base + i32::from(adjustment);
    #[allow(clippy::cast_sign_loss)]
    {
        adjusted.clamp(0, 20) as u32
    }
}

fn score_risk(risk: &RiskInfo) -> u32 {
    if let Some(penalty) = risk.penalty {
        return u32::from(penalty.min(15));
    }
    match risk.level {
        Some(RiskLevel::Low) | None => 0,
        Some(RiskLevel::Moderate) => 5,
        Some(RiskLevel::High) => 10,
        Some(RiskLevel::Critical) => 15,
    }
}

fn compute_gates(candidate: &CandidateInput) -> GateStatus {
    let provenance_pinned = candidate.gates.provenance_pinned.unwrap_or(false);
    let deterministic = candidate.gates.deterministic.unwrap_or(false);
    let license_ok = matches!(
        candidate.license.redistribution,
        Some(Redistribution::Ok | Redistribution::Restricted)
    );
    let unmodified = matches!(
        candidate.compat.status.unwrap_or_default(),
        CompatStatus::Unmodified | CompatStatus::RequiresShims | CompatStatus::RuntimeGap
    );
    let passes = provenance_pinned && deterministic && license_ok && unmodified;
    GateStatus {
        provenance_pinned,
        license_ok,
        deterministic,
        unmodified,
        passes,
    }
}

fn compute_tier(candidate: &CandidateInput, gates: &GateStatus, final_total: u32) -> String {
    let is_official = candidate.signals.pi_mono_example.unwrap_or(false)
        || matches!(candidate.source_tier.as_deref(), Some("official-pi-mono"));
    if is_official {
        if let Some(override_tier) = candidate
            .manual_override
            .as_ref()
            .and_then(|override_spec| override_spec.tier.clone())
        {
            return override_tier;
        }
        return "tier-0".to_string();
    }
    if let Some(override_tier) = candidate
        .manual_override
        .as_ref()
        .and_then(|override_spec| override_spec.tier.clone())
    {
        return override_tier;
    }
    if !gates.passes {
        return "excluded".to_string();
    }
    if final_total >= 70 {
        return "tier-1".to_string();
    }
    if final_total >= 50 {
        return "tier-2".to_string();
    }
    "excluded".to_string()
}

fn build_summary(items: &[ScoredCandidate], top_n: usize) -> ScoringSummary {
    let histogram = build_histogram(items);
    let top_overall = items
        .iter()
        .take(top_n)
        .map(|item| RankedEntry {
            id: item.id.clone(),
            score: item.score.final_total,
            tier: item.tier.clone(),
            rank: item.rank,
        })
        .collect::<Vec<_>>();

    let mut by_tier = BTreeMap::<String, Vec<&ScoredCandidate>>::new();
    for item in items {
        let tier = item
            .source_tier
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        by_tier.entry(tier).or_default().push(item);
    }

    let mut top_by_source_tier = BTreeMap::new();
    for (tier, entries) in by_tier {
        let mut top_entries = entries
            .into_iter()
            .take(top_n)
            .map(|item| RankedEntry {
                id: item.id.clone(),
                score: item.score.final_total,
                tier: item.tier.clone(),
                rank: item.rank,
            })
            .collect::<Vec<_>>();
        top_entries.sort_by_key(|entry| entry.rank);
        top_by_source_tier.insert(tier, top_entries);
    }

    let manual_overrides = items
        .iter()
        .filter_map(|item| {
            item.manual_override
                .as_ref()
                .map(|override_spec| ManualOverrideEntry {
                    id: item.id.clone(),
                    reason: override_spec.reason.clone(),
                    tier: override_spec.tier.clone(),
                })
        })
        .collect::<Vec<_>>();

    ScoringSummary {
        histogram,
        top_overall,
        top_by_source_tier,
        manual_overrides,
    }
}

fn build_histogram(items: &[ScoredCandidate]) -> Vec<ScoreHistogramBucket> {
    let mut buckets = BTreeMap::<u32, u32>::new();
    for item in items {
        let bucket = item.score.final_total / 10;
        *buckets.entry(bucket).or_insert(0) += 1;
    }
    (0..=10)
        .map(|bucket| {
            let start = bucket * 10;
            let end = if bucket == 10 { 100 } else { start + 9 };
            ScoreHistogramBucket {
                range: format!("{start}-{end}"),
                count: buckets.get(&bucket).copied().unwrap_or(0),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn empty_signals() -> Signals {
        Signals::default()
    }

    fn empty_tags() -> Tags {
        Tags::default()
    }

    fn minimal_candidate(id: &str) -> CandidateInput {
        CandidateInput {
            id: id.to_string(),
            name: None,
            source_tier: None,
            signals: Signals::default(),
            tags: Tags::default(),
            recency: Recency::default(),
            compat: Compatibility::default(),
            license: LicenseInfo::default(),
            gates: Gates::default(),
            risk: RiskInfo::default(),
            manual_override: None,
        }
    }

    // =========================================================================
    // score_github_stars
    // =========================================================================

    #[test]
    fn github_stars_none_returns_zero_and_records_missing() {
        let mut missing = BTreeSet::new();
        let signals = empty_signals();
        assert_eq!(score_github_stars(&signals, &mut missing), 0);
        assert!(missing.contains("signals.github_stars"));
    }

    #[test]
    fn github_stars_tiers() {
        let cases = [
            (0, 0),
            (49, 5),
            (50, 5),
            (199, 6),
            (200, 6),
            (499, 7),
            (500, 7),
            (999, 8),
            (1_000, 8),
            (1_999, 9),
            (2_000, 9),
            (4_999, 10),
            (5_000, 10),
            (100_000, 10),
        ];
        for (stars, expected) in cases {
            let mut missing = BTreeSet::new();
            let signals = Signals {
                github_stars: Some(stars),
                ..Default::default()
            };
            assert_eq!(
                score_github_stars(&signals, &mut missing),
                expected,
                "stars={stars}"
            );
        }
    }

    // =========================================================================
    // score_npm_downloads
    // =========================================================================

    #[test]
    fn npm_downloads_none_returns_zero() {
        let mut missing = BTreeSet::new();
        assert_eq!(score_npm_downloads(&empty_signals(), &mut missing), 0);
        assert!(missing.contains("signals.npm_downloads_month"));
    }

    #[test]
    fn npm_downloads_tiers() {
        let cases = [
            (0, 0),
            (499, 5),
            (500, 5),
            (2_000, 6),
            (10_000, 7),
            (50_000, 8),
        ];
        for (dl, expected) in cases {
            let mut missing = BTreeSet::new();
            let signals = Signals {
                npm_downloads_month: Some(dl),
                ..Default::default()
            };
            assert_eq!(
                score_npm_downloads(&signals, &mut missing),
                expected,
                "downloads={dl}"
            );
        }
    }

    // =========================================================================
    // score_marketplace_installs
    // =========================================================================

    #[test]
    fn marketplace_installs_no_marketplace_records_missing() {
        let mut missing = BTreeSet::new();
        assert_eq!(
            score_marketplace_installs(&empty_signals(), &mut missing),
            0
        );
        assert!(missing.contains("signals.marketplace.installs_month"));
    }

    #[test]
    fn marketplace_installs_none_records_missing() {
        let mut missing = BTreeSet::new();
        let signals = Signals {
            marketplace: Some(MarketplaceSignals::default()),
            ..Default::default()
        };
        assert_eq!(score_marketplace_installs(&signals, &mut missing), 0);
        assert!(missing.contains("signals.marketplace.installs_month"));
    }

    #[test]
    fn marketplace_installs_tiers() {
        let cases = [(0, 0), (99, 0), (100, 1), (500, 2), (2_000, 4), (10_000, 5)];
        for (installs, expected) in cases {
            let mut missing = BTreeSet::new();
            let signals = Signals {
                marketplace: Some(MarketplaceSignals {
                    installs_month: Some(installs),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert_eq!(
                score_marketplace_installs(&signals, &mut missing),
                expected,
                "installs={installs}"
            );
        }
    }

    // =========================================================================
    // score_forks
    // =========================================================================

    #[test]
    fn forks_none_returns_zero() {
        let mut missing = BTreeSet::new();
        assert_eq!(score_forks(&empty_signals(), &mut missing), 0);
        assert!(missing.contains("signals.github_forks"));
    }

    #[test]
    fn forks_tiers() {
        let cases = [(0, 0), (49, 0), (50, 1), (200, 1), (500, 2), (10_000, 2)];
        for (f, expected) in cases {
            let mut missing = BTreeSet::new();
            let signals = Signals {
                github_forks: Some(f),
                ..Default::default()
            };
            assert_eq!(score_forks(&signals, &mut missing), expected, "forks={f}");
        }
    }

    // =========================================================================
    // score_references
    // =========================================================================

    #[test]
    fn references_empty() {
        let signals = empty_signals();
        assert_eq!(score_references(&signals), 0);
    }

    #[test]
    fn references_deduplicates_trimmed() {
        let signals = Signals {
            references: vec![" ref1 ".to_string(), "ref1".to_string(), "ref2".to_string()],
            ..Default::default()
        };
        assert_eq!(score_references(&signals), 2); // 2 unique => score 2
    }

    #[test]
    fn references_tiers() {
        let make = |n: usize| -> Signals {
            Signals {
                references: (0..n).map(|i| format!("ref-{i}")).collect(),
                ..Default::default()
            }
        };
        assert_eq!(score_references(&make(1)), 0);
        assert_eq!(score_references(&make(2)), 2);
        assert_eq!(score_references(&make(5)), 3);
        assert_eq!(score_references(&make(10)), 4);
        assert_eq!(score_references(&make(20)), 4);
    }

    #[test]
    fn references_ignores_empty_and_whitespace() {
        let signals = Signals {
            references: vec![String::new(), "  ".to_string(), "real".to_string()],
            ..Default::default()
        };
        assert_eq!(score_references(&signals), 0); // 1 unique => 0
    }

    // =========================================================================
    // score_official_visibility
    // =========================================================================

    #[test]
    fn official_visibility_all_none_records_missing() {
        let mut missing = BTreeSet::new();
        assert_eq!(score_official_visibility(&empty_signals(), &mut missing), 0);
        assert!(missing.contains("signals.official_visibility"));
    }

    #[test]
    fn official_visibility_listing_highest() {
        let mut missing = BTreeSet::new();
        let signals = Signals {
            official_listing: Some(true),
            pi_mono_example: Some(true),
            badlogic_gist: Some(true),
            ..Default::default()
        };
        assert_eq!(score_official_visibility(&signals, &mut missing), 10);
    }

    #[test]
    fn official_visibility_example_mid() {
        let mut missing = BTreeSet::new();
        let signals = Signals {
            pi_mono_example: Some(true),
            ..Default::default()
        };
        assert_eq!(score_official_visibility(&signals, &mut missing), 8);
    }

    #[test]
    fn official_visibility_gist_lowest() {
        let mut missing = BTreeSet::new();
        let signals = Signals {
            badlogic_gist: Some(true),
            ..Default::default()
        };
        assert_eq!(score_official_visibility(&signals, &mut missing), 6);
    }

    // =========================================================================
    // score_marketplace_visibility
    // =========================================================================

    #[test]
    fn marketplace_visibility_no_marketplace() {
        let mut missing = BTreeSet::new();
        assert_eq!(
            score_marketplace_visibility(&empty_signals(), &mut missing),
            0
        );
        assert!(missing.contains("signals.marketplace.rank"));
        assert!(missing.contains("signals.marketplace.featured"));
    }

    #[test]
    fn marketplace_visibility_rank_tiers() {
        let cases = [
            (5, 6),
            (10, 6),
            (30, 4),
            (50, 4),
            (80, 2),
            (100, 2),
            (200, 0),
        ];
        for (rank, expected) in cases {
            let mut missing = BTreeSet::new();
            let signals = Signals {
                marketplace: Some(MarketplaceSignals {
                    rank: Some(rank),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert_eq!(
                score_marketplace_visibility(&signals, &mut missing),
                expected,
                "rank={rank}"
            );
        }
    }

    #[test]
    fn marketplace_visibility_featured_adds_2_capped_at_6() {
        let mut missing = BTreeSet::new();
        let signals = Signals {
            marketplace: Some(MarketplaceSignals {
                rank: Some(5),
                featured: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        // rank=5 -> 6, featured -> +2, capped at 6
        assert_eq!(score_marketplace_visibility(&signals, &mut missing), 6);
    }

    // =========================================================================
    // score_runtime_tier
    // =========================================================================

    #[test]
    fn runtime_tier_values() {
        let cases = [
            (None, 0),
            (Some("pkg-with-deps"), 6),
            (Some("provider-ext"), 6),
            (Some("multi-file"), 4),
            (Some("legacy-js"), 2),
            (Some("unknown-tier"), 0),
        ];
        for (runtime, expected) in cases {
            let tags = Tags {
                runtime: runtime.map(String::from),
                ..Default::default()
            };
            assert_eq!(score_runtime_tier(&tags), expected, "runtime={runtime:?}");
        }
    }

    // =========================================================================
    // score_interaction
    // =========================================================================

    #[test]
    fn interaction_empty() {
        assert_eq!(score_interaction(&empty_tags()), 0);
    }

    #[test]
    fn interaction_all_tags() {
        let tags = Tags {
            interaction: vec![
                "provider".to_string(),
                "ui_integration".to_string(),
                "event_hook".to_string(),
                "slash_command".to_string(),
                "tool_only".to_string(),
            ],
            ..Default::default()
        };
        // 3+2+2+1+1 = 9, capped at 8
        assert_eq!(score_interaction(&tags), 8);
    }

    #[test]
    fn interaction_single_provider() {
        let tags = Tags {
            interaction: vec!["provider".to_string()],
            ..Default::default()
        };
        assert_eq!(score_interaction(&tags), 3);
    }

    // =========================================================================
    // score_hostcalls
    // =========================================================================

    #[test]
    fn hostcalls_empty() {
        assert_eq!(score_hostcalls(&empty_tags()), 0);
    }

    #[test]
    fn hostcalls_all_capabilities() {
        let tags = Tags {
            capabilities: vec![
                "exec".to_string(),
                "http".to_string(),
                "read".to_string(),
                "ui".to_string(),
                "session".to_string(),
            ],
            ..Default::default()
        };
        // 2+2+1+1+1 = 7, capped at 6
        assert_eq!(score_hostcalls(&tags), 6);
    }

    #[test]
    fn hostcalls_write_and_edit_count_as_one() {
        let tags = Tags {
            capabilities: vec!["write".to_string(), "edit".to_string()],
            ..Default::default()
        };
        // write matches the read|write|edit arm => 1, edit also matches => still 1
        assert_eq!(score_hostcalls(&tags), 1);
    }

    // =========================================================================
    // score_activity
    // =========================================================================

    #[test]
    fn activity_none_returns_zero() {
        let mut missing = BTreeSet::new();
        let as_of = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(score_activity(&Recency::default(), as_of, &mut missing), 0);
        assert!(missing.contains("recency.updated_at"));
    }

    #[test]
    fn activity_recent_gets_max() {
        let mut missing = BTreeSet::new();
        let as_of = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
        let recency = Recency {
            updated_at: Some("2026-01-15T00:00:00Z".to_string()),
        };
        assert_eq!(score_activity(&recency, as_of, &mut missing), 14);
    }

    #[test]
    fn activity_tiers() {
        let as_of = Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).unwrap();
        let cases = [
            ("2026-06-15T00:00:00Z", 14), // 16 days
            ("2026-04-15T00:00:00Z", 11), // ~77 days
            ("2026-02-01T00:00:00Z", 8),  // ~150 days
            ("2025-10-01T00:00:00Z", 5),  // ~273 days
            ("2025-01-01T00:00:00Z", 2),  // ~547 days
            ("2023-01-01T00:00:00Z", 0),  // >730 days
        ];
        for (date, expected) in cases {
            let mut missing = BTreeSet::new();
            let recency = Recency {
                updated_at: Some(date.to_string()),
            };
            assert_eq!(
                score_activity(&recency, as_of, &mut missing),
                expected,
                "date={date}"
            );
        }
    }

    #[test]
    fn activity_invalid_date_returns_zero() {
        let mut missing = BTreeSet::new();
        let as_of = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let recency = Recency {
            updated_at: Some("not-a-date".to_string()),
        };
        assert_eq!(score_activity(&recency, as_of, &mut missing), 0);
        assert!(missing.contains("recency.updated_at"));
    }

    // =========================================================================
    // score_compatibility
    // =========================================================================

    #[test]
    fn compatibility_unmodified_is_max() {
        let compat = Compatibility {
            status: Some(CompatStatus::Unmodified),
            ..Default::default()
        };
        assert_eq!(score_compatibility(&compat), 20);
    }

    #[test]
    fn compatibility_requires_shims() {
        let compat = Compatibility {
            status: Some(CompatStatus::RequiresShims),
            ..Default::default()
        };
        assert_eq!(score_compatibility(&compat), 15);
    }

    #[test]
    fn compatibility_runtime_gap() {
        let compat = Compatibility {
            status: Some(CompatStatus::RuntimeGap),
            ..Default::default()
        };
        assert_eq!(score_compatibility(&compat), 10);
    }

    #[test]
    fn compatibility_blocked_is_zero() {
        let compat = Compatibility {
            status: Some(CompatStatus::Blocked),
            ..Default::default()
        };
        assert_eq!(score_compatibility(&compat), 0);
    }

    #[test]
    fn compatibility_adjustment_positive() {
        let compat = Compatibility {
            status: Some(CompatStatus::RequiresShims),
            adjustment: Some(3),
            ..Default::default()
        };
        assert_eq!(score_compatibility(&compat), 18);
    }

    #[test]
    fn compatibility_adjustment_negative_clamped() {
        let compat = Compatibility {
            status: Some(CompatStatus::RuntimeGap),
            adjustment: Some(-15),
            ..Default::default()
        };
        // 10 + (-15) = -5, clamped to 0
        assert_eq!(score_compatibility(&compat), 0);
    }

    #[test]
    fn compatibility_adjustment_capped_at_20() {
        let compat = Compatibility {
            status: Some(CompatStatus::Unmodified),
            adjustment: Some(10),
            ..Default::default()
        };
        // 20 + 10 = 30, capped at 20
        assert_eq!(score_compatibility(&compat), 20);
    }

    // =========================================================================
    // score_risk
    // =========================================================================

    #[test]
    fn risk_none_is_zero() {
        assert_eq!(score_risk(&RiskInfo::default()), 0);
    }

    #[test]
    fn risk_penalty_override() {
        let risk = RiskInfo {
            penalty: Some(7),
            level: Some(RiskLevel::Critical),
            ..Default::default()
        };
        // Explicit penalty overrides level
        assert_eq!(score_risk(&risk), 7);
    }

    #[test]
    fn risk_penalty_capped_at_15() {
        let risk = RiskInfo {
            penalty: Some(50),
            ..Default::default()
        };
        assert_eq!(score_risk(&risk), 15);
    }

    #[test]
    fn risk_level_tiers() {
        let cases = [
            (RiskLevel::Low, 0),
            (RiskLevel::Moderate, 5),
            (RiskLevel::High, 10),
            (RiskLevel::Critical, 15),
        ];
        for (level, expected) in cases {
            let risk = RiskInfo {
                level: Some(level),
                ..Default::default()
            };
            assert_eq!(score_risk(&risk), expected, "level={level:?}");
        }
    }

    // =========================================================================
    // compute_gates
    // =========================================================================

    #[test]
    fn gates_all_false_by_default() {
        let candidate = minimal_candidate("test");
        let gates = compute_gates(&candidate);
        assert!(!gates.provenance_pinned);
        assert!(!gates.license_ok);
        assert!(!gates.deterministic);
        assert!(!gates.unmodified); // Unknown status -> not unmodified
        assert!(!gates.passes);
    }

    #[test]
    fn gates_all_pass() {
        let mut candidate = minimal_candidate("test");
        candidate.gates.provenance_pinned = Some(true);
        candidate.gates.deterministic = Some(true);
        candidate.license.redistribution = Some(Redistribution::Ok);
        candidate.compat.status = Some(CompatStatus::Unmodified);
        let gates = compute_gates(&candidate);
        assert!(gates.passes);
    }

    #[test]
    fn gates_license_restricted_counts_as_ok() {
        let mut candidate = minimal_candidate("test");
        candidate.gates.provenance_pinned = Some(true);
        candidate.gates.deterministic = Some(true);
        candidate.license.redistribution = Some(Redistribution::Restricted);
        candidate.compat.status = Some(CompatStatus::RequiresShims);
        let gates = compute_gates(&candidate);
        assert!(gates.license_ok);
        assert!(gates.passes);
    }

    #[test]
    fn gates_license_exclude_fails() {
        let mut candidate = minimal_candidate("test");
        candidate.license.redistribution = Some(Redistribution::Exclude);
        let gates = compute_gates(&candidate);
        assert!(!gates.license_ok);
    }

    #[test]
    fn gates_unmodified_includes_requires_shims_and_runtime_gap() {
        for status in [
            CompatStatus::Unmodified,
            CompatStatus::RequiresShims,
            CompatStatus::RuntimeGap,
        ] {
            let mut candidate = minimal_candidate("test");
            candidate.compat.status = Some(status);
            let gates = compute_gates(&candidate);
            assert!(gates.unmodified, "status={status:?} should be unmodified");
        }
    }

    // =========================================================================
    // compute_tier
    // =========================================================================

    #[test]
    fn tier_official_is_tier_0() {
        let mut candidate = minimal_candidate("test");
        candidate.signals.pi_mono_example = Some(true);
        let gates = compute_gates(&candidate);
        assert_eq!(compute_tier(&candidate, &gates, 0), "tier-0");
    }

    #[test]
    fn tier_official_source_tier_is_tier_0() {
        let mut candidate = minimal_candidate("test");
        candidate.source_tier = Some("official-pi-mono".to_string());
        let gates = compute_gates(&candidate);
        assert_eq!(compute_tier(&candidate, &gates, 0), "tier-0");
    }

    #[test]
    fn tier_manual_override_on_official() {
        let mut candidate = minimal_candidate("test");
        candidate.signals.pi_mono_example = Some(true);
        candidate.manual_override = Some(ManualOverride {
            reason: "special".to_string(),
            tier: Some("tier-1".to_string()),
        });
        let gates = compute_gates(&candidate);
        assert_eq!(compute_tier(&candidate, &gates, 0), "tier-1");
    }

    #[test]
    fn tier_excluded_when_gates_fail() {
        let candidate = minimal_candidate("test");
        let gates = compute_gates(&candidate); // gates fail
        assert_eq!(compute_tier(&candidate, &gates, 100), "excluded");
    }

    #[test]
    fn tier_1_at_70_plus() {
        let mut candidate = minimal_candidate("test");
        candidate.gates.provenance_pinned = Some(true);
        candidate.gates.deterministic = Some(true);
        candidate.license.redistribution = Some(Redistribution::Ok);
        candidate.compat.status = Some(CompatStatus::Unmodified);
        let gates = compute_gates(&candidate);
        assert_eq!(compute_tier(&candidate, &gates, 70), "tier-1");
        assert_eq!(compute_tier(&candidate, &gates, 100), "tier-1");
    }

    #[test]
    fn tier_2_at_50_to_69() {
        let mut candidate = minimal_candidate("test");
        candidate.gates.provenance_pinned = Some(true);
        candidate.gates.deterministic = Some(true);
        candidate.license.redistribution = Some(Redistribution::Ok);
        candidate.compat.status = Some(CompatStatus::Unmodified);
        let gates = compute_gates(&candidate);
        assert_eq!(compute_tier(&candidate, &gates, 50), "tier-2");
        assert_eq!(compute_tier(&candidate, &gates, 69), "tier-2");
    }

    #[test]
    fn tier_excluded_below_50() {
        let mut candidate = minimal_candidate("test");
        candidate.gates.provenance_pinned = Some(true);
        candidate.gates.deterministic = Some(true);
        candidate.license.redistribution = Some(Redistribution::Ok);
        candidate.compat.status = Some(CompatStatus::Unmodified);
        let gates = compute_gates(&candidate);
        assert_eq!(compute_tier(&candidate, &gates, 49), "excluded");
    }

    // =========================================================================
    // compare_scored
    // =========================================================================

    #[test]
    fn compare_scored_by_final_total() {
        let as_of = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut a = score_candidate(&minimal_candidate("a"), as_of);
        let mut b = score_candidate(&minimal_candidate("b"), as_of);
        a.score.final_total = 80;
        b.score.final_total = 60;
        assert_eq!(compare_scored(&a, &b), std::cmp::Ordering::Greater);
    }

    #[test]
    fn compare_scored_tiebreak_by_id() {
        let as_of = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let a = score_candidate(&minimal_candidate("alpha"), as_of);
        let b = score_candidate(&minimal_candidate("beta"), as_of);
        // Same scores, tiebreak by id
        assert_eq!(
            compare_scored(&a, &b),
            std::cmp::Ordering::Less // "alpha" < "beta"
        );
    }

    // =========================================================================
    // build_histogram
    // =========================================================================

    #[test]
    fn histogram_empty() {
        let histogram = build_histogram(&[]);
        assert_eq!(histogram.len(), 11);
        for bucket in &histogram {
            assert_eq!(bucket.count, 0);
        }
    }

    #[test]
    fn histogram_ranges_correct() {
        let histogram = build_histogram(&[]);
        assert_eq!(histogram[0].range, "0-9");
        assert_eq!(histogram[5].range, "50-59");
        assert_eq!(histogram[10].range, "100-100");
    }

    #[test]
    fn histogram_counts_correctly() {
        let as_of = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut items: Vec<ScoredCandidate> = (0..3)
            .map(|i| score_candidate(&minimal_candidate(&format!("c{i}")), as_of))
            .collect();
        items[0].score.final_total = 15; // bucket 1 (10-19)
        items[1].score.final_total = 15; // bucket 1 (10-19)
        items[2].score.final_total = 75; // bucket 7 (70-79)
        let histogram = build_histogram(&items);
        assert_eq!(histogram[1].count, 2);
        assert_eq!(histogram[7].count, 1);
    }

    // =========================================================================
    // score_popularity (composite)
    // =========================================================================

    #[test]
    fn popularity_capped_at_30() {
        let mut missing = BTreeSet::new();
        let signals = Signals {
            official_listing: Some(true), // 10
            github_stars: Some(10_000),   // 10
            marketplace: Some(MarketplaceSignals {
                rank: Some(1),        // 6
                featured: Some(true), // +2 (capped at 6)
                ..Default::default()
            }),
            references: (0..20).map(|i| format!("ref-{i}")).collect(), // 4
            ..Default::default()
        };
        let (total, _) = score_popularity(&signals, &mut missing);
        assert_eq!(total, 30); // capped
    }

    // =========================================================================
    // score_adoption (composite)
    // =========================================================================

    #[test]
    fn adoption_capped_at_15() {
        let mut missing = BTreeSet::new();
        let signals = Signals {
            npm_downloads_month: Some(100_000), // 8
            github_forks: Some(1_000),          // 2
            marketplace: Some(MarketplaceSignals {
                installs_month: Some(50_000), // 5
                ..Default::default()
            }),
            ..Default::default()
        };
        let (total, _) = score_adoption(&signals, &mut missing);
        assert_eq!(total, 15); // capped
    }

    // =========================================================================
    // score_coverage (composite)
    // =========================================================================

    #[test]
    fn coverage_capped_at_20() {
        let tags = Tags {
            runtime: Some("pkg-with-deps".to_string()), // 6
            interaction: vec![
                "provider".to_string(),
                "ui_integration".to_string(),
                "event_hook".to_string(),
                "slash_command".to_string(),
                "tool_only".to_string(),
            ], // 8
            capabilities: vec![
                "exec".to_string(),
                "http".to_string(),
                "read".to_string(),
                "ui".to_string(),
                "session".to_string(),
            ], // 6
        };
        let (total, _) = score_coverage(&tags);
        assert_eq!(total, 20); // capped
    }

    // =========================================================================
    // score_candidates (integration)
    // =========================================================================

    #[test]
    fn score_candidates_ranks_correctly() {
        let as_of = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let generated_at = as_of;
        let mut high = minimal_candidate("high");
        high.signals.github_stars = Some(10_000);
        high.signals.pi_mono_example = Some(true);
        high.compat.status = Some(CompatStatus::Unmodified);
        high.recency.updated_at = Some("2025-12-15T00:00:00Z".to_string());

        let low = minimal_candidate("low");

        let report = score_candidates(&[high, low], as_of, generated_at, 5);
        assert_eq!(report.schema, "pi.ext.scoring.v1");
        assert_eq!(report.items.len(), 2);
        assert_eq!(report.items[0].rank, 1);
        assert_eq!(report.items[1].rank, 2);
        assert!(report.items[0].score.final_total >= report.items[1].score.final_total);
    }

    #[test]
    fn score_candidates_empty_input() {
        let as_of = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let report = score_candidates(&[], as_of, as_of, 5);
        assert!(report.items.is_empty());
        assert!(report.summary.top_overall.is_empty());
    }

    // =========================================================================
    // Serde round-trips
    // =========================================================================

    #[test]
    fn compat_status_serde_roundtrip() {
        for status in [
            CompatStatus::Unmodified,
            CompatStatus::RequiresShims,
            CompatStatus::RuntimeGap,
            CompatStatus::Blocked,
            CompatStatus::Unknown,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: CompatStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn redistribution_serde_roundtrip() {
        for red in [
            Redistribution::Ok,
            Redistribution::Restricted,
            Redistribution::Exclude,
            Redistribution::Unknown,
        ] {
            let json = serde_json::to_string(&red).unwrap();
            let back: Redistribution = serde_json::from_str(&json).unwrap();
            assert_eq!(back, red);
        }
    }

    #[test]
    fn risk_level_serde_roundtrip() {
        for level in [
            RiskLevel::Low,
            RiskLevel::Moderate,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(back, level);
        }
    }

    #[test]
    fn scoring_report_serde_roundtrip() {
        let as_of = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut candidate = minimal_candidate("test-ext");
        candidate.signals.github_stars = Some(500);
        candidate.compat.status = Some(CompatStatus::Unmodified);
        let report = score_candidates(&[candidate], as_of, as_of, 5);
        let json = serde_json::to_string(&report).unwrap();
        let back: ScoringReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.items[0].id, "test-ext");
    }

    // =========================================================================
    // Missing signals tracking
    // =========================================================================

    #[test]
    fn missing_signals_collected_for_empty_candidate() {
        let as_of = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let candidate = minimal_candidate("bare");
        let scored = score_candidate(&candidate, as_of);
        assert!(!scored.missing_signals.is_empty());
        assert!(
            scored
                .missing_signals
                .contains(&"signals.github_stars".to_string())
        );
        assert!(
            scored
                .missing_signals
                .contains(&"signals.github_forks".to_string())
        );
        assert!(
            scored
                .missing_signals
                .contains(&"recency.updated_at".to_string())
        );
    }
}
