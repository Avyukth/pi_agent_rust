//! Model registry: built-in + models.json overrides.

use crate::auth::{AuthStorage, SapResolvedCredentials, resolve_sap_credentials};
use crate::error::Error;
use crate::provider::{Api, InputType, Model, ModelCost};
use crate::provider_metadata::{
    ProviderRoutingDefaults, canonical_provider_id, provider_routing_defaults,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ModelEntry {
    pub model: Model,
    pub api_key: Option<String>,
    pub headers: HashMap<String, String>,
    pub auth_header: bool,
    pub compat: Option<CompatConfig>,
    /// OAuth config for extension-registered providers that require browser-based auth.
    pub oauth_config: Option<OAuthConfig>,
}

impl ModelEntry {
    /// Whether this model supports xhigh thinking level.
    pub fn supports_xhigh(&self) -> bool {
        matches!(
            self.model.id.as_str(),
            "gpt-5.1-codex-max" | "gpt-5.2" | "gpt-5.2-codex"
        )
    }

    /// Clamp a requested thinking level to the model's capabilities.
    ///
    /// Non-reasoning models always return `Off`. Models without xhigh support
    /// downgrade `XHigh` to `High`. All other levels pass through unchanged.
    pub fn clamp_thinking_level(
        &self,
        thinking: crate::model::ThinkingLevel,
    ) -> crate::model::ThinkingLevel {
        if !self.model.reasoning {
            return crate::model::ThinkingLevel::Off;
        }
        if thinking == crate::model::ThinkingLevel::XHigh && !self.supports_xhigh() {
            return crate::model::ThinkingLevel::High;
        }
        thinking
    }
}

/// OAuth configuration for extension-registered providers.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub auth_url: String,
    pub token_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelsConfig {
    pub providers: HashMap<String, ProviderConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderConfig {
    pub base_url: Option<String>,
    pub api: Option<String>,
    pub api_key: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub auth_header: Option<bool>,
    pub compat: Option<CompatConfig>,
    pub models: Option<Vec<ModelConfig>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelConfig {
    pub id: String,
    pub name: Option<String>,
    pub api: Option<String>,
    pub reasoning: Option<bool>,
    pub input: Option<Vec<String>>,
    pub cost: Option<ModelCost>,
    pub context_window: Option<u32>,
    pub max_tokens: Option<u32>,
    pub headers: Option<HashMap<String, String>>,
    pub compat: Option<CompatConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatConfig {
    // ── Capability flags ────────────────────────────────────────────────
    pub supports_store: Option<bool>,
    pub supports_developer_role: Option<bool>,
    pub supports_reasoning_effort: Option<bool>,
    pub supports_usage_in_streaming: Option<bool>,
    pub supports_tools: Option<bool>,
    pub supports_streaming: Option<bool>,
    pub supports_parallel_tool_calls: Option<bool>,

    // ── Request field overrides ─────────────────────────────────────────
    /// Override the JSON field name for `max_tokens` (e.g., `"max_completion_tokens"` for o1).
    pub max_tokens_field: Option<String>,
    /// Override the system message role name (e.g., `"developer"` for some providers).
    pub system_role_name: Option<String>,
    /// Override the stop-reason field name in responses.
    pub stop_reason_field: Option<String>,

    // ── Per-provider request headers ────────────────────────────────────
    /// Extra HTTP headers injected into every request for this provider.
    /// Applied after default headers but before per-request `StreamOptions.headers`.
    pub custom_headers: Option<HashMap<String, String>>,

    // ── Gateway/routing metadata ────────────────────────────────────────
    pub open_router_routing: Option<serde_json::Value>,
    pub vercel_gateway_routing: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct ModelRegistry {
    models: Vec<ModelEntry>,
    error: Option<String>,
}

fn canonicalize_openrouter_model_id(model_id: &str) -> String {
    let trimmed = model_id.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "auto" => "openrouter/auto".to_string(),
        "gpt-4o-mini" => "openai/gpt-4o-mini".to_string(),
        "gpt-4o" => "openai/gpt-4o".to_string(),
        "claude-3.5-sonnet" => "anthropic/claude-3.5-sonnet".to_string(),
        "gemini-2.5-pro" => "google/gemini-2.5-pro".to_string(),
        _ => trimmed.to_string(),
    }
}

fn canonicalize_model_id_for_provider(provider: &str, model_id: &str) -> String {
    if canonical_provider_id(provider).is_some_and(|canonical| canonical == "openrouter") {
        return canonicalize_openrouter_model_id(model_id);
    }
    model_id.trim().to_string()
}

fn openrouter_model_lookup_ids(model_id: &str) -> Vec<String> {
    let raw = model_id.trim().to_string();
    let canonical = canonicalize_openrouter_model_id(model_id);
    if canonical.eq_ignore_ascii_case(&raw) {
        vec![canonical]
    } else {
        vec![raw, canonical]
    }
}

impl ModelRegistry {
    pub fn load(auth: &AuthStorage, models_path: Option<PathBuf>) -> Self {
        let mut models = built_in_models(auth);
        let mut error = None;

        if let Some(path) = models_path {
            if path.exists() {
                match std::fs::read_to_string(&path)
                    .map_err(|e| Error::config(format!("Failed to read models.json: {e}")))
                    .and_then(|s| serde_json::from_str::<ModelsConfig>(&s).map_err(Error::from))
                {
                    Ok(config) => {
                        apply_custom_models(auth, &mut models, &config);
                    }
                    Err(e) => {
                        error = Some(format!("{e}\n\nFile: {}", path.display()));
                    }
                }
            }
        }

        Self { models, error }
    }

    pub fn models(&self) -> &[ModelEntry] {
        &self.models
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn get_available(&self) -> Vec<ModelEntry> {
        self.models
            .iter()
            .filter(|&m| m.api_key.is_some())
            .cloned()
            .collect()
    }

    pub fn find(&self, provider: &str, id: &str) -> Option<ModelEntry> {
        let provider = provider.trim();
        let canonical_provider = canonical_provider_id(provider).unwrap_or(provider);
        let lookup_ids = if canonical_provider.eq_ignore_ascii_case("openrouter") {
            openrouter_model_lookup_ids(id)
        } else {
            vec![id.trim().to_string()]
        };

        self.models
            .iter()
            .find(|m| {
                (m.model.provider.eq_ignore_ascii_case(provider)
                    || m.model.provider.eq_ignore_ascii_case(canonical_provider))
                    && lookup_ids
                        .iter()
                        .any(|lookup_id| m.model.id.eq_ignore_ascii_case(lookup_id))
            })
            .cloned()
    }

    /// Find a model by ID alone (ignoring provider), useful for extension models
    /// where the provider name may be custom.
    pub fn find_by_id(&self, id: &str) -> Option<ModelEntry> {
        self.models.iter().find(|m| m.model.id == id).cloned()
    }

    /// Merge extension-provided model entries into the registry.
    pub fn merge_entries(&mut self, entries: Vec<ModelEntry>) {
        for entry in entries {
            // Skip duplicates (same provider + id).
            let exists = self
                .models
                .iter()
                .any(|m| m.model.provider == entry.model.provider && m.model.id == entry.model.id);
            if !exists {
                self.models.push(entry);
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn built_in_models(auth: &AuthStorage) -> Vec<ModelEntry> {
    let mut models = Vec::new();

    let anthropic_key = auth.resolve_api_key("anthropic", None);
    for (id, name, reasoning) in [
        ("claude-sonnet-4-20250514", "Claude Sonnet 4", true),
        ("claude-sonnet-4-5", "Claude Sonnet 4.5", true),
        ("claude-opus-4-5", "Claude Opus 4.5", true),
        ("claude-haiku-4-5", "Claude Haiku 4.5", false),
        ("claude-3-5-sonnet-20241022", "Claude Sonnet 3.5", true),
        ("claude-3-5-haiku-20241022", "Claude Haiku 3.5", false),
        ("claude-3-opus-20240229", "Claude Opus 3", true),
    ] {
        models.push(ModelEntry {
            model: Model {
                id: id.to_string(),
                name: name.to_string(),
                api: Api::AnthropicMessages.to_string(),
                provider: "anthropic".to_string(),
                base_url: "https://api.anthropic.com/v1/messages".to_string(),
                reasoning,
                input: vec![InputType::Text, InputType::Image],
                cost: ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
                context_window: 200_000,
                max_tokens: 8192,
                headers: HashMap::new(),
            },
            api_key: anthropic_key.clone(),
            headers: HashMap::new(),
            auth_header: false,
            compat: None,
            oauth_config: None,
        });
    }

    let openai_key = auth.resolve_api_key("openai", None);
    for (id, name) in [
        ("gpt-5.1-codex", "GPT-5.1 Codex"),
        ("gpt-4o", "GPT-4o"),
        ("gpt-4o-mini", "GPT-4o Mini"),
    ] {
        models.push(ModelEntry {
            model: Model {
                id: id.to_string(),
                name: name.to_string(),
                api: Api::OpenAIResponses.to_string(),
                provider: "openai".to_string(),
                base_url: "https://api.openai.com/v1".to_string(),
                reasoning: true,
                input: vec![InputType::Text, InputType::Image],
                cost: ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
                context_window: 128_000,
                max_tokens: 16384,
                headers: HashMap::new(),
            },
            api_key: openai_key.clone(),
            headers: HashMap::new(),
            auth_header: true,
            compat: None,
            oauth_config: None,
        });
    }

    let google_key = auth.resolve_api_key("google", None);
    for (id, name) in [
        ("gemini-2.5-pro", "Gemini 2.5 Pro"),
        ("gemini-2.5-flash", "Gemini 2.5 Flash"),
        ("gemini-1.5-pro", "Gemini 1.5 Pro"),
        ("gemini-1.5-flash", "Gemini 1.5 Flash"),
    ] {
        models.push(ModelEntry {
            model: Model {
                id: id.to_string(),
                name: name.to_string(),
                api: Api::GoogleGenerativeAI.to_string(),
                provider: "google".to_string(),
                base_url: "https://generativelanguage.googleapis.com/v1beta".to_string(),
                reasoning: true,
                input: vec![InputType::Text, InputType::Image],
                cost: ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
                context_window: 128_000,
                max_tokens: 8192,
                headers: HashMap::new(),
            },
            api_key: google_key.clone(),
            headers: HashMap::new(),
            auth_header: false,
            compat: None,
            oauth_config: None,
        });
    }

    let openrouter_key = auth.resolve_api_key("openrouter", None);
    for (id, name, reasoning) in [
        ("openrouter/auto", "OpenRouter Auto", true),
        ("openai/gpt-4o-mini", "OpenRouter GPT-4o Mini", true),
        ("openai/gpt-4o", "OpenRouter GPT-4o", true),
        (
            "anthropic/claude-3.5-sonnet",
            "OpenRouter Claude 3.5 Sonnet",
            true,
        ),
        ("google/gemini-2.5-pro", "OpenRouter Gemini 2.5 Pro", true),
    ] {
        models.push(ModelEntry {
            model: Model {
                id: id.to_string(),
                name: name.to_string(),
                api: Api::OpenAICompletions.to_string(),
                provider: "openrouter".to_string(),
                base_url: "https://openrouter.ai/api/v1".to_string(),
                reasoning,
                input: vec![InputType::Text],
                cost: ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
                context_window: 128_000,
                max_tokens: 16_384,
                headers: HashMap::new(),
            },
            api_key: openrouter_key.clone(),
            headers: HashMap::new(),
            auth_header: true,
            compat: None,
            oauth_config: None,
        });
    }

    models
}

#[allow(clippy::too_many_lines)]
fn apply_custom_models(auth: &AuthStorage, models: &mut Vec<ModelEntry>, config: &ModelsConfig) {
    for (provider_id, provider_cfg) in &config.providers {
        let routing_defaults = provider_routing_defaults(provider_id);
        let default_api = routing_defaults.map_or("openai-completions", |defaults| defaults.api);
        let provider_api = provider_cfg.api.as_deref().unwrap_or(default_api);
        let provider_api_parsed: Api = provider_api
            .parse()
            .unwrap_or_else(|_| Api::Custom(provider_api.to_string()));
        let provider_api_string = provider_api_parsed.to_string();
        let provider_base = provider_cfg.base_url.clone().unwrap_or_else(|| {
            routing_defaults.map_or_else(
                || "https://api.openai.com/v1".to_string(),
                |defaults| defaults.base_url.to_string(),
            )
        });

        let provider_headers = resolve_headers(provider_cfg.headers.as_ref());
        let canonical_provider = canonical_provider_id(provider_id).unwrap_or(provider_id.as_str());
        let provider_key = provider_cfg
            .api_key
            .as_deref()
            .and_then(resolve_value)
            .or_else(|| auth.resolve_api_key(canonical_provider, None));

        let auth_header = provider_cfg
            .auth_header
            .unwrap_or_else(|| routing_defaults.is_some_and(|defaults| defaults.auth_header));

        if routing_defaults.is_some() {
            tracing::debug!(
                event = "pi.provider.schema_defaults",
                provider = %provider_id,
                canonical_provider = %canonical_provider,
                api = %provider_api_string,
                base_url = %provider_base,
                auth_header,
                "Applied provider metadata defaults"
            );
        }

        let has_models = provider_cfg.models.as_ref().is_some();
        let is_override = !has_models;

        if is_override {
            for entry in models
                .iter_mut()
                .filter(|m| m.model.provider == *provider_id)
            {
                // Only override base_url and api if explicitly set in models.json.
                // Otherwise keep the built-in defaults (e.g. anthropic's /v1/messages URL).
                if provider_cfg.base_url.is_some() {
                    entry.model.base_url.clone_from(&provider_base);
                }
                if provider_cfg.api.is_some() {
                    entry.model.api.clone_from(&provider_api_string);
                }
                entry.headers.clone_from(&provider_headers);
                if provider_key.is_some() {
                    entry.api_key.clone_from(&provider_key);
                }
                if provider_cfg.compat.is_some() {
                    entry.compat.clone_from(&provider_cfg.compat);
                }
                if provider_cfg.auth_header.is_some() {
                    entry.auth_header = auth_header;
                }
            }
            continue;
        }

        // Remove built-in provider models if fully overridden
        models.retain(|m| m.model.provider != *provider_id);

        let mut normalized_provider_ids = HashSet::new();
        for model_cfg in provider_cfg.models.clone().unwrap_or_default() {
            let normalized_model_id =
                canonicalize_model_id_for_provider(provider_id, &model_cfg.id);
            if normalized_model_id.is_empty() {
                tracing::warn!(
                    provider = %provider_id,
                    model_id = %model_cfg.id,
                    "Skipping model with empty normalized id"
                );
                continue;
            }

            if canonical_provider == "openrouter"
                && !normalized_provider_ids.insert(normalized_model_id.to_ascii_lowercase())
            {
                tracing::warn!(
                    provider = %provider_id,
                    model_id = %normalized_model_id,
                    "Skipping duplicate OpenRouter model id after alias normalization"
                );
                continue;
            }

            let model_api = model_cfg.api.as_deref().unwrap_or(provider_api);
            let model_api_parsed: Api = model_api
                .parse()
                .unwrap_or_else(|_| Api::Custom(model_api.to_string()));
            let model_headers = merge_headers(
                &provider_headers,
                resolve_headers(model_cfg.headers.as_ref()),
            );
            let default_input_types = routing_defaults
                .map_or_else(|| vec![InputType::Text], |defaults| defaults.input.to_vec());
            let input_types = model_cfg.input.as_ref().map_or_else(
                || default_input_types.clone(),
                |input| {
                    input
                        .iter()
                        .filter_map(|i| match i.as_str() {
                            "text" => Some(InputType::Text),
                            "image" => Some(InputType::Image),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                },
            );
            let input_types = if input_types.is_empty() {
                default_input_types
            } else {
                input_types
            };
            let default_reasoning = routing_defaults.is_some_and(|defaults| defaults.reasoning);
            let default_context_window =
                routing_defaults.map_or(128_000, |defaults| defaults.context_window);
            let default_max_tokens =
                routing_defaults.map_or(16_384, |defaults| defaults.max_tokens);

            let model = Model {
                id: normalized_model_id.clone(),
                name: model_cfg
                    .name
                    .clone()
                    .unwrap_or_else(|| normalized_model_id.clone()),
                api: model_api_parsed.to_string(),
                provider: provider_id.clone(),
                base_url: provider_base.clone(),
                reasoning: model_cfg.reasoning.unwrap_or(default_reasoning),
                input: input_types,
                cost: model_cfg.cost.clone().unwrap_or(ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                }),
                context_window: model_cfg.context_window.unwrap_or(default_context_window),
                max_tokens: model_cfg.max_tokens.unwrap_or(default_max_tokens),
                headers: HashMap::new(),
            };

            models.push(ModelEntry {
                model,
                api_key: provider_key.clone(),
                headers: model_headers,
                auth_header,
                compat: merge_compat(provider_cfg.compat.as_ref(), model_cfg.compat.as_ref()),
                oauth_config: None,
            });
        }
    }
}

fn merge_compat(
    provider_compat: Option<&CompatConfig>,
    model_compat: Option<&CompatConfig>,
) -> Option<CompatConfig> {
    match (provider_compat, model_compat) {
        (None, None) => None,
        (Some(provider), None) => Some(provider.clone()),
        (None, Some(model)) => Some(model.clone()),
        (Some(provider), Some(model)) => {
            let custom_headers = match (&provider.custom_headers, &model.custom_headers) {
                (None, None) => None,
                (Some(headers), None) | (None, Some(headers)) => Some(headers.clone()),
                (Some(provider_headers), Some(model_headers)) => {
                    let mut merged = provider_headers.clone();
                    for (key, value) in model_headers {
                        merged.insert(key.clone(), value.clone());
                    }
                    Some(merged)
                }
            };

            Some(CompatConfig {
                supports_store: model.supports_store.or(provider.supports_store),
                supports_developer_role: model
                    .supports_developer_role
                    .or(provider.supports_developer_role),
                supports_reasoning_effort: model
                    .supports_reasoning_effort
                    .or(provider.supports_reasoning_effort),
                supports_usage_in_streaming: model
                    .supports_usage_in_streaming
                    .or(provider.supports_usage_in_streaming),
                supports_tools: model.supports_tools.or(provider.supports_tools),
                supports_streaming: model.supports_streaming.or(provider.supports_streaming),
                supports_parallel_tool_calls: model
                    .supports_parallel_tool_calls
                    .or(provider.supports_parallel_tool_calls),
                max_tokens_field: model
                    .max_tokens_field
                    .clone()
                    .or_else(|| provider.max_tokens_field.clone()),
                system_role_name: model
                    .system_role_name
                    .clone()
                    .or_else(|| provider.system_role_name.clone()),
                stop_reason_field: model
                    .stop_reason_field
                    .clone()
                    .or_else(|| provider.stop_reason_field.clone()),
                custom_headers,
                open_router_routing: model
                    .open_router_routing
                    .clone()
                    .or_else(|| provider.open_router_routing.clone()),
                vercel_gateway_routing: model
                    .vercel_gateway_routing
                    .clone()
                    .or_else(|| provider.vercel_gateway_routing.clone()),
            })
        }
    }
}

fn merge_headers(
    base: &HashMap<String, String>,
    override_headers: HashMap<String, String>,
) -> HashMap<String, String> {
    let mut merged = base.clone();
    for (k, v) in override_headers {
        merged.insert(k, v);
    }
    merged
}

fn resolve_headers(headers: Option<&HashMap<String, String>>) -> HashMap<String, String> {
    let mut resolved = HashMap::new();
    if let Some(headers) = headers {
        for (k, v) in headers {
            if let Some(val) = resolve_value(v) {
                resolved.insert(k.clone(), val);
            }
        }
    }
    resolved
}

fn resolve_value(value: &str) -> Option<String> {
    if let Some(rest) = value.strip_prefix('!') {
        return resolve_shell(rest);
    }

    if let Some(var_name) = value.strip_prefix("env:") {
        if var_name.is_empty() {
            return None;
        }
        return std::env::var(var_name).ok().filter(|v| !v.is_empty());
    }

    if let Some(file_path) = value.strip_prefix("file:") {
        if file_path.is_empty() {
            return None;
        }
        return std::fs::read_to_string(file_path)
            .ok()
            .map(|contents| contents.trim().to_string())
            .filter(|v| !v.is_empty());
    }

    if let Ok(env_val) = std::env::var(value) {
        if !env_val.is_empty() {
            return Some(env_val);
        }
    }

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn resolve_shell(cmd: &str) -> Option<String> {
    let output = if cfg!(windows) {
        std::process::Command::new("cmd")
            .args(["/C", cmd])
            .output()
            .ok()?
    } else {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .ok()?
    };

    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

/// Convenience for default models.json path.
pub fn default_models_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join("models.json")
}

// === Ad-hoc model support ===

#[derive(Debug, Clone, Copy)]
struct AdHocProviderDefaults {
    api: &'static str,
    base_url: &'static str,
    auth_header: bool,
    reasoning: bool,
    input: &'static [InputType],
    context_window: u32,
    max_tokens: u32,
}

impl From<ProviderRoutingDefaults> for AdHocProviderDefaults {
    fn from(value: ProviderRoutingDefaults) -> Self {
        Self {
            api: value.api,
            base_url: value.base_url,
            auth_header: value.auth_header,
            reasoning: value.reasoning,
            input: value.input,
            context_window: value.context_window,
            max_tokens: value.max_tokens,
        }
    }
}

fn ad_hoc_provider_defaults(provider: &str) -> Option<AdHocProviderDefaults> {
    provider_routing_defaults(provider).map(AdHocProviderDefaults::from)
}

fn sap_chat_completions_endpoint(service_url: &str, model_id: &str) -> Option<String> {
    let base = service_url.trim().trim_end_matches('/');
    let deployment = model_id.trim();
    if base.is_empty() || deployment.is_empty() {
        return None;
    }
    Some(format!(
        "{base}/v2/inference/deployments/{deployment}/chat/completions"
    ))
}

fn ad_hoc_model_entry_with_sap_resolver<F>(
    provider: &str,
    model_id: &str,
    mut resolve_sap: F,
) -> Option<ModelEntry>
where
    F: FnMut() -> Option<SapResolvedCredentials>,
{
    if canonical_provider_id(provider).is_some_and(|canonical| canonical == "sap-ai-core") {
        let sap_creds = resolve_sap()?;
        let base_url = sap_chat_completions_endpoint(&sap_creds.service_url, model_id)?;
        return Some(ModelEntry {
            model: Model {
                id: model_id.to_string(),
                name: model_id.to_string(),
                api: "openai-completions".to_string(),
                provider: provider.to_string(),
                base_url,
                reasoning: true,
                input: vec![InputType::Text],
                cost: ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
                context_window: 128_000,
                max_tokens: 16_384,
                headers: HashMap::new(),
            },
            api_key: None,
            headers: HashMap::new(),
            auth_header: true,
            compat: None,
            oauth_config: None,
        });
    }

    let defaults = ad_hoc_provider_defaults(provider)?;
    let normalized_model_id = canonicalize_model_id_for_provider(provider, model_id);
    if normalized_model_id.is_empty() {
        return None;
    }
    Some(ModelEntry {
        model: Model {
            id: normalized_model_id.clone(),
            name: normalized_model_id,
            api: defaults.api.to_string(),
            provider: provider.to_string(),
            base_url: defaults.base_url.to_string(),
            reasoning: defaults.reasoning,
            input: defaults.input.to_vec(),
            cost: ModelCost {
                input: 0.0,
                output: 0.0,
                cache_read: 0.0,
                cache_write: 0.0,
            },
            context_window: defaults.context_window,
            max_tokens: defaults.max_tokens,
            headers: HashMap::new(),
        },
        api_key: None,
        headers: HashMap::new(),
        auth_header: defaults.auth_header,
        compat: None,
        oauth_config: None,
    })
}

pub(crate) fn ad_hoc_model_entry(provider: &str, model_id: &str) -> Option<ModelEntry> {
    ad_hoc_model_entry_with_sap_resolver(provider, model_id, || {
        let auth = AuthStorage::load(crate::config::Config::auth_path()).ok()?;
        resolve_sap_credentials(&auth)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthCredential, AuthStorage};
    use tempfile::tempdir;

    fn test_auth_storage() -> (tempfile::TempDir, AuthStorage) {
        let dir = tempdir().expect("tempdir");
        let auth_path = dir.path().join("auth.json");
        let mut auth = AuthStorage::load(auth_path).expect("load auth");
        auth.set(
            "anthropic",
            AuthCredential::ApiKey {
                key: "anthropic-auth-key".to_string(),
            },
        );
        auth.set(
            "openai",
            AuthCredential::ApiKey {
                key: "openai-auth-key".to_string(),
            },
        );
        auth.set(
            "google",
            AuthCredential::ApiKey {
                key: "google-auth-key".to_string(),
            },
        );
        auth.set(
            "openrouter",
            AuthCredential::ApiKey {
                key: "openrouter-auth-key".to_string(),
            },
        );
        auth.set(
            "acme",
            AuthCredential::ApiKey {
                key: "acme-auth-key".to_string(),
            },
        );
        (dir, auth)
    }

    fn expected_env_pair() -> (String, String) {
        let key = ["PATH", "HOME", "PWD"]
            .iter()
            .find_map(|k| {
                std::env::var(k)
                    .ok()
                    .filter(|v| !v.is_empty())
                    .map(|v| ((*k).to_string(), v))
            })
            .expect("expected at least one non-empty environment variable");
        (key.0, key.1)
    }

    #[test]
    fn built_in_models_include_core_provider_entries() {
        let (_dir, auth) = test_auth_storage();
        let models = built_in_models(&auth);

        assert!(
            models.iter().any(
                |m| m.model.provider == "anthropic" && m.model.id == "claude-sonnet-4-20250514"
            )
        );
        assert!(
            models
                .iter()
                .any(|m| m.model.provider == "openai" && m.model.id == "gpt-4o")
        );
        assert!(
            models
                .iter()
                .any(|m| m.model.provider == "google" && m.model.id == "gemini-2.5-pro")
        );
        assert!(
            models
                .iter()
                .any(|m| m.model.provider == "openrouter" && m.model.id == "openrouter/auto")
        );

        let anthropic = models
            .iter()
            .find(|m| m.model.provider == "anthropic")
            .expect("anthropic model");
        let openai = models
            .iter()
            .find(|m| m.model.provider == "openai")
            .expect("openai model");
        let google = models
            .iter()
            .find(|m| m.model.provider == "google")
            .expect("google model");
        let openrouter = models
            .iter()
            .find(|m| m.model.provider == "openrouter")
            .expect("openrouter model");
        assert_eq!(anthropic.api_key.as_deref(), Some("anthropic-auth-key"));
        assert_eq!(openai.api_key.as_deref(), Some("openai-auth-key"));
        assert_eq!(google.api_key.as_deref(), Some("google-auth-key"));
        assert_eq!(openrouter.api_key.as_deref(), Some("openrouter-auth-key"));
    }

    #[test]
    fn apply_custom_models_overrides_provider_fields() {
        let (_dir, auth) = test_auth_storage();
        let mut models = built_in_models(&auth);
        let (env_key, env_val) = expected_env_pair();
        let mut provider_headers = HashMap::new();
        provider_headers.insert("x-provider".to_string(), "provider-header".to_string());

        let config = ModelsConfig {
            providers: HashMap::from([(
                "anthropic".to_string(),
                ProviderConfig {
                    base_url: Some("https://proxy.example/v1/messages".to_string()),
                    api: Some("anthropic-messages".to_string()),
                    api_key: Some(format!("env:{env_key}")),
                    headers: Some(provider_headers),
                    auth_header: Some(true),
                    compat: Some(CompatConfig {
                        supports_store: Some(true),
                        ..CompatConfig::default()
                    }),
                    models: None,
                },
            )]),
        };

        apply_custom_models(&auth, &mut models, &config);

        for entry in models.iter().filter(|m| m.model.provider == "anthropic") {
            assert_eq!(entry.model.base_url, "https://proxy.example/v1/messages");
            assert_eq!(entry.model.api, "anthropic-messages");
            assert_eq!(entry.api_key.as_deref(), Some(env_val.as_str()));
            assert_eq!(
                entry.headers.get("x-provider").map(String::as_str),
                Some("provider-header")
            );
            assert!(entry.auth_header);
            assert!(
                entry
                    .compat
                    .as_ref()
                    .and_then(|c| c.supports_store)
                    .unwrap_or(false)
            );
        }
    }

    #[test]
    fn apply_custom_models_uses_schema_defaults_for_provider_models() {
        let (_dir, auth) = test_auth_storage();
        let mut models = Vec::new();
        let config = ModelsConfig {
            providers: HashMap::from([(
                "cohere".to_string(),
                ProviderConfig {
                    models: Some(vec![ModelConfig {
                        id: "command-r-plus".to_string(),
                        ..ModelConfig::default()
                    }]),
                    ..ProviderConfig::default()
                },
            )]),
        };

        apply_custom_models(&auth, &mut models, &config);

        let cohere = models
            .iter()
            .find(|entry| entry.model.provider == "cohere")
            .expect("cohere model should be added");
        assert_eq!(cohere.model.api, "cohere-chat");
        assert_eq!(cohere.model.base_url, "https://api.cohere.com/v2");
        assert!(cohere.model.reasoning);
        assert_eq!(cohere.model.input, vec![InputType::Text]);
        assert_eq!(cohere.model.context_window, 128_000);
        assert_eq!(cohere.model.max_tokens, 8192);
        assert!(!cohere.auth_header);
    }

    #[test]
    fn apply_custom_models_merges_provider_and_model_compat() {
        let (_dir, auth) = test_auth_storage();
        let mut models = Vec::new();
        let config = ModelsConfig {
            providers: HashMap::from([(
                "custom-openai".to_string(),
                ProviderConfig {
                    api: Some("openai-completions".to_string()),
                    base_url: Some("https://compat.example/v1".to_string()),
                    compat: Some(CompatConfig {
                        supports_tools: Some(false),
                        supports_usage_in_streaming: Some(false),
                        max_tokens_field: Some("max_completion_tokens".to_string()),
                        custom_headers: Some(HashMap::from([
                            ("x-provider-only".to_string(), "provider".to_string()),
                            ("x-shared".to_string(), "provider".to_string()),
                        ])),
                        ..CompatConfig::default()
                    }),
                    models: Some(vec![ModelConfig {
                        id: "custom-model".to_string(),
                        compat: Some(CompatConfig {
                            supports_tools: Some(true),
                            system_role_name: Some("developer".to_string()),
                            custom_headers: Some(HashMap::from([
                                ("x-model-only".to_string(), "model".to_string()),
                                ("x-shared".to_string(), "model".to_string()),
                            ])),
                            ..CompatConfig::default()
                        }),
                        ..ModelConfig::default()
                    }]),
                    ..ProviderConfig::default()
                },
            )]),
        };

        apply_custom_models(&auth, &mut models, &config);

        let entry = models
            .iter()
            .find(|m| m.model.provider == "custom-openai" && m.model.id == "custom-model")
            .expect("custom model should be added");
        let compat = entry.compat.as_ref().expect("compat should be merged");
        assert_eq!(
            compat.max_tokens_field.as_deref(),
            Some("max_completion_tokens")
        );
        assert_eq!(compat.system_role_name.as_deref(), Some("developer"));
        assert_eq!(compat.supports_usage_in_streaming, Some(false));
        assert_eq!(compat.supports_tools, Some(true));
        let custom_headers = compat
            .custom_headers
            .as_ref()
            .expect("custom headers should be merged");
        assert_eq!(
            custom_headers.get("x-provider-only").map(String::as_str),
            Some("provider")
        );
        assert_eq!(
            custom_headers.get("x-model-only").map(String::as_str),
            Some("model")
        );
        assert_eq!(
            custom_headers.get("x-shared").map(String::as_str),
            Some("model")
        );
    }

    #[test]
    fn apply_custom_models_uses_schema_defaults_for_native_anthropic_models() {
        let (_dir, auth) = test_auth_storage();
        let mut models = Vec::new();
        let config = ModelsConfig {
            providers: HashMap::from([(
                "anthropic".to_string(),
                ProviderConfig {
                    models: Some(vec![ModelConfig {
                        id: "claude-schema-default".to_string(),
                        ..ModelConfig::default()
                    }]),
                    ..ProviderConfig::default()
                },
            )]),
        };

        apply_custom_models(&auth, &mut models, &config);

        let anthropic = models
            .iter()
            .find(|entry| entry.model.provider == "anthropic")
            .expect("anthropic model should be added");
        assert_eq!(anthropic.model.api, "anthropic-messages");
        assert_eq!(
            anthropic.model.base_url,
            "https://api.anthropic.com/v1/messages"
        );
        assert!(anthropic.model.reasoning);
        assert_eq!(
            anthropic.model.input,
            vec![InputType::Text, InputType::Image]
        );
        assert_eq!(anthropic.model.context_window, 200_000);
        assert_eq!(anthropic.model.max_tokens, 8192);
        assert!(!anthropic.auth_header);
    }

    #[test]
    fn apply_custom_models_alias_resolves_canonical_provider_api_key() {
        let (_dir, mut auth) = test_auth_storage();
        auth.set(
            "moonshotai",
            AuthCredential::ApiKey {
                key: "moonshot-auth-key".to_string(),
            },
        );

        let mut models = Vec::new();
        let config = ModelsConfig {
            providers: HashMap::from([(
                "kimi".to_string(),
                ProviderConfig {
                    models: Some(vec![ModelConfig {
                        id: "kimi-k2-instruct".to_string(),
                        ..ModelConfig::default()
                    }]),
                    ..ProviderConfig::default()
                },
            )]),
        };

        apply_custom_models(&auth, &mut models, &config);

        let kimi = models
            .iter()
            .find(|entry| entry.model.provider == "kimi")
            .expect("kimi model should be added");
        assert_eq!(kimi.model.api, "openai-completions");
        assert_eq!(kimi.model.base_url, "https://api.moonshot.ai/v1");
        assert_eq!(kimi.api_key.as_deref(), Some("moonshot-auth-key"));
        assert!(kimi.auth_header);
    }

    #[test]
    fn model_registry_find_and_find_by_id_work() {
        let (_dir, auth) = test_auth_storage();
        let registry = ModelRegistry::load(&auth, None);

        let by_provider_and_id = registry
            .find("openai", "gpt-4o")
            .expect("openai/gpt-4o should exist");
        assert_eq!(by_provider_and_id.model.provider, "openai");
        assert_eq!(by_provider_and_id.model.id, "gpt-4o");

        let by_id = registry
            .find_by_id("gemini-2.5-pro")
            .expect("gemini-2.5-pro should exist");
        assert_eq!(by_id.model.provider, "google");
        assert_eq!(by_id.model.id, "gemini-2.5-pro");

        assert!(registry.find("openai", "does-not-exist").is_none());
        assert!(registry.find_by_id("does-not-exist").is_none());
    }

    #[test]
    fn model_registry_find_normalizes_openrouter_model_aliases() {
        let (_dir, auth) = test_auth_storage();
        let registry = ModelRegistry::load(&auth, None);

        let gpt4o_mini = registry
            .find("openrouter", "gpt-4o-mini")
            .expect("openrouter alias should resolve");
        assert_eq!(gpt4o_mini.model.provider, "openrouter");
        assert_eq!(gpt4o_mini.model.id, "openai/gpt-4o-mini");

        let auto = registry
            .find("openrouter", "auto")
            .expect("openrouter auto alias should resolve");
        assert_eq!(auto.model.id, "openrouter/auto");

        let provider_alias = registry
            .find("open-router", "gpt-4o-mini")
            .expect("open-router provider alias should resolve");
        assert_eq!(provider_alias.model.provider, "openrouter");
        assert_eq!(provider_alias.model.id, "openai/gpt-4o-mini");
    }

    #[test]
    fn ad_hoc_model_entry_normalizes_openrouter_aliases() {
        let auto = ad_hoc_model_entry("openrouter", "auto").expect("openrouter auto ad-hoc");
        assert_eq!(auto.model.id, "openrouter/auto");

        let gpt4o_mini =
            ad_hoc_model_entry("openrouter", "gpt-4o-mini").expect("openrouter gpt-4o-mini ad-hoc");
        assert_eq!(gpt4o_mini.model.id, "openai/gpt-4o-mini");
    }

    #[test]
    fn model_registry_merge_entries_deduplicates() {
        let (_dir, auth) = test_auth_storage();
        let mut registry = ModelRegistry::load(&auth, None);
        let before = registry.models().len();
        let duplicate = registry
            .find("openai", "gpt-4o")
            .expect("expected built-in openai model");

        let new_entry = ModelEntry {
            model: Model {
                id: "acme-chat".to_string(),
                name: "Acme Chat".to_string(),
                api: "openai-completions".to_string(),
                provider: "acme".to_string(),
                base_url: "https://acme.example/v1".to_string(),
                reasoning: true,
                input: vec![InputType::Text],
                cost: ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
                context_window: 64_000,
                max_tokens: 4096,
                headers: HashMap::new(),
            },
            api_key: Some("acme-auth-key".to_string()),
            headers: HashMap::new(),
            auth_header: true,
            compat: None,
            oauth_config: None,
        };

        registry.merge_entries(vec![duplicate, new_entry]);
        assert_eq!(registry.models().len(), before + 1);
        assert!(registry.find("acme", "acme-chat").is_some());
    }

    #[test]
    fn apply_custom_models_dedupes_openrouter_alias_conflicts() {
        let (_dir, auth) = test_auth_storage();
        let mut models = Vec::new();
        let config = ModelsConfig {
            providers: HashMap::from([(
                "openrouter".to_string(),
                ProviderConfig {
                    models: Some(vec![
                        ModelConfig {
                            id: "gpt-4o-mini".to_string(),
                            ..ModelConfig::default()
                        },
                        ModelConfig {
                            id: "openai/gpt-4o-mini".to_string(),
                            ..ModelConfig::default()
                        },
                        ModelConfig {
                            id: "auto".to_string(),
                            ..ModelConfig::default()
                        },
                    ]),
                    ..ProviderConfig::default()
                },
            )]),
        };

        apply_custom_models(&auth, &mut models, &config);

        let openrouter_models: Vec<&ModelEntry> = models
            .iter()
            .filter(|entry| entry.model.provider == "openrouter")
            .collect();
        assert_eq!(openrouter_models.len(), 2);
        assert!(
            openrouter_models
                .iter()
                .any(|entry| entry.model.id == "openai/gpt-4o-mini")
        );
        assert!(
            openrouter_models
                .iter()
                .any(|entry| entry.model.id == "openrouter/auto")
        );
    }

    #[test]
    fn resolve_value_supports_env_and_file_prefixes() {
        let (env_key, env_val) = expected_env_pair();
        assert_eq!(
            resolve_value(&format!("env:{env_key}")).as_deref(),
            Some(env_val.as_str())
        );
        assert_eq!(resolve_value(&env_key).as_deref(), Some(env_val.as_str()));

        let dir = tempdir().expect("tempdir");
        let key_path = dir.path().join("api_key.txt");
        std::fs::write(&key_path, "file-key\n").expect("write key file");
        assert_eq!(
            resolve_value(&format!("file:{}", key_path.display())).as_deref(),
            Some("file-key")
        );
        assert!(resolve_value("file:/definitely/missing/path").is_none());
    }

    #[test]
    fn model_registry_load_reads_models_json_and_applies_config() {
        let (dir, auth) = test_auth_storage();
        let models_path = dir.path().join("models.json");
        let key_path = dir.path().join("custom_key.txt");
        std::fs::write(&key_path, "acme-file-key\n").expect("write custom key");

        let models_json = serde_json::json!({
            "providers": {
                "acme": {
                    "baseUrl": "https://acme.example/v1",
                    "api": "openai-completions",
                    "apiKey": format!("file:{}", key_path.display()),
                    "headers": {
                        "x-provider": "provider-level"
                    },
                    "authHeader": true,
                    "models": [
                        {
                            "id": "acme-chat",
                            "name": "Acme Chat",
                            "input": ["text", "image"],
                            "reasoning": true,
                            "contextWindow": 64000,
                            "maxTokens": 4096,
                            "headers": {
                                "x-model": "model-level"
                            }
                        }
                    ]
                }
            }
        });

        std::fs::write(
            &models_path,
            serde_json::to_string_pretty(&models_json).expect("serialize models json"),
        )
        .expect("write models.json");

        let registry = ModelRegistry::load(&auth, Some(models_path));
        let acme = registry
            .find("acme", "acme-chat")
            .expect("custom acme model should load from models.json");

        assert_eq!(acme.model.name, "Acme Chat");
        assert_eq!(acme.model.api, "openai-completions");
        assert_eq!(acme.model.base_url, "https://acme.example/v1");
        assert_eq!(acme.model.context_window, 64_000);
        assert_eq!(acme.model.max_tokens, 4096);
        assert_eq!(acme.api_key.as_deref(), Some("acme-file-key"));
        assert!(acme.auth_header);
        assert_eq!(
            acme.headers.get("x-provider").map(String::as_str),
            Some("provider-level")
        );
        assert_eq!(
            acme.headers.get("x-model").map(String::as_str),
            Some("model-level")
        );
        assert_eq!(acme.model.input, vec![InputType::Text, InputType::Image]);
    }

    // ─── supports_xhigh ──────────────────────────────────────────────

    fn make_model_entry(id: &str, reasoning: bool) -> ModelEntry {
        ModelEntry {
            model: Model {
                id: id.to_string(),
                name: id.to_string(),
                api: "openai-responses".to_string(),
                provider: "test".to_string(),
                base_url: "https://example.com".to_string(),
                reasoning,
                input: vec![InputType::Text],
                cost: ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
                context_window: 128_000,
                max_tokens: 8192,
                headers: HashMap::new(),
            },
            api_key: None,
            headers: HashMap::new(),
            auth_header: false,
            compat: None,
            oauth_config: None,
        }
    }

    #[test]
    fn supports_xhigh_for_known_models() {
        assert!(make_model_entry("gpt-5.1-codex-max", true).supports_xhigh());
        assert!(make_model_entry("gpt-5.2", true).supports_xhigh());
        assert!(make_model_entry("gpt-5.2-codex", true).supports_xhigh());
    }

    #[test]
    fn supports_xhigh_false_for_other_models() {
        assert!(!make_model_entry("gpt-4o", true).supports_xhigh());
        assert!(!make_model_entry("claude-sonnet-4-20250514", true).supports_xhigh());
        assert!(!make_model_entry("gemini-2.5-pro", true).supports_xhigh());
    }

    // ─── clamp_thinking_level ────────────────────────────────────────

    #[test]
    fn clamp_non_reasoning_always_off() {
        use crate::model::ThinkingLevel;
        let entry = make_model_entry("gpt-4o-mini", false);
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::High),
            ThinkingLevel::Off
        );
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::Medium),
            ThinkingLevel::Off
        );
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::Off),
            ThinkingLevel::Off
        );
    }

    #[test]
    fn clamp_xhigh_downgraded_without_support() {
        use crate::model::ThinkingLevel;
        let entry = make_model_entry("claude-sonnet-4-20250514", true);
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::XHigh),
            ThinkingLevel::High,
        );
    }

    #[test]
    fn clamp_xhigh_preserved_with_support() {
        use crate::model::ThinkingLevel;
        let entry = make_model_entry("gpt-5.2", true);
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::XHigh),
            ThinkingLevel::XHigh,
        );
    }

    #[test]
    fn clamp_passthrough_for_regular_levels() {
        use crate::model::ThinkingLevel;
        let entry = make_model_entry("claude-sonnet-4-20250514", true);
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::High),
            ThinkingLevel::High
        );
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::Medium),
            ThinkingLevel::Medium
        );
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::Low),
            ThinkingLevel::Low
        );
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::Minimal),
            ThinkingLevel::Minimal
        );
        assert_eq!(
            entry.clamp_thinking_level(ThinkingLevel::Off),
            ThinkingLevel::Off
        );
    }

    // ─── ad_hoc_provider_defaults ────────────────────────────────────

    #[test]
    fn ad_hoc_known_providers() {
        let providers = [
            "anthropic",
            "openai",
            "google",
            "cohere",
            "amazon-bedrock",
            "groq",
            "deepinfra",
            "cerebras",
            "openrouter",
            "mistral",
            "deepseek",
            "fireworks",
            "togetherai",
            "perplexity",
            "xai",
            "baseten",
            "llama",
            "lmstudio",
            "ollama-cloud",
        ];
        for provider in providers {
            assert!(
                ad_hoc_provider_defaults(provider).is_some(),
                "expected defaults for '{provider}'"
            );
        }
    }

    #[test]
    fn ad_hoc_alibaba_aliases() {
        for alias in ["alibaba", "dashscope", "qwen"] {
            let defaults = ad_hoc_provider_defaults(alias)
                .unwrap_or_else(|| panic!("expected defaults for '{alias}'"));
            assert!(defaults.base_url.contains("dashscope"));
        }
    }

    #[test]
    fn ad_hoc_moonshot_aliases() {
        for alias in ["moonshotai", "moonshot", "kimi"] {
            let defaults = ad_hoc_provider_defaults(alias)
                .unwrap_or_else(|| panic!("expected defaults for '{alias}'"));
            assert!(defaults.base_url.contains("moonshot"));
        }
    }

    #[test]
    fn ad_hoc_batch_b1_defaults_resolve_expected_routes() {
        let alibaba_cn =
            ad_hoc_provider_defaults("alibaba-cn").expect("expected defaults for alibaba-cn");
        assert_eq!(alibaba_cn.api, "openai-completions");
        assert!(alibaba_cn.auth_header);
        assert!(alibaba_cn.base_url.contains("dashscope.aliyuncs.com"));

        let kimi_for_coding = ad_hoc_provider_defaults("kimi-for-coding")
            .expect("expected defaults for kimi-for-coding");
        assert_eq!(kimi_for_coding.api, "anthropic-messages");
        assert!(!kimi_for_coding.auth_header);
        assert!(kimi_for_coding.base_url.contains("api.kimi.com/coding"));

        for provider in [
            "minimax",
            "minimax-cn",
            "minimax-coding-plan",
            "minimax-cn-coding-plan",
        ] {
            let defaults =
                ad_hoc_provider_defaults(provider).unwrap_or_else(|| panic!("defaults {provider}"));
            assert_eq!(defaults.api, "anthropic-messages");
            assert!(!defaults.auth_header);
            assert!(defaults.base_url.contains("api.minimax"));
        }
    }

    #[test]
    fn ad_hoc_batch_b2_defaults_resolve_expected_routes() {
        let cases = [
            ("modelscope", "https://api-inference.modelscope.cn/v1"),
            ("moonshotai-cn", "https://api.moonshot.cn/v1"),
            ("nebius", "https://api.tokenfactory.nebius.com/v1"),
            (
                "ovhcloud",
                "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
            ),
            ("scaleway", "https://api.scaleway.ai/v1"),
        ];
        for (provider, expected_base_url) in &cases {
            let defaults =
                ad_hoc_provider_defaults(provider).unwrap_or_else(|| panic!("defaults {provider}"));
            assert_eq!(defaults.api, "openai-completions");
            assert!(defaults.auth_header);
            assert_eq!(defaults.base_url, *expected_base_url);
        }
    }

    #[test]
    fn ad_hoc_batch_b3_defaults_resolve_expected_routes() {
        let cases = [
            ("siliconflow", "https://api.siliconflow.com/v1"),
            ("siliconflow-cn", "https://api.siliconflow.cn/v1"),
            ("upstage", "https://api.upstage.ai/v1/solar"),
            ("venice", "https://api.venice.ai/api/v1"),
            ("zai", "https://api.z.ai/api/paas/v4"),
            ("zai-coding-plan", "https://api.z.ai/api/coding/paas/v4"),
            ("zhipuai", "https://open.bigmodel.cn/api/paas/v4"),
            (
                "zhipuai-coding-plan",
                "https://open.bigmodel.cn/api/coding/paas/v4",
            ),
        ];
        for (provider, expected_base_url) in &cases {
            let defaults =
                ad_hoc_provider_defaults(provider).unwrap_or_else(|| panic!("defaults {provider}"));
            assert_eq!(defaults.api, "openai-completions");
            assert!(defaults.auth_header);
            assert_eq!(defaults.base_url, *expected_base_url);
        }
    }

    #[test]
    fn ad_hoc_batch_b3_coding_plan_and_regional_variants_remain_distinct() {
        let siliconflow = ad_hoc_provider_defaults("siliconflow").expect("siliconflow defaults");
        let siliconflow_cn =
            ad_hoc_provider_defaults("siliconflow-cn").expect("siliconflow-cn defaults");
        assert_eq!(canonical_provider_id("siliconflow"), Some("siliconflow"));
        assert_eq!(
            canonical_provider_id("siliconflow-cn"),
            Some("siliconflow-cn")
        );
        assert_ne!(siliconflow.base_url, siliconflow_cn.base_url);

        let zai = ad_hoc_provider_defaults("zai").expect("zai defaults");
        let zai_coding = ad_hoc_provider_defaults("zai-coding-plan").expect("zai-coding defaults");
        assert_eq!(canonical_provider_id("zai"), Some("zai"));
        assert_eq!(
            canonical_provider_id("zai-coding-plan"),
            Some("zai-coding-plan")
        );
        assert_eq!(zai.api, "openai-completions");
        assert_eq!(zai_coding.api, "openai-completions");
        assert_ne!(zai.base_url, zai_coding.base_url);

        let zhipu = ad_hoc_provider_defaults("zhipuai").expect("zhipu defaults");
        let zhipu_coding =
            ad_hoc_provider_defaults("zhipuai-coding-plan").expect("zhipu-coding defaults");
        assert_eq!(canonical_provider_id("zhipuai"), Some("zhipuai"));
        assert_eq!(
            canonical_provider_id("zhipuai-coding-plan"),
            Some("zhipuai-coding-plan")
        );
        assert_eq!(zhipu.api, "openai-completions");
        assert_eq!(zhipu_coding.api, "openai-completions");
        assert_ne!(zhipu.base_url, zhipu_coding.base_url);
    }

    #[test]
    fn ad_hoc_batch_c1_defaults_resolve_expected_routes() {
        let cases = [
            ("baseten", "https://inference.baseten.co/v1"),
            ("llama", "https://api.llama.com/compat/v1"),
            ("lmstudio", "http://127.0.0.1:1234/v1"),
            ("ollama-cloud", "https://ollama.com/v1"),
        ];
        for (provider, expected_base_url) in &cases {
            let defaults =
                ad_hoc_provider_defaults(provider).unwrap_or_else(|| panic!("defaults {provider}"));
            assert_eq!(defaults.api, "openai-completions");
            assert!(defaults.auth_header);
            assert_eq!(defaults.base_url, *expected_base_url);
        }
    }

    #[test]
    fn ad_hoc_kimi_alias_and_kimi_for_coding_remain_distinct() {
        assert_eq!(canonical_provider_id("kimi"), Some("moonshotai"));
        assert_eq!(
            canonical_provider_id("kimi-for-coding"),
            Some("kimi-for-coding")
        );

        let kimi_alias = ad_hoc_provider_defaults("kimi").expect("kimi alias defaults");
        let kimi_for_coding =
            ad_hoc_provider_defaults("kimi-for-coding").expect("kimi-for-coding defaults");
        assert!(kimi_alias.base_url.contains("moonshot.ai"));
        assert!(kimi_for_coding.base_url.contains("api.kimi.com"));
        assert_ne!(kimi_alias.base_url, kimi_for_coding.base_url);
        assert_ne!(kimi_alias.api, kimi_for_coding.api);
    }

    #[test]
    fn ad_hoc_alibaba_cn_is_distinct_from_alibaba_family_aliases() {
        let alibaba = ad_hoc_provider_defaults("alibaba").expect("alibaba defaults");
        let alibaba_cn = ad_hoc_provider_defaults("alibaba-cn").expect("alibaba-cn defaults");
        assert_eq!(canonical_provider_id("dashscope"), Some("alibaba"));
        assert_eq!(canonical_provider_id("alibaba-cn"), Some("alibaba-cn"));
        assert_eq!(alibaba.api, "openai-completions");
        assert_eq!(alibaba_cn.api, "openai-completions");
        assert_ne!(alibaba.base_url, alibaba_cn.base_url);
    }

    #[test]
    fn ad_hoc_moonshot_cn_is_distinct_from_global_moonshot_aliases() {
        let moonshot_global = ad_hoc_provider_defaults("moonshot").expect("moonshot defaults");
        let moonshot_cn =
            ad_hoc_provider_defaults("moonshotai-cn").expect("moonshotai-cn defaults");
        assert_eq!(canonical_provider_id("moonshot"), Some("moonshotai"));
        assert_eq!(
            canonical_provider_id("moonshotai-cn"),
            Some("moonshotai-cn")
        );
        assert_eq!(moonshot_global.api, "openai-completions");
        assert_eq!(moonshot_cn.api, "openai-completions");
        assert_ne!(moonshot_global.base_url, moonshot_cn.base_url);
    }

    #[test]
    fn ad_hoc_unknown_returns_none() {
        assert!(ad_hoc_provider_defaults("unknown-provider").is_none());
        assert!(ad_hoc_provider_defaults("").is_none());
    }

    #[test]
    fn ad_hoc_anthropic_uses_messages_api() {
        let defaults = ad_hoc_provider_defaults("anthropic").unwrap();
        assert_eq!(defaults.api, "anthropic-messages");
        assert_eq!(defaults.base_url, "https://api.anthropic.com/v1/messages");
        assert!(defaults.reasoning);
    }

    #[test]
    fn ad_hoc_openai_uses_responses_api() {
        let defaults = ad_hoc_provider_defaults("openai").unwrap();
        assert_eq!(defaults.api, "openai-responses");
    }

    #[test]
    fn ad_hoc_groq_uses_completions_api() {
        let defaults = ad_hoc_provider_defaults("groq").unwrap();
        assert_eq!(defaults.api, "openai-completions");
        assert!(defaults.base_url.contains("groq.com"));
    }

    #[test]
    fn ad_hoc_bedrock_uses_converse_api() {
        let defaults = ad_hoc_provider_defaults("amazon-bedrock").unwrap();
        assert_eq!(defaults.api, "bedrock-converse-stream");
        assert_eq!(defaults.base_url, "");
        assert!(!defaults.auth_header);
    }

    // ─── ad_hoc_model_entry ──────────────────────────────────────────

    #[test]
    fn ad_hoc_model_entry_creates_valid_entry() {
        let entry = ad_hoc_model_entry("groq", "llama-3-70b").unwrap();
        assert_eq!(entry.model.id, "llama-3-70b");
        assert_eq!(entry.model.name, "llama-3-70b");
        assert_eq!(entry.model.provider, "groq");
        assert_eq!(entry.model.api, "openai-completions");
        assert!(entry.model.base_url.contains("groq.com"));
        assert!(entry.auth_header); // openai-compatible → auth_header = true
        assert!(entry.api_key.is_none()); // no auth lookup
    }

    #[test]
    fn ad_hoc_model_entry_anthropic_no_auth_header() {
        let entry = ad_hoc_model_entry("anthropic", "claude-custom").unwrap();
        assert!(!entry.auth_header); // anthropic uses x-api-key, not Authorization
    }

    #[test]
    fn ad_hoc_model_entry_unknown_returns_none() {
        assert!(ad_hoc_model_entry("nonexistent", "model").is_none());
    }

    #[test]
    fn sap_chat_completions_endpoint_formats_expected_path() {
        let endpoint =
            sap_chat_completions_endpoint("https://api.ai.sap.example.com/", "deployment-a")
                .expect("endpoint");
        assert_eq!(
            endpoint,
            "https://api.ai.sap.example.com/v2/inference/deployments/deployment-a/chat/completions"
        );
    }

    #[test]
    fn ad_hoc_model_entry_supports_sap_with_resolved_service_key() {
        let entry = ad_hoc_model_entry_with_sap_resolver("sap-ai-core", "dep-123", || {
            Some(SapResolvedCredentials {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
                token_url: "https://auth.sap.example.com/oauth/token".to_string(),
                service_url: "https://api.ai.sap.example.com".to_string(),
            })
        })
        .expect("sap ad-hoc entry");

        assert_eq!(entry.model.provider, "sap-ai-core");
        assert_eq!(entry.model.api, "openai-completions");
        assert_eq!(
            entry.model.base_url,
            "https://api.ai.sap.example.com/v2/inference/deployments/dep-123/chat/completions"
        );
        assert!(entry.auth_header);
    }

    #[test]
    fn ad_hoc_model_entry_supports_sap_alias() {
        let entry = ad_hoc_model_entry_with_sap_resolver("sap", "dep-123", || {
            Some(SapResolvedCredentials {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
                token_url: "https://auth.sap.example.com/oauth/token".to_string(),
                service_url: "https://api.ai.sap.example.com".to_string(),
            })
        })
        .expect("sap alias ad-hoc entry");

        assert_eq!(entry.model.provider, "sap");
        assert_eq!(entry.model.api, "openai-completions");
        assert!(entry.auth_header);
    }

    #[test]
    fn ad_hoc_model_entry_sap_without_credentials_returns_none() {
        assert!(ad_hoc_model_entry_with_sap_resolver("sap-ai-core", "dep-123", || None).is_none());
    }

    // ─── merge_headers ───────────────────────────────────────────────

    #[test]
    fn merge_headers_combines_both() {
        let base = HashMap::from([
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ]);
        let overrides = HashMap::from([
            ("b".to_string(), "override".to_string()),
            ("c".to_string(), "3".to_string()),
        ]);
        let merged = merge_headers(&base, overrides);
        assert_eq!(merged.get("a").unwrap(), "1");
        assert_eq!(merged.get("b").unwrap(), "override");
        assert_eq!(merged.get("c").unwrap(), "3");
    }

    #[test]
    fn merge_headers_empty_base() {
        let merged = merge_headers(
            &HashMap::new(),
            HashMap::from([("x".to_string(), "y".to_string())]),
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged.get("x").unwrap(), "y");
    }

    #[test]
    fn merge_headers_empty_overrides() {
        let base = HashMap::from([("x".to_string(), "y".to_string())]);
        let merged = merge_headers(&base, HashMap::new());
        assert_eq!(merged, base);
    }

    // ─── resolve_value ───────────────────────────────────────────────

    #[test]
    fn resolve_value_plain_literal() {
        assert_eq!(resolve_value("my-key").as_deref(), Some("my-key"));
    }

    #[test]
    fn resolve_value_empty_returns_none() {
        assert!(resolve_value("").is_none());
    }

    #[test]
    fn resolve_value_env_empty_var_name_returns_none() {
        assert!(resolve_value("env:").is_none());
    }

    #[test]
    fn resolve_value_file_empty_path_returns_none() {
        assert!(resolve_value("file:").is_none());
    }

    #[test]
    fn resolve_value_file_missing_returns_none() {
        assert!(resolve_value("file:/nonexistent/path/key.txt").is_none());
    }

    #[test]
    fn resolve_value_shell_echo() {
        let result = resolve_value("!echo hello");
        assert_eq!(result.as_deref(), Some("hello"));
    }

    #[test]
    fn resolve_value_shell_failing_command() {
        assert!(resolve_value("!false").is_none());
    }

    // ─── resolve_headers ─────────────────────────────────────────────

    #[test]
    fn resolve_headers_none_returns_empty() {
        assert!(resolve_headers(None).is_empty());
    }

    #[test]
    fn resolve_headers_resolves_literal_values() {
        let mut headers = HashMap::new();
        headers.insert("x-key".to_string(), "literal-value".to_string());
        let resolved = resolve_headers(Some(&headers));
        assert_eq!(resolved.get("x-key").unwrap(), "literal-value");
    }

    // ─── ModelRegistry ───────────────────────────────────────────────

    #[test]
    fn model_registry_get_available_filters_by_api_key() {
        let (_dir, auth) = test_auth_storage();
        let registry = ModelRegistry::load(&auth, None);
        let available = registry.get_available();
        assert!(!available.is_empty());
        for entry in &available {
            assert!(
                entry.api_key.is_some(),
                "all available models should have api_key"
            );
        }
    }

    #[test]
    fn model_registry_error_none_for_valid_load() {
        let (_dir, auth) = test_auth_storage();
        let registry = ModelRegistry::load(&auth, None);
        assert!(registry.error().is_none());
    }

    #[test]
    fn model_registry_error_on_invalid_json() {
        let dir = tempdir().expect("tempdir");
        let auth = AuthStorage::load(dir.path().join("auth.json")).expect("auth");
        let models_path = dir.path().join("models.json");
        std::fs::write(&models_path, "not valid json").expect("write bad json");
        let registry = ModelRegistry::load(&auth, Some(models_path));
        assert!(registry.error().is_some());
    }

    #[test]
    fn model_registry_load_missing_models_json_is_fine() {
        let dir = tempdir().expect("tempdir");
        let auth = AuthStorage::load(dir.path().join("auth.json")).expect("auth");
        let registry = ModelRegistry::load(&auth, Some(dir.path().join("nonexistent.json")));
        assert!(registry.error().is_none());
    }

    // ─── default_models_path ─────────────────────────────────────────

    #[test]
    fn default_models_path_joins_correctly() {
        let path = default_models_path(Path::new("/home/user/.pi"));
        assert_eq!(path, PathBuf::from("/home/user/.pi/models.json"));
    }

    // ─── ModelsConfig deserialization ────────────────────────────────

    #[test]
    fn models_config_deserialize_camel_case() {
        let json = r#"{
            "providers": {
                "acme": {
                    "baseUrl": "https://acme.com/v1",
                    "apiKey": "env:ACME_KEY",
                    "authHeader": true,
                    "models": [{
                        "id": "acme-1",
                        "contextWindow": 32000,
                        "maxTokens": 2048
                    }]
                }
            }
        }"#;
        let config: ModelsConfig = serde_json::from_str(json).expect("parse");
        let acme = config.providers.get("acme").expect("acme provider");
        assert_eq!(acme.base_url.as_deref(), Some("https://acme.com/v1"));
        assert_eq!(acme.auth_header, Some(true));
        let model = &acme.models.as_ref().unwrap()[0];
        assert_eq!(model.context_window, Some(32000));
        assert_eq!(model.max_tokens, Some(2048));
    }

    #[test]
    fn models_config_empty_providers_ok() {
        let json = r#"{"providers": {}}"#;
        let config: ModelsConfig = serde_json::from_str(json).expect("parse");
        assert!(config.providers.is_empty());
    }

    #[test]
    fn compat_config_deserialize() {
        let json = r#"{
            "supportsStore": true,
            "supportsDeveloperRole": false,
            "supportsReasoningEffort": true,
            "supportsUsageInStreaming": false,
            "maxTokensField": "max_completion_tokens"
        }"#;
        let compat: CompatConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(compat.supports_store, Some(true));
        assert_eq!(compat.supports_developer_role, Some(false));
        assert_eq!(compat.supports_reasoning_effort, Some(true));
        assert_eq!(compat.supports_usage_in_streaming, Some(false));
        assert_eq!(
            compat.max_tokens_field.as_deref(),
            Some("max_completion_tokens")
        );
    }

    #[test]
    fn compat_config_deserialize_all_fields() {
        let json = r#"{
            "supportsStore": true,
            "supportsDeveloperRole": true,
            "supportsReasoningEffort": false,
            "supportsUsageInStreaming": false,
            "supportsTools": false,
            "supportsStreaming": true,
            "supportsParallelToolCalls": false,
            "maxTokensField": "max_completion_tokens",
            "systemRoleName": "developer",
            "stopReasonField": "finish_reason",
            "customHeaders": {"X-Region": "us-east-1", "X-Tag": "override"},
            "openRouterRouting": {"order": ["fallback"]},
            "vercelGatewayRouting": {"priority": 1}
        }"#;
        let compat: CompatConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(compat.supports_tools, Some(false));
        assert_eq!(compat.supports_streaming, Some(true));
        assert_eq!(compat.supports_parallel_tool_calls, Some(false));
        assert_eq!(compat.system_role_name.as_deref(), Some("developer"));
        assert_eq!(compat.stop_reason_field.as_deref(), Some("finish_reason"));
        let custom = compat.custom_headers.as_ref().expect("custom_headers");
        assert_eq!(
            custom.get("X-Region").map(String::as_str),
            Some("us-east-1")
        );
        assert_eq!(custom.get("X-Tag").map(String::as_str), Some("override"));
        assert!(compat.open_router_routing.is_some());
        assert!(compat.vercel_gateway_routing.is_some());
    }

    #[test]
    fn compat_config_default_all_none() {
        let compat = CompatConfig::default();
        assert!(compat.supports_store.is_none());
        assert!(compat.supports_tools.is_none());
        assert!(compat.supports_streaming.is_none());
        assert!(compat.max_tokens_field.is_none());
        assert!(compat.system_role_name.is_none());
        assert!(compat.stop_reason_field.is_none());
        assert!(compat.custom_headers.is_none());
    }

    #[test]
    fn compat_config_deserialize_empty_object() {
        let compat: CompatConfig = serde_json::from_str("{}").expect("parse");
        assert!(compat.supports_store.is_none());
        assert!(compat.supports_tools.is_none());
        assert!(compat.custom_headers.is_none());
    }

    // ─── apply_custom_models: provider replaces built-ins ────────────

    #[test]
    fn apply_custom_models_replaces_built_in_when_models_specified() {
        let (_dir, auth) = test_auth_storage();
        let mut models = built_in_models(&auth);
        let anthropic_before = models
            .iter()
            .filter(|m| m.model.provider == "anthropic")
            .count();
        assert!(anthropic_before > 0);

        let config = ModelsConfig {
            providers: HashMap::from([(
                "anthropic".to_string(),
                ProviderConfig {
                    base_url: Some("https://proxy.example/v1".to_string()),
                    api: Some("anthropic-messages".to_string()),
                    models: Some(vec![ModelConfig {
                        id: "custom-claude".to_string(),
                        name: Some("Custom Claude".to_string()),
                        ..ModelConfig::default()
                    }]),
                    ..ProviderConfig::default()
                },
            )]),
        };

        apply_custom_models(&auth, &mut models, &config);

        // Built-in anthropic models should be replaced
        let anthropic_after: Vec<_> = models
            .iter()
            .filter(|m| m.model.provider == "anthropic")
            .collect();
        assert_eq!(anthropic_after.len(), 1);
        assert_eq!(anthropic_after[0].model.id, "custom-claude");
    }

    // ─── OAuthConfig ─────────────────────────────────────────────────

    #[test]
    fn oauth_config_fields() {
        let config = OAuthConfig {
            auth_url: "https://auth.example.com/authorize".to_string(),
            token_url: "https://auth.example.com/token".to_string(),
            client_id: "client-123".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            redirect_uri: Some("http://localhost:8080/callback".to_string()),
        };
        assert_eq!(config.client_id, "client-123");
        assert_eq!(config.scopes.len(), 2);
        assert!(config.redirect_uri.is_some());
    }

    // ─── Built-in model properties ───────────────────────────────────

    #[test]
    fn built_in_anthropic_models_use_correct_api() {
        let (_dir, auth) = test_auth_storage();
        let models = built_in_models(&auth);
        for m in models.iter().filter(|m| m.model.provider == "anthropic") {
            assert_eq!(m.model.api, "anthropic-messages");
            assert!(!m.auth_header, "anthropic uses x-api-key, not auth header");
            assert_eq!(m.model.context_window, 200_000);
        }
    }

    #[test]
    fn built_in_openai_models_use_auth_header() {
        let (_dir, auth) = test_auth_storage();
        let models = built_in_models(&auth);
        for m in models.iter().filter(|m| m.model.provider == "openai") {
            assert!(m.auth_header, "openai uses Authorization header");
            assert_eq!(m.model.api, "openai-responses");
        }
    }

    #[test]
    fn built_in_google_models_no_auth_header() {
        let (_dir, auth) = test_auth_storage();
        let models = built_in_models(&auth);
        for m in models.iter().filter(|m| m.model.provider == "google") {
            assert!(!m.auth_header, "google uses api key in URL, not header");
            assert_eq!(m.model.api, "google-generative-ai");
        }
    }

    #[test]
    fn built_in_reasoning_models_marked_correctly() {
        let (_dir, auth) = test_auth_storage();
        let models = built_in_models(&auth);
        // Haiku models are non-reasoning
        for m in models.iter().filter(|m| m.model.id.contains("haiku")) {
            assert!(
                !m.model.reasoning || m.model.id.contains("3-5-haiku"),
                "haiku 3.5 is non-reasoning, but {}: reasoning={}",
                m.model.id,
                m.model.reasoning
            );
        }
        // Opus/Sonnet models are reasoning
        for m in models
            .iter()
            .filter(|m| m.model.id.contains("opus") || m.model.id.contains("sonnet"))
        {
            assert!(m.model.reasoning, "{} should be reasoning", m.model.id);
        }
    }
}
