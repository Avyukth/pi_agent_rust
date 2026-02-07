//! Model registry: built-in + models.json overrides.

use crate::auth::AuthStorage;
use crate::error::Error;
use crate::provider::{Api, InputType, Model, ModelCost};
use serde::Deserialize;
use std::collections::HashMap;
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
    pub supports_store: Option<bool>,
    pub supports_developer_role: Option<bool>,
    pub supports_reasoning_effort: Option<bool>,
    pub supports_usage_in_streaming: Option<bool>,
    pub max_tokens_field: Option<String>,
    pub open_router_routing: Option<serde_json::Value>,
    pub vercel_gateway_routing: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct ModelRegistry {
    models: Vec<ModelEntry>,
    error: Option<String>,
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
        self.models
            .iter()
            .find(|m| m.model.provider == provider && m.model.id == id)
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

    models
}

#[allow(clippy::too_many_lines)]
fn apply_custom_models(auth: &AuthStorage, models: &mut Vec<ModelEntry>, config: &ModelsConfig) {
    for (provider_id, provider_cfg) in &config.providers {
        let provider_api = provider_cfg.api.as_deref().unwrap_or("openai-completions");
        let provider_api_parsed: Api = provider_api
            .parse()
            .unwrap_or_else(|_| Api::Custom(provider_api.to_string()));
        let provider_api_string = provider_api_parsed.to_string();
        let provider_base = provider_cfg
            .base_url
            .clone()
            .unwrap_or_else(|| "https://api.openai.com/v1".to_string());

        let provider_headers = resolve_headers(provider_cfg.headers.as_ref());
        let provider_key = provider_cfg
            .api_key
            .as_deref()
            .and_then(resolve_value)
            .or_else(|| auth.resolve_api_key(provider_id, None));

        let auth_header = provider_cfg.auth_header.unwrap_or(false);

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

        for model_cfg in provider_cfg.models.clone().unwrap_or_default() {
            let model_api = model_cfg.api.as_deref().unwrap_or(provider_api);
            let model_api_parsed: Api = model_api
                .parse()
                .unwrap_or_else(|_| Api::Custom(model_api.to_string()));
            let model_headers = merge_headers(
                &provider_headers,
                resolve_headers(model_cfg.headers.as_ref()),
            );
            let input = model_cfg
                .input
                .clone()
                .unwrap_or_else(|| vec!["text".to_string()]);

            let input_types = input
                .iter()
                .filter_map(|i| match i.as_str() {
                    "text" => Some(InputType::Text),
                    "image" => Some(InputType::Image),
                    _ => None,
                })
                .collect::<Vec<_>>();

            let model = Model {
                id: model_cfg.id.clone(),
                name: model_cfg
                    .name
                    .clone()
                    .unwrap_or_else(|| model_cfg.id.clone()),
                api: model_api_parsed.to_string(),
                provider: provider_id.clone(),
                base_url: provider_base.clone(),
                reasoning: model_cfg.reasoning.unwrap_or(false),
                input: if input_types.is_empty() {
                    vec![InputType::Text]
                } else {
                    input_types
                },
                cost: model_cfg.cost.clone().unwrap_or(ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                }),
                context_window: model_cfg.context_window.unwrap_or(128_000),
                max_tokens: model_cfg.max_tokens.unwrap_or(16_384),
                headers: HashMap::new(),
            };

            models.push(ModelEntry {
                model,
                api_key: provider_key.clone(),
                headers: model_headers,
                auth_header,
                compat: model_cfg
                    .compat
                    .clone()
                    .or_else(|| provider_cfg.compat.clone()),
                oauth_config: None,
            });
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
    reasoning: bool,
    input: &'static [InputType],
    context_window: u32,
    max_tokens: u32,
}

const INPUT_TEXT: [InputType; 1] = [InputType::Text];
const INPUT_TEXT_IMAGE: [InputType; 2] = [InputType::Text, InputType::Image];

#[allow(clippy::too_many_lines)]
fn ad_hoc_provider_defaults(provider: &str) -> Option<AdHocProviderDefaults> {
    match provider {
        // Built-in providers.
        "anthropic" => Some(AdHocProviderDefaults {
            api: "anthropic-messages",
            base_url: "https://api.anthropic.com/v1/messages",
            reasoning: true,
            input: &INPUT_TEXT_IMAGE,
            context_window: 200_000,
            max_tokens: 8192,
        }),
        "openai" => Some(AdHocProviderDefaults {
            api: "openai-responses",
            base_url: "https://api.openai.com/v1",
            reasoning: true,
            input: &INPUT_TEXT_IMAGE,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "google" => Some(AdHocProviderDefaults {
            api: "google-generative-ai",
            base_url: "https://generativelanguage.googleapis.com/v1beta",
            reasoning: true,
            input: &INPUT_TEXT_IMAGE,
            context_window: 128_000,
            max_tokens: 8192,
        }),
        "cohere" => Some(AdHocProviderDefaults {
            api: "cohere-chat",
            base_url: "https://api.cohere.com/v2",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 8192,
        }),

        // OpenAI-compatible providers (chat/completions).
        // Sources: Vercel AI SDK + opencode fixture.
        "groq" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.groq.com/openai/v1",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "deepinfra" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.deepinfra.com/v1/openai",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "cerebras" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.cerebras.ai/v1",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "openrouter" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://openrouter.ai/api/v1",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "mistral" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.mistral.ai/v1",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        // MoonshotAI is the API behind "Kimi".
        "moonshotai" | "moonshot" | "kimi" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.moonshot.ai/v1",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        // Qwen models via DashScope OpenAI-compatible endpoint.
        "alibaba" | "dashscope" | "qwen" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "deepseek" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.deepseek.com",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "fireworks" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.fireworks.ai/inference/v1",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "togetherai" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.together.xyz/v1",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "perplexity" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.perplexity.ai",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        "xai" => Some(AdHocProviderDefaults {
            api: "openai-completions",
            base_url: "https://api.x.ai/v1",
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        _ => None,
    }
}

pub(crate) fn ad_hoc_model_entry(provider: &str, model_id: &str) -> Option<ModelEntry> {
    let defaults = ad_hoc_provider_defaults(provider)?;
    Some(ModelEntry {
        model: Model {
            id: model_id.to_string(),
            name: model_id.to_string(),
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
        auth_header: defaults.api.starts_with("openai-"),
        compat: None,
        oauth_config: None,
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
        assert_eq!(anthropic.api_key.as_deref(), Some("anthropic-auth-key"));
        assert_eq!(openai.api_key.as_deref(), Some("openai-auth-key"));
        assert_eq!(google.api_key.as_deref(), Some("google-auth-key"));
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
