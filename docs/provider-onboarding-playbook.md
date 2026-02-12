# Provider Onboarding Playbook

This playbook is the execution-focused companion to `providers.md`.

Use it when you need to:
- onboard a provider configuration quickly,
- debug provider auth/routing failures without guesswork, and
- add or update provider support without creating metadata/factory drift.

Primary bead coverage:
- `bd-3uqg.9` (parent)
- working draft support for `bd-3uqg.9.2` and `bd-3uqg.9.3`

## Scope and source of truth

Use these files as authoritative:
- Provider metadata (canonical IDs, aliases, env keys, routing defaults): `../src/provider_metadata.rs`
- Runtime route selection and provider factory dispatch: `../src/providers/mod.rs`
- API key resolution precedence: `../src/app.rs`, `../src/auth.rs`, `../src/models.rs`
- Existing provider baseline and matrix: `providers.md`
- Error-hint taxonomy and remediation messages: `../src/error.rs`

Use these tests/artifacts as verification anchors:
- Factory/routing behavior: `../tests/provider_factory.rs`
- Metadata invariants and alias correctness: `../tests/provider_metadata_comprehensive.rs`
- Streaming/provider contracts: `../tests/provider_streaming.rs`
- Live parity/artifact lanes: `../tests/e2e_cross_provider_parity.rs`, `../tests/e2e_live_harness.rs`, `../tests/e2e_live.rs`

## Runtime model: how provider selection actually works

Selection pipeline:
1. Model entry is chosen (`--provider/--model`, defaults, or scoped models) in `../src/app.rs`.
2. API key resolution is attempted in this order:
   - `--api-key`
   - provider env vars (`provider_auth_env_keys` via `../src/provider_metadata.rs`)
   - `auth.json`
   - `models.json` `providers.<id>.apiKey` (fallback)
3. Provider route is selected in `resolve_provider_route(...)` in `../src/providers/mod.rs`.
4. A concrete provider implementation is created in `create_provider(...)`.

Important caveat:
- `github-copilot` currently reads `GITHUB_COPILOT_API_KEY` / `GITHUB_TOKEN` directly in `create_provider(...)`. For Copilot, setting only `models.json` `apiKey` is not sufficient.

## Provider family map

| Family | Typical canonical IDs | Route style | Core config surface |
|---|---|---|---|
| Built-in native | `anthropic`, `openai`, `google`, `cohere` | Native provider modules | Usually `--provider/--model` + env key |
| OpenAI-compatible presets | `openrouter`, `xai`, `deepseek`, `groq`, `cloudflare-ai-gateway`, `cloudflare-workers-ai`, etc. | API fallback to `openai-completions` | Provider metadata defaults + standard bearer auth |
| Native adapters | `azure-openai`, `google-vertex`, `github-copilot`, `gitlab`, `amazon-bedrock`, `sap-ai-core` | Dedicated adapter route in factory | Provider-specific env/config requirements |

## Copy-paste configuration examples

### 1) Built-in native providers (quick CLI)

```bash
export ANTHROPIC_API_KEY="..."
export OPENAI_API_KEY="..."
export GOOGLE_API_KEY="..."
export COHERE_API_KEY="..."

pi --provider anthropic --model claude-sonnet-4-5 -p "Say hello"
pi --provider openai --model gpt-4o-mini -p "Say hello"
pi --provider google --model gemini-2.5-flash -p "Say hello"
pi --provider cohere --model command-r-plus -p "Say hello"
```

Expected check:
- Command returns model text output with no provider/auth error.

### 2) OpenAI-compatible preset providers (`models.json` optional)

Minimal env-only path (example: OpenRouter):

```bash
export OPENROUTER_API_KEY="..."
pi --provider openrouter --model openai/gpt-4o-mini -p "Say hello"
```

Optional explicit config (example: Cloudflare AI Gateway):

```json
{
  "providers": {
    "cloudflare-ai-gateway": {
      "baseUrl": "https://gateway.ai.cloudflare.com/v1/<account_id>/<gateway_id>/openai",
      "models": [
        { "id": "gpt-4o-mini" }
      ]
    }
  }
}
```

```bash
export CLOUDFLARE_API_TOKEN="..."
pi --provider cloudflare-ai-gateway --model gpt-4o-mini -p "Say hello"
```

Expected check:
- Factory resolves to `openai-completions` route for these providers (see `../tests/provider_factory.rs`).

Wave A verification lock for the preset family (`bd-3uqg.4.4`):
- `wave_a_presets_resolve_openai_compat_defaults_and_factory_route`
- `wave_a_openai_compat_streams_use_chat_completions_path_and_bearer_auth`

### 2a) Alias migration example (`fireworks-ai` -> `fireworks`)

Legacy config (still supported):

```json
{
  "providers": {
    "fireworks-ai": {
      "models": [
        { "id": "accounts/fireworks/models/llama-v3p3-70b-instruct" }
      ]
    }
  }
}
```

Recommended config (canonical):

```json
{
  "providers": {
    "fireworks": {
      "models": [
        { "id": "accounts/fireworks/models/llama-v3p3-70b-instruct" }
      ]
    }
  }
}
```

Migration behavior guarantees:
- Both IDs resolve to `openai-completions` with base `https://api.fireworks.ai/inference/v1`.
- Both IDs use the same auth env mapping (`FIREWORKS_API_KEY`).
- Alias parity is lock-tested in `fireworks_ai_alias_migration_matches_fireworks_canonical_defaults`.

### 2b) Wave B1 canonical IDs (regional + coding-plan)

Batch B1 lock tests (`bd-3uqg.5.2`):
- `wave_b1_presets_resolve_metadata_defaults_and_factory_route`
- `wave_b1_alibaba_cn_openai_compat_streams_use_chat_completions_path_and_bearer_auth`
- `wave_b1_anthropic_compat_streams_use_messages_path_and_x_api_key`
- `wave_b1_family_coherence_with_existing_moonshot_and_alibaba_mappings`

Representative smoke/e2e checks (`provider_native_verify`):
- `wave_b1_smoke::b1_alibaba_cn_{simple_text,tool_call_single,error_auth_401}`
- `wave_b1_smoke::b1_kimi_for_coding_{simple_text,tool_call_single,error_auth_401}`
- `wave_b1_smoke::b1_minimax_{simple_text,tool_call_single,error_auth_401}`
- Command: `cargo test --test provider_native_verify b1_ -- --nocapture`
- Generated fixtures:
  `tests/fixtures/vcr/verify_alibaba-cn_*.json`,
  `tests/fixtures/vcr/verify_kimi-for-coding_*.json`,
  `tests/fixtures/vcr/verify_minimax_*.json`.

Key mapping decisions:
- `kimi` remains an alias of canonical `moonshotai`.
- `kimi-for-coding` is distinct and routes to Anthropic-compatible path with `KIMI_API_KEY`.
- `alibaba-cn` is distinct from `alibaba`/`dashscope` and uses CN DashScope base URL.
- `minimax*` variants are distinct canonical IDs with shared family auth/env mapping:
  `MINIMAX_API_KEY` for global, `MINIMAX_CN_API_KEY` for CN.

Representative `models.json` snippet:

```json
{
  "providers": {
    "alibaba-cn": {
      "models": [{ "id": "qwen-plus" }]
    },
    "kimi-for-coding": {
      "models": [{ "id": "k2p5" }]
    },
    "minimax-coding-plan": {
      "models": [{ "id": "MiniMax-M2.1" }]
    }
  }
}
```

### 2c) Wave B2 canonical IDs (regional + cloud OpenAI-compatible)

Batch B2 lock tests (`bd-3uqg.5.1`):
- `wave_b2_presets_resolve_metadata_defaults_and_factory_route`
- `wave_b2_openai_compat_streams_use_chat_completions_path_and_bearer_auth`
- `wave_b2_moonshot_cn_and_global_moonshot_mapping_are_distinct`

Representative smoke/e2e checks (`provider_native_verify`):
- `wave_b2_smoke::b2_modelscope_{simple_text,tool_call_single,error_auth_401}`
- `wave_b2_smoke::b2_moonshotai_cn_{simple_text,tool_call_single,error_auth_401}`
- `wave_b2_smoke::b2_nebius_{simple_text,tool_call_single,error_auth_401}`
- `wave_b2_smoke::b2_ovhcloud_{simple_text,tool_call_single,error_auth_401}`
- `wave_b2_smoke::b2_scaleway_{simple_text,tool_call_single,error_auth_401}`
- Command: `cargo test --test provider_native_verify b2_ -- --nocapture`
- Generated fixtures:
  `tests/fixtures/vcr/verify_modelscope_*.json`,
  `tests/fixtures/vcr/verify_moonshotai-cn_*.json`,
  `tests/fixtures/vcr/verify_nebius_*.json`,
  `tests/fixtures/vcr/verify_ovhcloud_*.json`,
  `tests/fixtures/vcr/verify_scaleway_*.json`.

Key mapping decisions:
- `modelscope`, `nebius`, `ovhcloud`, and `scaleway` are onboarded as canonical OpenAI-compatible preset IDs.
- `moonshotai-cn` is a distinct canonical regional ID and does not alias to `moonshotai`.
- `moonshotai` and `moonshotai-cn` intentionally share `MOONSHOT_API_KEY` while retaining distinct base URLs.

Representative `models.json` snippet:

```json
{
  "providers": {
    "modelscope": {
      "models": [{ "id": "ZhipuAI/GLM-4.5" }]
    },
    "moonshotai-cn": {
      "models": [{ "id": "kimi-k2-0905-preview" }]
    },
    "nebius": {
      "models": [{ "id": "NousResearch/hermes-4-70b" }]
    },
    "ovhcloud": {
      "models": [{ "id": "mixtral-8x7b-instruct-v0.1" }]
    },
    "scaleway": {
      "models": [{ "id": "qwen3-235b-a22b-instruct-2507" }]
    }
  }
}
```

### 2d) Wave B3 canonical IDs (regional + coding-plan OpenAI-compatible)

Batch B3 lock tests (`bd-3uqg.5.3`):
- `wave_b3_presets_resolve_metadata_defaults_and_factory_route`
- `wave_b3_openai_compat_streams_use_chat_completions_path_and_bearer_auth`
- `wave_b3_family_and_coding_plan_variants_are_distinct`
- `ad_hoc_batch_b3_defaults_resolve_expected_routes`
- `ad_hoc_batch_b3_coding_plan_and_regional_variants_remain_distinct`

Representative smoke/e2e checks (`provider_native_verify`):
- `wave_b3_smoke::b3_siliconflow_{simple_text,tool_call_single,error_auth_401}`
- `wave_b3_smoke::b3_siliconflow_cn_{simple_text,tool_call_single,error_auth_401}`
- `wave_b3_smoke::b3_upstage_{simple_text,tool_call_single,error_auth_401}`
- `wave_b3_smoke::b3_venice_{simple_text,tool_call_single,error_auth_401}`
- `wave_b3_smoke::b3_zai_{simple_text,tool_call_single,error_auth_401}`
- `wave_b3_smoke::b3_zai_coding_{simple_text,tool_call_single,error_auth_401}`
- `wave_b3_smoke::b3_zhipuai_{simple_text,tool_call_single,error_auth_401}`
- `wave_b3_smoke::b3_zhipuai_coding_{simple_text,tool_call_single,error_auth_401}`
- Command: `cargo test --test provider_native_verify b3_ -- --nocapture`
- Generated fixtures:
  `tests/fixtures/vcr/verify_siliconflow_*.json`,
  `tests/fixtures/vcr/verify_siliconflow-cn_*.json`,
  `tests/fixtures/vcr/verify_upstage_*.json`,
  `tests/fixtures/vcr/verify_venice_*.json`,
  `tests/fixtures/vcr/verify_zai_*.json`,
  `tests/fixtures/vcr/verify_zai-coding-plan_*.json`,
  `tests/fixtures/vcr/verify_zhipuai_*.json`,
  `tests/fixtures/vcr/verify_zhipuai-coding-plan_*.json`.

Key mapping decisions:
- `siliconflow` and `siliconflow-cn` are distinct canonical regional IDs with separate auth env keys (`SILICONFLOW_API_KEY`, `SILICONFLOW_CN_API_KEY`).
- `zai` and `zai-coding-plan` are distinct canonical IDs sharing `ZHIPU_API_KEY` but using different base URLs.
- `zhipuai` and `zhipuai-coding-plan` are distinct canonical IDs sharing `ZHIPU_API_KEY` but using different base URLs.

Representative `models.json` snippet:

```json
{
  "providers": {
    "siliconflow": {
      "models": [{ "id": "Qwen/Qwen3-Coder-480B-A35B-Instruct" }]
    },
    "upstage": {
      "models": [{ "id": "solar-pro2" }]
    },
    "venice": {
      "models": [{ "id": "venice-uncensored" }]
    },
    "zai-coding-plan": {
      "models": [{ "id": "glm-4.5" }]
    },
    "zhipuai-coding-plan": {
      "models": [{ "id": "glm-4.5" }]
    }
  }
}
```

### 2e) Wave C canonical IDs (local/self-hosted/gateway staging)

Source for defaults in this section:
- `https://models.dev/api.json` (queried on 2026-02-12)
- Extraction command:

```bash
curl -s https://models.dev/api.json | jq '{
  baseten: {api: ."baseten".api, env: ."baseten".env},
  llama: {api: ."llama".api, env: ."llama".env},
  lmstudio: {api: ."lmstudio".api, env: ."lmstudio".env},
  "ollama-cloud": {api: ."ollama-cloud".api, env: ."ollama-cloud".env},
  opencode: {api: ."opencode".api, env: ."opencode".env},
  vercel: {api: ."vercel".api, env: ."vercel".env},
  zenmux: {api: ."zenmux".api, env: ."zenmux".env}
}'
```

Current Wave C routing stance:
- `baseten`, `llama`, `lmstudio`, and `ollama-cloud` are onboarded as OpenAI-compatible presets (metadata + factory verified, VCR pending).
- `opencode` and `vercel` are onboarded as OpenAI-compatible presets with VCR verification (3 scenarios each).
- `zenmux` is onboarded as an Anthropic-compatible preset with VCR verification (3 scenarios).

Wave C defaults (from `models.dev`):

| Provider ID | API family target | Default base URL | Auth env |
|---|---|---|---|
| `baseten` | `openai-completions` | `https://inference.baseten.co/v1` | `BASETEN_API_KEY` |
| `llama` | `openai-completions` | `https://api.llama.com/compat/v1/` | `LLAMA_API_KEY` |
| `lmstudio` | `openai-completions` | `http://127.0.0.1:1234/v1` | `LMSTUDIO_API_KEY` |
| `ollama-cloud` | `openai-completions` | `https://ollama.com/v1` | `OLLAMA_API_KEY` |
| `opencode` | `openai-completions` | `https://opencode.ai/zen/v1` | `OPENCODE_API_KEY` |
| `vercel` | gateway-wrapper (`@ai-sdk/gateway`) | no static API URL in `models.dev` | `AI_GATEWAY_API_KEY` |
| `zenmux` | `anthropic-messages` target (Anthropic-style gateway) | `https://zenmux.ai/api/anthropic/v1` | `ZENMUX_API_KEY` |

Representative `models.json` for unblocked Wave C presets:

```json
{
  "providers": {
    "baseten": {
      "models": [{ "id": "moonshotai/Kimi-K2-Instruct-0905" }]
    },
    "llama": {
      "models": [{ "id": "llama-3.3-70b-instruct" }]
    },
    "lmstudio": {
      "models": [{ "id": "openai/gpt-oss-20b" }]
    },
    "ollama-cloud": {
      "models": [{ "id": "glm-4.7" }]
    }
  }
}
```

Special-routing status:
- `opencode`, `vercel`, and `zenmux` are now onboarded and VCR-verified as preset providers.
- VCR cassettes: `tests/fixtures/vcr/verify_opencode_*.json`, `tests/fixtures/vcr/verify_vercel_*.json`, `tests/fixtures/vcr/verify_zenmux_*.json`.

### 3) Azure OpenAI (`azure-openai` / aliases `azure`, `azure-cognitive-services`)

```json
{
  "providers": {
    "azure-openai": {
      "baseUrl": "https://<resource>.openai.azure.com",
      "models": [
        { "id": "gpt-4o" }
      ]
    }
  }
}
```

```bash
export AZURE_OPENAI_API_KEY="..."
# Optional overrides used by runtime resolver:
# export AZURE_OPENAI_RESOURCE="<resource>"
# export AZURE_OPENAI_DEPLOYMENT="<deployment>"
# export AZURE_OPENAI_API_VERSION="2024-08-01-preview"

pi --provider azure-openai --model gpt-4o -p "Say hello"
```

Expected check:
- Route is native Azure path.
- Missing deployment/resource failures include explicit remediation text from `resolve_azure_provider_runtime(...)` in `../src/providers/mod.rs`.

### 4) Google Vertex (`google-vertex` / alias `vertexai`)

Recommended explicit base URL shape:

```json
{
  "providers": {
    "google-vertex": {
      "baseUrl": "https://us-central1-aiplatform.googleapis.com/v1/projects/<project>/locations/us-central1/publishers/google/models/gemini-2.0-flash",
      "models": [
        { "id": "gemini-2.0-flash", "api": "google-vertex" }
      ]
    }
  }
}
```

```bash
export GOOGLE_CLOUD_API_KEY="..."   # or VERTEX_API_KEY
export GOOGLE_CLOUD_PROJECT="<project>"   # optional if embedded in baseUrl
export GOOGLE_CLOUD_LOCATION="us-central1" # optional if embedded in baseUrl

pi --provider google-vertex --model gemini-2.0-flash -p "Say hello"
```

Expected check:
- Provider route is native vertex.
- Missing project/auth errors match messages in `../src/providers/vertex.rs`.

### 5) GitHub Copilot (`github-copilot` / alias `copilot`)

```json
{
  "providers": {
    "github-copilot": {
      "baseUrl": "https://api.github.com",
      "models": [
        { "id": "gpt-4o" }
      ]
    }
  }
}
```

```bash
export GITHUB_TOKEN="..."   # or GITHUB_COPILOT_API_KEY
pi --provider github-copilot --model gpt-4o -p "Say hello"
```

Expected check:
- Provider performs token exchange against GitHub API before chat call.
- If token exchange fails, error contains Copilot-specific diagnostic context.

### 6) GitLab Duo (`gitlab` / alias `gitlab-duo`)

```json
{
  "providers": {
    "gitlab": {
      "baseUrl": "https://gitlab.com",
      "models": [
        { "id": "gitlab-duo-chat", "api": "gitlab-chat" }
      ]
    }
  }
}
```

```bash
export GITLAB_TOKEN="..."   # or GITLAB_API_KEY
pi --provider gitlab --model gitlab-duo-chat -p "Say hello"
```

Expected check:
- Provider sends request to `/api/v4/chat/completions` and returns a non-streaming done event path.

### 7) Bedrock / SAP AI Core (native adapters - VCR-verified)

Current status:
- `amazon-bedrock` and `sap-ai-core` are classified as `native-adapter-required` and are now VCR-verified.
- Auth/env mapping exists in `../src/provider_metadata.rs` and `../src/auth.rs`.
- VCR cassettes: `tests/fixtures/vcr/verify_bedrock_*.json` (4 scenarios), `tests/fixtures/vcr/verify_sap_ai_core_*.json` (6 scenarios).
- Parity evidence: [`docs/provider-native-parity-report.json`](provider-native-parity-report.json).

Bedrock auth:
- SigV4 credentials: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- Bearer token alternative: `AWS_BEARER_TOKEN_BEDROCK`

SAP AI Core auth:
- OAuth2 client credentials: `SAP_AI_CORE_CLIENT_ID`, `SAP_AI_CORE_CLIENT_SECRET`, `SAP_AI_CORE_TOKEN_URL`

## Troubleshooting matrix (symptom -> action)

| Symptom | Fast diagnosis | Remediation |
|---|---|---|
| `Missing API key` / auth error at startup | Check provider env key mapping in `provider_auth_env_keys(...)` | Set provider env var, or `--api-key`, or persisted `auth.json`; re-run |
| `Provider not implemented (api: ...)` | Route fell through unknown provider/api in `resolve_provider_route(...)` | Fix provider ID/api in `models.json`; verify canonical ID or alias in `../src/provider_metadata.rs` |
| Azure missing resource/deployment | Resolver could not infer `resource` / `deployment` from base URL/env | Set `AZURE_OPENAI_RESOURCE`, `AZURE_OPENAI_DEPLOYMENT`, or include full Azure host/deployments path |
| Vertex missing project | Project not in base URL and not in env | Set `GOOGLE_CLOUD_PROJECT` or `VERTEX_PROJECT`; or encode project in base URL |
| Vertex missing token | No `api_key` and no `GOOGLE_CLOUD_API_KEY`/`VERTEX_API_KEY` | Set one of those env vars (bearer token/access token) |
| Copilot auth failure | GitHub token missing/invalid or token exchange rejected | Set `GITHUB_COPILOT_API_KEY`/`GITHUB_TOKEN`; verify Copilot entitlement |
| GitLab auth failure | Missing or invalid PAT/OAuth token | Set `GITLAB_TOKEN` or `GITLAB_API_KEY`; validate instance URL and scopes |
| 429/quota/5xx | Provider-side limit or outage | Retry policy tuning in settings, reduce request size, or switch model/provider |

## OAuth and login caveat

Interactive slash help currently advertises `/login` as Anthropic-first (`../src/interactive.rs`).
For non-Anthropic providers, prefer explicit env/auth.json setup unless extension/provider-specific OAuth wiring is confirmed in your target flow.

## Validation commands for doc and onboarding changes

Targeted checks (fast):

```bash
cargo test provider_factory -- --nocapture
cargo test provider_metadata_comprehensive -- --nocapture
```

Broader quality gates:

```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Live parity lanes (gated, real APIs):

```bash
CI_E2E_TESTS=1 cargo test e2e_cross_provider_parity -- --nocapture
CI_E2E_TESTS=1 cargo test e2e_live_harness -- --nocapture
```

## Contributor checklist (new provider or major provider update)

1. Add or update canonical metadata entry in `../src/provider_metadata.rs`.
2. Ensure alias resolution + env key mapping are covered by tests.
3. Wire route and provider factory behavior in `../src/providers/mod.rs`.
4. Add/update provider-specific tests:
   - factory selection,
   - metadata invariants,
   - streaming contract behavior.
5. Update docs:
   - `providers.md` (matrix/status)
   - this playbook (config/troubleshooting)
6. Attach evidence links (tests + artifact outputs) before closing provider-doc beads.

## Current evidence-backed limits

The canonical matrix/evidence table in `providers.md` is under active parallel edits. Treat that file as the source for final matrix status, and this playbook as the operational implementation guide for onboarding and troubleshooting.
