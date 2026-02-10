# Providers

This document is the canonical in-repo provider baseline for `pi_agent_rust`.
It summarizes provider IDs, aliases, API families, auth behavior, and current implementation mode.

Snapshot basis:
- `src/models.rs` (`built_in_models`, `ad_hoc_provider_defaults`)
- `src/auth.rs` (`env_keys_for_provider`)
- `src/providers/mod.rs` (`create_provider`, API fallback routing)
- `src/providers/*.rs` native implementations
- Timestamp: 2026-02-10

## Implementation Modes

| Mode | Meaning |
|------|---------|
| `native-implemented` | Provider has a direct runtime path in `create_provider` and is dispatchable now. |
| `native-partial` | Native module exists, but factory wiring or required config path is not fully integrated. |
| `oai-compatible-preset` | Provider resolves through OpenAI-compatible adapter (`openai-completions`) with preset base/auth defaults. |
| `alias-only` | Provider ID is a documented synonym of a canonical ID; no distinct runtime implementation. |
| `missing` | Provider ID is recognized in enums/auth mappings but has no usable runtime dispatch path yet. |

### Machine-Readable Classification (`bd-3uqg.1.4`)

Canonical planning artifact: `docs/provider-implementation-modes.json`

This JSON is the execution source-of-truth for provider onboarding mode selection:

| Mode | Planning Meaning |
|------|------------------|
| `native-adapter-required` | Requires dedicated runtime adapter path (protocol/auth/tool semantics not safely covered by generic OAI routing). |
| `oai-compatible-preset` | Can route through OpenAI-compatible adapter with provider-specific base/auth presets. |
| `gateway-wrapper-routing` | Acts as gateway/meta-router/alias-routing surface; prioritize routing-policy and diagnostics guarantees. |
| `deferred` | Explicitly not in current implementation wave; retained for planning completeness. |

Current artifact coverage (`docs/provider-implementation-modes.json`):
- 93 upstream union IDs classified (no gaps)
- 6 supplemental Pi alias IDs classified
- 99 total entries with explicit profile, rationale, and runtime status
- 20 high-risk providers carry explicit prerequisite beads + required diagnostic artifacts

## Canonical Provider Matrix (Current Baseline)

| Canonical ID | Aliases | API family | Base URL template | Auth mode | Mode | Runtime status | Required test tiers |
|--------------|---------|------------|-------------------|-----------|------|----------------|---------------------|
| `anthropic` | - | `anthropic-messages` | `https://api.anthropic.com/v1/messages` | `x-api-key` (`ANTHROPIC_API_KEY`) or `auth.json` OAuth/API key | `native-implemented` | Implemented and dispatchable | unit + contract + live-smoke |
| `openai` | - | `openai-responses` (default), `openai-completions` (compat) | `https://api.openai.com/v1` (normalized to `/responses` or `/chat/completions`) | `Authorization: Bearer` (`OPENAI_API_KEY`) | `native-implemented` | Implemented and dispatchable | unit + contract + live-smoke |
| `google` | `gemini` | `google-generative-ai` | `https://generativelanguage.googleapis.com/v1beta` | query key (`GOOGLE_API_KEY`, fallback `GEMINI_API_KEY`) | `native-implemented` | Implemented and dispatchable | unit + contract + live-smoke |
| `cohere` | - | `cohere-chat` | `https://api.cohere.com/v2` (normalized to `/chat`) | `Authorization: Bearer` (`COHERE_API_KEY`) | `native-implemented` | Implemented and dispatchable | unit + contract + live-smoke |
| `azure-openai` | `azure` | Azure chat/completions path | `https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version={version}` | `api-key` header (`AZURE_OPENAI_API_KEY`) | `native-partial` | Module exists; current factory path intentionally returns config/wiring error | unit + contract + live-smoke (after wiring) |
| `groq` | - | `openai-completions` | `https://api.groq.com/openai/v1` | `Authorization: Bearer` (`GROQ_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `deepinfra` | - | `openai-completions` | `https://api.deepinfra.com/v1/openai` | `Authorization: Bearer` (`DEEPINFRA_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `cerebras` | - | `openai-completions` | `https://api.cerebras.ai/v1` | `Authorization: Bearer` (`CEREBRAS_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `openrouter` | - | `openai-completions` | `https://openrouter.ai/api/v1` | `Authorization: Bearer` (`OPENROUTER_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `mistral` | - | `openai-completions` | `https://api.mistral.ai/v1` | `Authorization: Bearer` (`MISTRAL_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `moonshotai` | `moonshot`, `kimi` | `openai-completions` | `https://api.moonshot.ai/v1` | `Authorization: Bearer` (`MOONSHOT_API_KEY`) | `oai-compatible-preset` (`moonshot`,`kimi` are `alias-only`) | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `dashscope` | `alibaba`, `qwen` | `openai-completions` | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` | `Authorization: Bearer` (`DASHSCOPE_API_KEY`) | `oai-compatible-preset` (`alibaba`,`qwen` are `alias-only`) | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `deepseek` | - | `openai-completions` | `https://api.deepseek.com` | `Authorization: Bearer` (`DEEPSEEK_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `fireworks` | `fireworks-ai` | `openai-completions` | `https://api.fireworks.ai/inference/v1` | `Authorization: Bearer` (`FIREWORKS_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `togetherai` | - | `openai-completions` | `https://api.together.xyz/v1` | `Authorization: Bearer` (`TOGETHER_API_KEY`, alt `TOGETHER_AI_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `perplexity` | - | `openai-completions` | `https://api.perplexity.ai` | `Authorization: Bearer` (`PERPLEXITY_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |
| `xai` | - | `openai-completions` | `https://api.x.ai/v1` | `Authorization: Bearer` (`XAI_API_KEY`) | `oai-compatible-preset` | Dispatchable through OpenAI-compatible fallback | unit + contract + live-smoke |

## Missing/Partial IDs in Current Runtime

Provider IDs already recognized in auth/enums but not yet fully dispatchable:

| ID | Current state | User impact | Required follow-up |
|----|---------------|-------------|--------------------|
| `azure-openai` | `native-partial` (implementation exists, factory currently returns error) | Requires manual models/config and cannot use normal provider-name routing yet | Factory wiring + config validation + contract/e2e coverage |
| `google-vertex` (`vertexai`) | `missing` (enum/env mapping only) | Cannot route requests through a dedicated Vertex path | Add metadata + provider routing + tests |
| `amazon-bedrock` (`bedrock`) | `missing` (enum/env mapping only) | No Bedrock dispatch path despite enum/env references | Add native or adapter implementation + tests |
| `github-copilot` (`copilot`) | `missing` (enum/env mapping only) | No runtime provider selection path | Decide implementation mode + add tests/docs |

## Already-Covered vs Missing Snapshot

Covered now:
- 4 native dispatchable providers: `anthropic`, `openai`, `google`, `cohere`.
- 12 OpenAI-compatible preset providers dispatchable via fallback adapters:
  `groq`, `deepinfra`, `cerebras`, `openrouter`, `mistral`, `moonshotai`, `dashscope`,
  `deepseek`, `fireworks`, `togetherai`, `perplexity`, `xai`.
- Alias coverage built into preset defaults:
  `moonshot`/`kimi` -> `moonshotai`, and `alibaba`/`qwen` -> `dashscope`.

Not fully covered yet:
- 1 partial native path: `azure-openai`.
- 3 recognized-but-missing paths: `google-vertex`, `amazon-bedrock`, `github-copilot`.
- Additional upstream IDs from `models.dev + opencode + code` remain to be classified in the
  frozen upstream snapshot workflow (`bd-3uqg.1.1`).

## Provider Selection and Configuration

Credential resolution precedence (runtime):
1. explicit CLI override (`--api-key`)
2. provider env vars from metadata (ordered; includes shared fallbacks like `GOOGLE_API_KEY` then `GEMINI_API_KEY`)
3. persisted `auth.json` credential (`ApiKey` or unexpired OAuth `access_token`)
4. inline `models.json` `apiKey` fallback (resolved from literal/env/file/shell sources)

Choose provider/model via:
- CLI flags: `pi --provider openai --model gpt-4o "Hello"`
- Env vars: `PI_PROVIDER`, `PI_MODEL`
- Settings: `default_provider`, `default_model` in `~/.pi/agent/settings.json`

Custom endpoints and overrides should be configured in `models.json`:
- See [models.md](models.md) for schema and examples.

Example key exports:

```bash
export ANTHROPIC_API_KEY="..."
export OPENAI_API_KEY="..."
export GOOGLE_API_KEY="..."
export COHERE_API_KEY="..."
```
