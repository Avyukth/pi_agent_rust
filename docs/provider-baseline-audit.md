# Provider Baseline Audit (`bd-3uqg.1.2`)

Generated: `2026-02-10T04:35:00Z`
Upstream snapshot: `bd-3uqg.1.1` (93 canonical provider IDs)

## Executive Summary

| Category | Count | % of 93 upstream |
|----------|-------|-------------------|
| Fully supported (native module) | 7 | 7.5% |
| Ad-hoc supported (OAI-compatible preset) | 12 | 12.9% |
| Partially supported (auth/enum only) | 5 | 5.4% |
| Alias only | 1 | 1.1% |
| Missing | 68 | 73.1% |

**Effective coverage**: 19 providers usable today (20.4%), 5 more partially wired, 68 have zero support.

---

## Native Provider Modules (6 files, 7 structs)

| Provider | Struct | File | API Family | Auth Env Var |
|----------|--------|------|-----------|--------------|
| anthropic | `AnthropicProvider` | `src/providers/anthropic.rs` | anthropic-messages | `ANTHROPIC_API_KEY` |
| openai | `OpenAIProvider` | `src/providers/openai.rs` | openai-completions | `OPENAI_API_KEY` |
| openai | `OpenAIResponsesProvider` | `src/providers/openai_responses.rs` | openai-responses | `OPENAI_API_KEY` |
| google | `GeminiProvider` | `src/providers/gemini.rs` | google-generative-ai | `GOOGLE_API_KEY` |
| cohere | `CohereProvider` | `src/providers/cohere.rs` | cohere-chat | `COHERE_API_KEY` |
| azure-openai | `AzureOpenAIProvider` | `src/providers/azure.rs` | azure-openai-responses | `AZURE_OPENAI_API_KEY` |
| (extension) | `ExtensionStreamSimpleProvider` | `src/providers/mod.rs` | dynamic | dynamic |

---

## Ad-Hoc OpenAI-Compatible Providers (12)

Defined in `src/models.rs:ad_hoc_provider_defaults()`. All use `openai-completions` API family routed through `OpenAIProvider`.

| Provider ID | Pi Aliases | Base URL | Auth Env Var | Upstream Match |
|-------------|-----------|----------|--------------|----------------|
| groq | - | `api.groq.com/openai/v1` | `GROQ_API_KEY` | groq |
| deepinfra | - | `api.deepinfra.com/v1/openai` | `DEEPINFRA_API_KEY` | deepinfra |
| cerebras | - | `api.cerebras.ai/v1` | `CEREBRAS_API_KEY` | cerebras |
| openrouter | - | `openrouter.ai/api/v1` | `OPENROUTER_API_KEY` | openrouter |
| mistral | - | `api.mistral.ai/v1` | `MISTRAL_API_KEY` | mistral |
| moonshotai | moonshot, kimi | `api.moonshot.ai/v1` | `MOONSHOT_API_KEY` | moonshotai |
| alibaba | dashscope, qwen | `dashscope-intl.aliyuncs.com/compatible-mode/v1` | `DASHSCOPE_API_KEY` | alibaba |
| deepseek | - | `api.deepseek.com` | `DEEPSEEK_API_KEY` | deepseek |
| fireworks | - | `api.fireworks.ai/inference/v1` | `FIREWORKS_API_KEY` | fireworks-ai |
| togetherai | - | `api.together.xyz/v1` | `TOGETHER_API_KEY` | togetherai |
| perplexity | - | `api.perplexity.ai` | `PERPLEXITY_API_KEY` | perplexity |
| xai | - | `api.x.ai/v1` | `XAI_API_KEY` | xai |

---

## Partially Supported (auth/enum stubs, no module)

| Provider ID | What exists | What's missing |
|-------------|-------------|----------------|
| amazon-bedrock | Auth env var (`AWS_ACCESS_KEY_ID`), `Api::BedrockConverseStream` enum | No provider module |
| google-vertex | Auth env var (`GOOGLE_CLOUD_API_KEY`), `KnownProvider::GoogleVertex`, `Api::GoogleVertex` enum | No provider module |
| github-copilot | Auth env var (`GITHUB_COPILOT_API_KEY`), `KnownProvider::GithubCopilot` enum | No provider module |
| bedrock (opencode ID) | Same as amazon-bedrock | - |
| copilot (opencode ID) | Same as github-copilot | - |

---

## ID Mismatches Between Pi and Upstream

| Upstream ID | Pi ID | Source | Notes |
|------------|-------|--------|-------|
| azure | azure-openai | models.dev | Pi includes '-openai' suffix |
| fireworks-ai | fireworks | models.dev | Pi drops '-ai' suffix |
| amazon-bedrock / bedrock | - | models.dev / opencode | Different IDs in different sources |
| github-copilot / copilot | - | models.dev / opencode | Different IDs in different sources |
| google / gemini | google | models.dev / opencode | opencode uses product name 'gemini' |
| google-vertex / vertexai | - | models.dev / opencode | Different naming conventions |

---

## Factory Selection Logic (`src/providers/mod.rs:create_provider()`)

1. **Extension providers checked first**: `manager.provider_has_stream_simple(&provider_id)` -> `ExtensionStreamSimpleProvider`
2. **Match on `entry.model.provider`**: anthropic | openai (branches to completions/responses by api field) | cohere | google | azure-openai
3. **Fallback on `entry.model.api`**: anthropic-messages | openai-completions | openai-responses | cohere-chat | google-generative-ai
4. **Otherwise**: Error "Provider not implemented"

---

## Coverage by Upstream Source

| Source | Total IDs | Supported | Coverage |
|--------|-----------|-----------|----------|
| models.dev | 87 | 19 (native+ad-hoc) | 21.8% |
| opencode | 11 | 8 full + 3 partial | 72.7% |
| codex | 3 | 1 (openai) | 33.3% |

---

## Missing Providers (68 from upstream union)

High-value missing (in opencode or codex): `sap-ai-core`, `cloudflare-ai-gateway`, `cloudflare-workers-ai`, `gitlab`, `lmstudio`, `ollama`, `zenmux`, `opencode`, `vercel`

Other missing: 302ai, abacus, aihubmix, alibaba-cn, azure-cognitive-services, bailing, baseten, berget, chutes, cortecs, fastrouter, firmware, friendli, github-copilot-enterprise, github-models, google-vertex-anthropic, helicone, huggingface, iflowcn, inception, inference, io-net, jiekou, llama, lucidquery, minimax, minimax-cn, minimax-cn-coding-plan, minimax-coding-plan, moark, modelscope, moonshotai-cn, morph, nano-gpt, nebius, nova, novita-ai, nvidia, ollama-cloud, ovhcloud, poe, privatemode-ai, requesty, scaleway, siliconflow, siliconflow-cn, submodel, synthetic, upstage, v0, venice, vivgrid, vultr, wandb, xiaomi, zai, zai-coding-plan, zhipuai, zhipuai-coding-plan

---

## Architectural Notes

- The `Provider` trait requires: `name()`, `api()`, `model_id()`, `stream()` - all 6 native modules implement this
- Ad-hoc providers use `ad_hoc_model_entry()` to create `ModelEntry` on-the-fly when user specifies a known provider ID
- Extension `streamSimple` can cover **any** gap without native code changes
- `Api` enum has forward-declared variants (`BedrockConverseStream`, `GoogleVertex`) with no corresponding modules
- OAuth framework exists for Anthropic + extension providers; other natives use API key auth only
