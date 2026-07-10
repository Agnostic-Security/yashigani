# AI Assets Inventory

**Product:** Yashigani MCP Security Gateway
**Version:** 3.1.1
**Last updated:** 2026-07-10T00:00:00+01:00
**ACS control:** ASSET.1 — AI model inventory file required at repo root
**Asset owners:** Gateway engineering, container engineering, and product ownership (Agnostic Security Ltd)

---

## Contents

1. [Proxied / hosted model backends](#1-proxied--hosted-model-backends)
2. [AI agents](#2-ai-agents)
3. [Inspection and classification models](#3-inspection-and-classification-models)
4. [Sensitivity classification pipeline](#4-sensitivity-classification-pipeline)
5. [Optimization engine (routing)](#5-optimization-engine-routing)
6. [Training data](#6-training-data)
7. [Asset ownership and update cadence](#7-asset-ownership-and-update-cadence)
8. [Maintenance note](#8-maintenance-note)

---

## 1. Proxied / hosted model backends

Yashigani is an inference gateway. It does not host model weights itself. All models listed below are proxied — requests pass through the gateway's full security pipeline (identity, sensitivity, inspection, PII, budget, audit) before reaching the upstream provider.

### 1.1 Inference backends (user-facing)

| Backend | Role | Upstream provider | Default model | Version pinning | Trained by us? |
|---|---|---|---|---|---|
| **Ollama** | Primary local inference proxy | Ollama (self-hosted, local) | `qwen2.5:3b` | Model tag pinned in `OLLAMA_MODEL` env var; pulled at deploy time via `ollama pull` | No — third-party weights from upstream model registries (Meta, Qwen, etc.) |
| **Anthropic** | Cloud inference proxy (optional) | Anthropic (api.anthropic.com) | Configurable via admin panel | SDK `anthropic>=0.25`; model name set at runtime | No — Anthropic-trained |
| **OpenAI / OpenAI-compatible** | Cloud inference proxy + API compatibility layer | OpenAI (api.openai.com) or any OpenAI-compatible endpoint | Configurable | SDK via `openai>=1.30` optional dep; model name set at runtime | No — OpenAI-trained |
| **LM Studio** | Local dev inference proxy | LM Studio (localhost:1234) | `qwen2.5-3b-instruct` | OpenAI-compatible endpoint; no SDK, raw HTTP. Dev/non-production only (YASHIGANI_ENV guard) | No — third-party weights |
| **Letta (MemGPT)** | Stateful agent runtime proxy | Letta (self-hosted, port 8283) | `openai-proxy/qwen2.5:3b` via Ollama bridge | HTTP adapter; no SDK pinning required | No — third-party |
| **Langflow** | Visual workflow runtime proxy | Langflow (self-hosted, port 7860) | Operator-configured inside Langflow flow | HTTP adapter; no SDK pinning required | No — third-party |

**Note on model identity:** The specific model weights loaded by Ollama, LM Studio, or Letta are determined by the operator's deployment configuration. Yashigani enforces policy on all traffic regardless of which model is loaded upstream.

### 1.3 Embedding model (RAG, optional Open WebUI)

| Backend | Role | Upstream provider | Default model | Version pinning | Trained by us? |
|---|---|---|---|---|---|
| **Ollama (embeddings)** | RAG document-embedding for the optional Open WebUI chat surface | Ollama (self-hosted, local) | `nomic-embed-text` | Pulled at deploy time by `ollama-init`; set as `RAG_EMBEDDING_MODEL` on the Open WebUI service (since v2.25.5) | No — third-party weights |

`nomic-embed-text` is pulled on install (since v2.25.5) so file-upload RAG in the optional Open WebUI surface resolves embeddings locally rather than reaching an external embedding API. It is used only for retrieval embeddings, not for inference or inspection.

### 1.2 Inspection backends (classification-only — see section 3)

The inspection pipeline uses a separate backend set solely for prompt-injection and credential-exfiltration classification. These are NOT used for user-facing inference.

| Backend | Upstream provider | Default model |
|---|---|---|
| Ollama (inspection) | Ollama (self-hosted) | `qwen2.5:3b` |
| Anthropic (inspection) | Anthropic | `claude-haiku-4-5` |
| Google Gemini (inspection) | Google (generativelanguage.googleapis.com) | `gemini-1.5-flash` |
| Azure OpenAI (inspection) | Microsoft Azure | `gpt-4o-mini` |
| LM Studio (inspection) | LM Studio (local) | `qwen2.5-3b-instruct` |
| scikit-learn (inspection) | Self-contained — bundled joblib artefact | Custom TF-IDF + LogisticRegression model trained on synthetic prompt-injection data (see section 3.2; replaced FastText in v2.23.3) |

---

## 2. AI agents

Yashigani provides an agent registry: a persistent store of registered agent identities, each with an upstream URL, supported protocol, and access controls. The registry is not an agent runtime — it is an identity and routing layer.

### 2.1 Agent registry

| Component | Description | Source |
|---|---|---|
| `AgentRegistry` | Redis-backed store of agent identities (PSK tokens bcrypt-hashed at cost 12). Manages registration, token rotation, soft-delete, and TOCTOU-safe Lua atomic registration. | `src/yashigani/agents/registry.py` |
| Admin routes | CRUD + token rotation routes under `/admin/agents/*`. Step-up session required for mutations. | `src/yashigani/backoffice/routes/agents.py` |

### 2.2 Supported agent protocols

| Protocol | Description | Adapter |
|---|---|---|
| `openai` | OpenAI-compatible chat completions upstream. Default protocol. | `src/yashigani/gateway/openai_router.py` |
| `letta` | Letta (MemGPT) stateful agent. Native Letta REST API, response translated to OpenAI shape. | `src/yashigani/gateway/letta_client.py` |
| `langflow` | Langflow visual workflow. Auto-login, API key creation, flow run; response translated to OpenAI shape. | `src/yashigani/gateway/langflow_client.py` |

### 2.3 Open WebUI integration

When an agent is registered via the admin API, Yashigani optionally registers the agent as a selectable model in Open WebUI (`OWUI_API_URL` env var). Open WebUI is an operator-deployed chat interface; it is not bundled in the Yashigani image.

---

## 3. Inspection and classification models

The inspection pipeline classifies every inbound prompt and outbound response for prompt injection and credential exfiltration. It operates independently of the inference backend the user's request is routed to.

### 3.1 LLM inspection backends

| Backend name | Upstream | Default model | Deployment constraint | API key storage |
|---|---|---|---|---|
| `ollama` | Local Ollama | `qwen2.5:3b` | Any environment. Default and primary. | N/A — no auth |
| `anthropic` | Anthropic API | `claude-haiku-4-5` | Optional; requires `[cloud-inspection]` extra | KMS at init time; never env var |
| `gemini` | Google Generative AI | `gemini-1.5-flash` | Optional; requires `[cloud-inspection]` extra | KMS at init time; never env var |
| `azure_openai` | Azure OpenAI | `gpt-4o-mini` | Optional; requires `[cloud-inspection]` extra; HTTPS endpoint enforced | KMS at init time; never env var |
| `lmstudio` | Local LM Studio | `qwen2.5-3b-instruct` | Non-production only (YASHIGANI_ENV guard at admin route) | N/A — no auth required locally |

The backend registry tries backends in order (default fallback chain: `["ollama", "gemini", "fail_closed"]`). If all backends fail, the registry returns `PROMPT_INJECTION_ONLY` with confidence 1.0 — fail-closed, never fail-open.

Source: `src/yashigani/inspection/backends/`, `src/yashigani/inspection/backend_registry.py`

### 3.2 scikit-learn classifier

| Attribute | Value |
|---|---|
| Name | `sklearn` (backward-compat slot name `fasttext_backend` preserved in surrounding code) |
| Type | Bundled scikit-learn pipeline — TF-IDF vectoriser + LogisticRegression, joblib serialised |
| Model file | `/app/models/sensitivity_classifier.joblib` (~28 KB; baked into gateway image at build time) |
| Training data | Synthetic prompt-injection/clean samples generated by `scripts/generate_training_data.py`. Agnostic Security-authored synthetic data only — no production user data, no third-party training corpus. |
| Quality | Macro F1 0.9545 on 220-example training corpus |
| Role | First-pass gate (< 5ms). High-confidence results bypass LLM second-pass; uncertain results route to LLM backend. |
| Trained by us? | Yes — the joblib pipeline is our own, trained on our own synthetic data. Weights are proprietary. |
| Version pinning | Model artefact is built at image build time; image rebuild required to update. `scikit-learn>=1.4` + `joblib>=1.3` installed in the trainer Docker stage. |
| History | Replaced FastText in v2.23.3 (`fasttext-wheel` was last uploaded 2020-09-03, archived by maintainer 2024-03-22, Python ABI pin blocking ≤3.12 upgrade path). sklearn ships pre-built wheels across all current Python versions; joblib artefact ~28 KB vs ~1-2 MB FastText `.bin`. |

Source: `src/yashigani/inspection/backends/sklearn_backend.py` (class `SklearnBackend`)

---

## 4. Sensitivity classification pipeline

The sensitivity pipeline classifies data sensitivity level (PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED) for every prompt. It is used by the optimization engine to enforce routing rules (P1: CONFIDENTIAL/RESTRICTED always routes local).

| Layer | Mechanism | Backend | Always on? |
|---|---|---|---|
| Layer 1 | Regex pattern matching (SSN, card numbers, API keys, IBAN, email, classification markers) | In-process (no external call) | Yes — cannot be disabled |
| Layer 2 | scikit-learn classifier — TF-IDF + LogisticRegression (same joblib artefact as section 3.2) | In-process | Opt-out via admin config |
| Layer 3 | Ollama deep contextual scan | Local Ollama (`qwen2.5:3b`) | Opt-out via admin config |

Conservative rule: the highest sensitivity level across all layers is used. Conflicts are logged.

Source: `src/yashigani/optimization/sensitivity_classifier.py`

---

## 5. Optimization engine (routing)

The optimization engine is deterministic rule-based logic — not a learned model. It applies a P1–P9 priority matrix to select local or cloud routing per request. No ML inference is used in the routing decision itself.

| Signal | Source |
|---|---|
| Sensitivity level | Section 4 pipeline |
| Complexity score | `src/yashigani/optimization/complexity_scorer.py` (heuristic, not ML) |
| Budget state | `src/yashigani/billing/budget_enforcer.py` |
| Identity flags | `force_local` / `force_cloud` per registered identity |

Source: `src/yashigani/optimization/engine.py`

---

## 6. Training data

**Yashigani trains no production models at inference time.** The gateway is inference-only.

The one exception is the scikit-learn joblib artefact (section 3.2):

| Artefact | Data source | PII in training data? | Retention |
|---|---|---|---|
| `sensitivity_classifier.joblib` | Synthetic prompt-injection and clean-prompt samples authored by Agnostic Security engineers | No — all synthetic, no user data | Training scripts in `scripts/`; model artefact in image layer (replaced FastText `.bin` in v2.23.3) |

No user prompts, responses, or any operator data are used as training inputs at any point.

---

## 7. Asset ownership and update cadence

### Ownership

| Domain | Owner |
|---|---|
| Gateway runtime (inspection pipeline, agent registry, optimization engine) | Gateway engineering team |
| Container runtime parity (Docker / Podman / Kubernetes) | Container engineering team |
| Product strategy and licensing | Product ownership (Agnostic Security Ltd) |

### Update cadence

| Event | Required action |
|---|---|
| New inference backend added (new upstream provider or protocol) | PR adding the backend module under `src/yashigani/gateway/` or `src/yashigani/inspection/backends/`; this file updated in the same PR |
| Backend removed or deprecated | PR removing/deprecating the module; this file updated in the same PR |
| Default model changed (e.g. Ollama default bumped from `qwen2.5:3b`) | PR updating env var defaults or image build args; this file updated in the same PR |
| Sensitivity classifier retrained | New joblib artefact committed as build artefact; training data provenance recorded in commit body; this file updated to note model version/date (current backend: scikit-learn TF-IDF + LogisticRegression since v2.23.3) |
| New agent protocol supported | PR adding adapter under `src/yashigani/gateway/`; this file updated in the same PR |

Each PR that adds or removes an AI backend must reference this file update in its description. The rule is enforced at code review.

---

## 8. Maintenance note

This file is the ASSET.1 inventory required by the ACS LLM Governance Checklist. It must remain accurate when backends are added, removed, or reconfigured.

**Do not** add entries for backends that are not yet implemented. **Do not** remove entries for backends that are deprecated but still callable — mark them with a "Deprecated in vX.Y.Z" note instead.

If you are opening a PR that touches `src/yashigani/gateway/`, `src/yashigani/inspection/backends/`, or `src/yashigani/optimization/sensitivity_classifier.py`, check whether this file needs updating. If it does, include the update in your PR.
