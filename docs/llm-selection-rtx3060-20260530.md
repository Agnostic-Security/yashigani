# Ollama LLM selection for Yashigani — benchmarked on RTX 3060 (12 GB), 2026-05-30

Measured on the live e2e box (host Docker, RTX 3060 via nvidia CDI). Method: `ollama` `/api/generate` (stream=false), one warm run per model, `num_predict=120`. Raw data: `testing_runs/metrics/llm-bench-20260530/llm_bench.csv`.

| model | tier | gen tok/s | prompt tok/s | VRAM | disk |
|---|---|---:|---:|---:|---|
| qwen2.5:0.5b | inspection | **371** | 4221 | 1.6 GB | 0.4 GB |
| llama3.2:1b | inspection | 212 | 3886 | 2.5 GB | 1.3 GB |
| qwen2.5:1.5b | inspection | 201 | 3321 | 2.2 GB | 1.0 GB |
| gemma2:2b | inspection | 141 | 1627 | 3.3 GB | 1.6 GB |
| **llama-guard3:1b** | safety | 255 | **9403** | 2.5 GB | 1.6 GB |
| qwen2.5:3b | mid | 124 | 1817 | 3.2 GB | 1.9 GB |
| llama3.2:3b | mid | 127 | 1986 | 3.5 GB | 2.0 GB |
| qwen2.5:7b | chat | 65 | 1405 | 5.6 GB | 4.7 GB |
| llama3.1:8b | chat | 61 | 881 | 6.1 GB | 4.9 GB |
| gemma2:9b | chat | 52 | 628 | 8.0 GB | 5.4 GB |

All fit the 12 GB card; even a 14B-q4 (~9–10 GB) would fit solo.

## The constraint that drives the choice
Yashigani runs **inspection/classification models AND the end-user chat model concurrently on the same GPU** (sensitivity classifier + prompt-injection/CHS guard on every request, plus the chat completion). So pick the set whose **combined VRAM** fits 12 GB with headroom — not the single biggest model.

## Recommendations

### Yashigani internal pipeline (latency-critical, runs per-request)
- **Prompt-injection / credential-exfil / safety classification → `llama-guard3:1b`.** Purpose-built safety classifier; **9,400 tok/s prompt eval** (prefill dominates classification latency) at only 2.5 GB. Directly strengthens the inspection layer that the red-team probed — and would have flagged the prompt-injection attempts as a dedicated signal (the current pipeline relied on the response-leg sensitivity rule). Strongly recommended to add.
- **Sensitivity classification (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED) → `qwen2.5:1.5b`** (201 tok/s, 2.2 GB) or `qwen2.5:0.5b` (371 tok/s, 1.6 GB) for the lightest footprint. The current default `OLLAMA_MODEL=qwen2.5:3b` works but a 0.5–1.5b is faster and lighter for pure classification — free up VRAM for chat. *(Note: during the e2e the classifier fail-closed to RESTRICTED when its ollama backend was briefly unreachable — keep a small, always-resident classifier to avoid that.)*

### End-user chat (quality matters)
- **Primary → `qwen2.5:7b`** (65 tok/s, 5.6 GB): best quality/speed/VRAM balance, leaves ~4 GB for the concurrent inspection models. Recommended default for end users on a 12 GB card.
- **Alt → `llama3.1:8b`** (61 tok/s, 6.1 GB): strong general + tool-use; pick if you want Llama-family behavior.
- **Max quality → `gemma2:9b`** (52 tok/s, 8.0 GB): highest quality tested, but at 8 GB it leaves little room to also load inspection models — only if chat runs on a *separate* GPU or inspection is regex/sklearn-only.
- **Coding alias** ("code" optimization-engine alias): add `qwen2.5-coder:7b` (≈ qwen2.5:7b footprint) when code workloads are expected.

### Recommended resident set for a single 12 GB card (full pipeline)
`qwen2.5:7b` (chat, 5.6 GB) + `llama-guard3:1b` (safety, 2.5 GB) + `qwen2.5:1.5b` (sensitivity, 2.2 GB) ≈ **10.3 GB** — fits with headroom. Avoid pairing `gemma2:9b` (8 GB) with resident inspection models on one 12 GB card.

### The 2nd GPU
The box also has a GTX 1060 3 GB. It's too small for chat, but can host a **resident inspection model** (`qwen2.5:1.5b`/`llama-guard3:1b` fit ~2.5 GB) to keep the RTX 3060 fully for end-user chat — a cheap way to remove inspection/chat VRAM contention. Wire via a second Ollama instance pinned to `nvidia.com/gpu=0`.

## Concurrency & capacity per GPU (parallel vs queued requests)

Measured with a dedicated Ollama per card (`OLLAMA_NUM_PARALLEL`: 3060=4, 1060=2), firing N simultaneous 100-token completions. Raw: `testing_runs/metrics/llm-bench-20260530/llm_concurrency.csv`.

| GPU | model | conc | aggregate tok/s | per-req tok/s | p50 latency | VRAM |
|---|---|---:|---:|---:|---:|---:|
| **RTX 3060** | qwen2.5:1.5b | 1 | 147 | 147 | 0.7 s | 2.5 GB |
| | | 2 | 207 | 104 | 0.9 s | |
| | | 4 | 225 | 56 | 1.8 s | |
| | | 8 | 249 | 31 | 2.4 s | |
| **RTX 3060** | qwen2.5:7b | 1 | 57 | 57 | 1.7 s | 8.1 GB |
| | | 2 | **92** | 46 | 2.1 s | |
| | | 4 | 91 | 23 | 4.2 s | |
| | | 8 | 94 | 12 | 6.1 s | |
| **GTX 1060 3 GB** | qwen2.5:1.5b | 1 | 61 | 61 | 1.6 s | 1.6 GB |
| | | 2 | **105** | 53 | 1.9 s | |
| | | 4 | 68 ↓ | 17 | 4.4 s | |

### How to read it
- **Ollama queues, it doesn't drop.** Past the parallel-slot limit, extra requests wait — aggregate throughput plateaus while per-request latency climbs roughly linearly. No errors, just slower.
- **RTX 3060 — chat (7B): ~2 effective parallel.** Aggregate peaks at **~92 tok/s at concurrency 2**, then flat (3rd+ requests queue): the 3060 is compute-bound on a 7B. Set `OLLAMA_NUM_PARALLEL=2` for chat. Plan **~90 tok/s total** chat capacity; at 8 in-flight, p50 ≈ 6 s.
- **RTX 3060 — inspection (1.5b): scales to ~4.** Aggregate ~**225–250 tok/s** at conc 4–8 (small model, parallelism helps); latency stays sub-2.5 s even at 8. Comfortably handles bursty per-request inspection.
- **GTX 1060 — ~2 concurrent small models, hard ceiling.** Peaks ~**105 tok/s at conc 2**, then **regresses at 4** (68 tok/s, 4.4 s) — Pascal, no tensor cores, 3 GB. Use it only for **low-concurrency inspection offload**, never chat.

### Capacity guidance
- **Single RTX 3060, full pipeline:** budget ~2 concurrent end-user chats (~90 tok/s shared) + plenty of headroom for inspection (4-wide, 225 tok/s). Beyond ~2–3 simultaneous chatters, responses queue and latency grows — add a GPU or a second node before that.
- **Offload split (recommended for >2 chatters):** pin chat to the RTX 3060 (`OLLAMA_NUM_PARALLEL=2`) and inspection to a second Ollama on the GTX 1060 (`gpu=0`, `NUM_PARALLEL=2`, small model) — removes inspection↔chat VRAM/compute contention; the 1060 sustains the per-request inspection load fine at ≤2 concurrent.
- **Rule of thumb:** size `OLLAMA_NUM_PARALLEL` to where aggregate tok/s stops rising (2 for 7B on the 3060, 4 for ≤2B). Higher just inflates latency.

## Expanded sweep (current strongest Ollama models, RTX 3060) — 2026-05-30

All pull+run in Ollama. VRAM ≈ disk size + KV cache (the live `vram_mb` reading was noisy/shared, use disk size). Raw: `testing_runs/metrics/llm-bench-20260530/llm_expanded.csv`.

| tier | model | gen tok/s | prompt tok/s | size | notes |
|---|---|---:|---:|---|---|
| inspection | **gemma3:1b** | 206 | 1840 | 0.8 GB | tiny + fast — best light classifier |
| inspection | qwen3:1.7b | 194 | 2024 | 1.4 GB | strong small |
| inspection | smollm2:1.7b | 159 | 3538 | 1.8 GB | |
| safety | **llama-guard3:1b** | 255 | **9403** | 1.6 GB | best prefill (round 1) — purpose-built |
| safety | shieldgemma:2b | 188 | 5125 | 1.7 GB | Gemma-family safety |
| safety | granite3-guardian:2b | 161 | 3470 | 2.7 GB | IBM Granite guardian |
| general | **gemma3:4b** | **98** | 1170 | 3.3 GB | faster+smaller than qwen2.5:7b, high quality — **best balance** |
| general | qwen3:8b | 60 | 805 | 5.2 GB | newer, strong reasoning |
| general | mistral-nemo:12b | 47 | 437 | 7.1 GB | 128k context |
| general | **gemma3:12b** | 40 | 515 | 8.1 GB | **best quality that's still interactive** |
| general | qwen3:14b | 23 | 305 | 9.3 GB | too slow on a 3060 |
| general | phi4 (14b) | 11 | 92 | ~9 GB | too slow on a 3060 |
| reasoning | deepseek-r1:14b | 13 | 101 | 9.0 GB | "other functions" (slow; emits think tokens) |
| dev | **deepseek-coder-v2:16b** | 44 | — | 8.9 GB | MoE-lite, best coding that fits |
| dev | codegemma:7b | 18 | 274 | 5.0 GB | slow |

## ⭐ Recommended model MIX (client-facing)

> **How to read "best" vs "most lightweight":** *lightweight* = smallest VRAM / fastest that adequately does the job; *best* = highest **capability/quality that still fits 12 GB and runs at interactive speed** (so 14B models that drop to 11–23 tok/s are excluded). **Caveat:** these benchmarks measured **throughput, prompt-speed, and VRAM — not output quality.** "Best" is therefore a capability judgement (model reputation + size + measured speed), **not an empirical quality score.** For a data-backed quality ranking, run a per-tier accuracy eval (task set) — not yet done. tok/s figures are gen-rate unless noted;  is estimated (≈ qwen2.5:7b 65 tok/s — coder-bench rate-parse failed, VRAM captured).


A **mix**, not one model — pick best vs lightweight per function. All Ollama-runnable; sizing assumes one RTX 3060-class 12 GB card.

| Function | Most lightweight | Best (quality) |
|---|---|---|
| **Yashigani internal — sensitivity** | `gemma3:1b` (0.8 GB, 206 tok/s) | `qwen3:1.7b` (1.4 GB, 194 tok/s) |
| **Yashigani internal — injection/safety guard** | `llama-guard3:1b` (1.6 GB, 9.4k prompt tok/s) | `shieldgemma:2b` (1.7 GB, 188 gen / 5.1k prompt tok/s) |
| **General usage (chat)** | `gemma3:4b` (3.3 GB, 98 tok/s) | `gemma3:12b` (8.1 GB, 40 tok/s) |
| **Developer (coding)** | `qwen2.5-coder:7b` (4.7 GB, ~65 tok/s) | `deepseek-coder-v2:16b` (8.9 GB, 44 tok/s) |
| **Other functions (reasoning)** | `qwen3:8b` (5.2 GB, 60 tok/s) | `deepseek-r1:14b` (9 GB, 13 tok/s — batch only) |

**Default resident bundle for one 12 GB card (general + full inspection):**
`gemma3:4b` (general, 3.3 GB) + `gemma3:1b` (sensitivity, 0.8 GB) + `llama-guard3:1b` (safety, 1.6 GB) ≈ **5.7 GB** — fits with big headroom, and all three are fast. This **beats the round-1 bundle** (qwen2.5:7b + …, ~10 GB): lighter, faster, leaves VRAM for more chat concurrency.

**Dev bundle:** `deepseek-coder-v2:16b` (8.9 GB) leaves little room for resident inspection on a 12 GB card → run inspection on the 2nd GPU, or use `qwen2.5-coder:7b` (4.7 GB) to keep inspection co-resident.

**Why gemma3 wins here:** on the RTX 3060, `gemma3:4b` delivers ~98 tok/s at 3.3 GB — higher chat capacity per GPU than the 7–9B models, with quality competitive for general assistant use. Reserve the 12 GB for `gemma3:12b` only when max single-response quality matters more than concurrency.
