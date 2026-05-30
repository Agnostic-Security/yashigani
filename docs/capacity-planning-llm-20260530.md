# Yashigani local-LLM capacity planning (pre-sales sizing)

Purpose: tell a client/prospect **what GPU capacity they need for N users** — worked for **100 users** — *before* they buy. Grounded in measured numbers from the e2e box (RTX 3060 12 GB); other GPUs are scaled estimates (clearly marked) that we can confirm by benchmarking the client's target card.

## The one number that drives sizing: concurrency saturation
Capacity is **not** "100 users = 100 GPUs." It's about how many are *generating at the exact same instant* (chat is bursty — users read/type far longer than the model generates). Measured on the RTX 3060 with `qwen2.5:7b` (a realistic chat model):

| concurrent generations | aggregate tok/s | per-user tok/s | per-user feel (300-tok reply) |
|---:|---:|---:|---|
| 1 | 57 | 57 | ~5 s — snappy |
| 2 | 92 | 46 | ~6.5 s — good |
| 4 | 91 | 23 | ~13 s — sluggish |
| 8 | 94 | 12 | ~25 s — bad (queued) |

**Read:** a single RTX 3060 comfortably serves ~**2–3 concurrent chat generations** (≥~30 tok/s each). Past that, Ollama **queues** — throughput is flat but latency climbs. So **usable capacity per RTX 3060 ≈ 2.5 concurrent chats.** (Inspection/OPA models run separately at 4-wide / 225 tok/s and are **never the bottleneck** — budget them as ~10% overhead.)

## The sizing formula
```
concurrent_generations ≈ users × (requests_per_user_per_hour) × (avg_generation_seconds) / 3600
GPUs needed            = ceil( concurrent_generations / concurrent_per_GPU )
```
`concurrent_per_GPU` (good UX, 7B chat): **RTX 3060 ≈ 2.5** (measured anchor).

## 100 users — worked answer
| usage profile | req/user/hr | gen seconds | peak concurrent | RTX 3060-class GPUs | …or a single bigger GPU |
|---|---:|---:|---:|---:|---|
| **Light** (occasional Q&A) | 8 | 6 | ~1.3 | **1** | any 12 GB+ |
| **Moderate** (regular assistant) | 20 | 8 | ~4.4 | **2** | 1× L4 / A10 / RTX 4090 |
| **Heavy** (power users, long replies) | 40 | 12 | ~13 | **5** | 1× A100, or 2× L4/4090 |

**Headline for 100 users (now MEASURED, see below):** the formula above is the *unqueued* estimate; a sustained ramped load test shows one RTX 3060 comfortably serves **~50 moderate chat users** (p95 < 7 s) with `gemma3:4b`, and **100 moderate users is the edge** (p50 fine, p95 ~44 s) → size **100 users at ~2× RTX-3060-class, or one L4 / A10 / RTX 4090.** Heavy/coding 100-user use needs more (saturates one 3060).

## Workload tiers (the 3 areas — each sizes differently)
1. **Yashigani OPA / inspection (always-on, per request):** small classifiers (`qwen2.5:1.5b` + `llama-guard3:1b`), 4-wide at ~225 tok/s on one 3060. Cheap and parallel — **not a capacity driver**; it co-resides with chat (≈10% overhead) or offloads to the 2nd GPU (GTX 1060).
2. **General usage (chat):** the **primary driver** — the table above. Size to `concurrent_per_GPU ≈ 2.5` on a 3060-class card.
3. **Development / coding:** longer prompts *and* longer outputs (code) → ~**2–3× the tokens per interaction** → **count one dev user as ~2–3 general users**. A team of 100 devs on coding assistants needs roughly the "Heavy" row or more. Use a coder model (`qwen2.5-coder:7b`, same footprint as `qwen2.5:7b`).

## GPU class reference (RTX 3060 measured; others estimated)
| GPU | VRAM | ~concurrent 7B chats | biggest model | note |
|---|---:|---:|---|---|
| **RTX 3060** | 12 GB | **2–3 (measured)** | 14B-q4 | the anchor for all estimates |
| RTX 4090 | 24 GB | ~6–8 (est) | 32B-q4 | ~3× compute of the 3060 |
| NVIDIA L4 | 24 GB | ~4–5 (est) | 32B-q4 | efficient datacenter card |
| NVIDIA A10 | 24 GB | ~5–6 (est) | 32B-q4 | common cloud SKU |
| A100 40/80 GB | 40–80 GB | ~15–25 (est) | 70B | one card covers ~heavy-100 + headroom |
| GTX 1060 3 GB | 3 GB | 0 (chat) | ≤2B | inspection offload only (≤2 concurrent) |

> Estimates scale from the measured 3060 by relative FP16/INT8 throughput + VRAM; **we validate by benchmarking the client's actual GPU** (same harness used here, ~20 min) before quoting.

## How to use this in a quote
1. Ask the prospect: # users, rough requests/user/hour, chat vs coding, acceptable response time.
2. Plug into the formula → peak concurrent generations.
3. Divide by `concurrent_per_GPU` for their GPU class (anchor 3060=2.5; scale per the table).
4. Add the inspection overhead (~10%) and a peak-headroom factor (×1.3–1.5).
5. Offer the on-card benchmark to firm it up.

## Caveats / to firm up
- Numbers are single-run on one box; for a hard SLA we should run a **sustained load test** (N simulated users at a request rate over 10–15 min) — I can build that harness next.
- Assumes local Ollama. Yashigani's optimization engine can also route to cloud providers for overflow/large-context, changing the local-GPU math.
- Token/latency depends on model + quant + prompt size; the table assumes ~300-token replies on a 7B-q4.

## MEASURED capacity — sustained ramped load test (supersedes the formula estimate)

100/50 simulated users, **staggered start** (60 s ramp, removes thundering-herd), each looping {200-token request → think → repeat} for 4 min on the RTX 3060. Raw: `testing_runs/metrics/llm-bench-20260530/llm_loadtest_ramped.csv`.

| model | users | profile (think) | throughput (req/min) | p50 | p95 | p99 | verdict |
|---|---:|---|---:|---:|---:|---:|---|
| **gemma3:4b** | 50 | moderate (150 s) | 20 | 4.2 s | **6.3 s** | 6.9 s | ✅ comfortable |
| **gemma3:4b** | 100 | moderate (150 s) | 40 | 4.5 s | **43.8 s** | 47.3 s | ⚠️ edge — median fine, tail queues |
| gemma3:4b | 100 | heavy (60 s) | 66 | 44 s | 44 s | 45 s | ❌ saturated |
| qwen2.5:7b | 100 | moderate (burst) | 35 | 45 s | 134 s | 144 s | ❌ slower model, worse tail |

### Hard guidance (use these for quotes)
- **~50 moderate chat users per RTX 3060** with `gemma3:4b` → snappy (p95 < 7 s). This is the dependable "users per 12 GB consumer GPU" number.
- **100 moderate users → 2× RTX 3060-class** (or 1× L4 / A10 / RTX 4090) to keep p95 in the single digits. One 3060 *technically* serves 100 (median 4.5 s) but the **tail (p95 44 s) is unacceptable** — don't sell a single 3060 for 100 active chatters.
- **Heavy or coding-heavy 100 users → 3×+ a 3060, or one A100.**
- **Model choice ≈ doubles capacity:** `gemma3:4b` halved p95 vs `qwen2.5:7b` at the same load. Recommend the lighter-but-capable general model to stretch per-GPU user count.
- **Inspection/OPA never the bottleneck:** the small classifiers run alongside at >150 tok/s, 4-wide — budget ~10% overhead, not extra GPUs.

### Quick sizing rule of thumb (consumer 12 GB / RTX 3060-class)
`GPUs ≈ ceil(active_users / 50)` for moderate chat on `gemma3:4b`; halve the per-GPU number (≈25/GPU) for heavy or coding use; datacenter cards (L4/A10/4090 ≈ 2×, A100 ≈ 5–8×) scale the per-GPU user count up proportionally (validate by benchmarking the client's card).
