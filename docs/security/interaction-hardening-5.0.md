# Yashigani 5.0 — interaction-hardening controls (capability + operator reference)

This documents the 5.0 "interaction-hardening" controls: what each **provably
does**, what it **does not** do, how to enable/configure it, and its default.
Wording follows the honest-claim contract (register §B): **detection where the
control escalates, prevention where it fails closed** — not blanket "prevention."

## Scope boundary (applies to every control below)

- **Gateway-scope, interaction-time.** These controls act on requests/responses
  passing through the gateway. They do **not** secure model *training* (LLM04 /
  the training half of LLM03 are out of scope by design).
- **Text and voice.** Image-content inspection is **blocked, not inspected**
  until A6-image ships; video inputs/streams are blocked, not inspected
  (A6-video, post-5.0); vector/RAG-store security carries an **LLM08 asterisk**
  (A11, post-5.0 — operator responsibility until built).
- **Downstream MCP-server credential use** beyond the gateway's JWT chain is a
  declared boundary (operator responsibility), and in-context soft-steering via
  tool results is **mitigated, not eliminated** (structurally bounded).
- **Independent external pentest (register C1) is the credibility gate** for any
  "ALL interactions" claim. Until that lands, coverage is self-attested + the
  standing per-release adversarial gate.

## Controls

| Control | What it PROVABLY does | What it does NOT do | Enable / config | Default |
|---|---|---|---|---|
| **Request-leg injection (A1)** | Mechanical (deterministic, obfuscation-normalised) block on `/v1` chat + embeddings, BEFORE the LLM inspector sees the payload; LLM escalation only for suspicious content; fail-closed on classifier error | Guarantee detection of every novel semantic injection (arms race — *detection*, not proof of prevention) | always on | on |
| **Suspicion gate** | Sends only *suspicious* prompts to the LLM (markers / forged structure / obfuscation / sklearn-uncertain / conversation score); normal traffic never reaches the LLM | Replace the LLM — it decides *who* gets it, cheaply/deterministically | always on | on |
| **Multi-turn accumulator** | Per-conversation decaying risk score; a slow-burn attack across turns (incl. benign tangents) escalates flag→step-up→block; shared across replicas when Redis is wired | Judge single messages (that's the per-message layers); catch an attack with zero linguistic signal | `YASHIGANI_CONVERSATION_RISK` | on |
| **Server-initiated MCP (A2)** | Default-deny sampling/elicitation/roots + id-collision hijack, on bridge + HTTP legs, audited | — | always on | on |
| **Memory-poisoning (A3, embeddings)** | Injection/moderation/promoted-rule checks on the embeddings (Letta archival) ingress | Sanitise memory already stored before 5.0 (in-flight only) | always on | on |
| **System-prompt leak scrub (A4)** | Redacts registered system-prompt content echoed in a response; audited | Protect prompts the operator does not register | `YASHIGANI_PROTECTED_SYSTEM_PROMPTS_FILE` | off (no-op unset) |
| **Model-integrity pin (A5)** | Verifies the served ollama model's **weights-blob** hash (primary anchor) + manifest digest against a dual-control pin; blocks a swap/drift; verifies the classifier's own startup model | Detect a compromised ollama *binary* that lies about the digest (pin the image digest separately); cover the direct-ollama bypass unless isolated/keyed | pin via admin API; probe auto; `YASHIGANI_MODEL_PIN_STRICT` to refuse start on mismatch | pin off until bootstrapped |
| **Rug-pull re-approval** | A post-approval manifest delta is held pending; an invocation of a pending server is **blocked at the broker** until a 2nd admin approves | — | auto when the gate is wired | on |
| **Tool-poison strict import** | Rejects an MCP import whose tool surface fails the day-one-poison screen | Scan a manifest that ships poisoned but passes the heuristic + sidecar (bounded) | `YASHIGANI_MCP_IMPORT_STRICT=true` | off (flag-not-block default) |
| **LLM→mechanical promotion** | A novel injection the LLM caught → admin-approved deterministic rule → next instance blocked mechanically (no LLM); resists leet/homoglyph | Auto-activate a rule (dual-control required) | `YASHIGANI_RULE_PROMOTION` | on |
| **Audio (A6-audio)** | Transcribes voice, then runs the full text pipeline on the transcript; audio with no transcriber is **blocked**, never passed uninspected | Inspect the raw audio signal (transcript-only); image/video (blocked) | `YASHIGANI_AUDIO_TRANSCRIBE_URL` (local whisper) | off (audio blocked until set) |
| **Content moderation (A12)** | Admin-tunable category policy (block/flag) on prompt + response; both legs | Ship a fixed moral line — it is mechanism, not policy (empty = no-op) | `YASHIGANI_CONTENT_MODERATION_POLICY_FILE` | off (no-op unset) |
| **Audit + forensic** | Every block/scrub/deny writes an attributable audit event (who, leg, layer, matched rule, content hash) | Log raw payloads by default — forensic mode captures the payload with **credentials masked** | `YASHIGANI_SECURITY_FORENSIC_CAPTURE=true` | off (hash-only) |
| **Metrics** | `yashigani_interaction_blocks_total{control,layer,leg}`, `suspicion_gate_decisions_total`, `rule_promotion_total` on `/metrics` | — | always on | on |

## The defensible claim (register, once C1/pentest lands)

> *"Yashigani secures all text and voice Agentic AI, MCP, API and LLM interactions
> with organization data at the gateway — detection where escalate-only,
> prevention where fail-closed — independently pentested. Image-content
> inspection and vector/RAG-store security are on the roadmap (5.1 / post-5.0);
> model-training risks are out of scope by design."*

Use that wording — an "ALL" with a written-down, defensible asterisk — never a
blanket absolute. Do NOT publish this claim before the external pentest (C1).
