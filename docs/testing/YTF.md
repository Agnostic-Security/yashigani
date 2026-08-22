# Yashigani Test Framework (YTF)

**YTF is the canonical test harness for Yashigani.** It covers all release gates, conformance, security, and lifecycle testing across platforms (macOS/Linux) and runtimes (Docker/Podman).

---

## Tier Structure

### Tier-A: Conformance (Runtime-Invariant)
- **Runs on:** macOS only (once per release, all platforms use same suite)
- **Coverage:** 
  - API contract validation (OpenAI SDK compatibility)
  - Model enumeration (`/v1/models`)
  - Chat completion requests (streaming + non-streaming)
  - Token counting accuracy
  - RBAC enforcement (admin/user/agent roles)
  - OPA policy evaluation (ingress + egress inspection)
  - Admin user creation and password change
- **Expected:** PASS on both macOS (Ollama) and Linux (KUROSHIO)
- **Duration:** ~20 minutes
- **Gate:** Required before any tag

---

### Tier-B: Live Per-Runtime Testing
- **Runs on:** Both macOS and Linux (Docker + Podman variants)
- **Coverage:**
  - Runtime lifecycle (container health, restart recovery)
  - Service dependencies (gateway → cache → policy → inference backend)
  - SSL/TLS termination (Caddy cert pinning)
  - Secret management (bearer tokens, client certs)
  - Multi-tenant isolation (tenant_id scoping)
  - Rate limiting and request quotas
  - Audit logging
- **Inference backend per platform:**
  - **macOS:** Ollama (localhost:11434, user-space inference)
  - **Linux:** KUROSHIO classifier + chat services (internal ringfence)
- **Duration:** ~30 minutes per platform
- **Gate:** Required before any tag

---

### Tier-C: Lifecycle & Integration
- **Runs on:** Both macOS and Linux (Docker + Podman variants)
- **Coverage:**
  - Install → Boot → Healthz → Populate → Test → Teardown
  - Data persistence across restart cycles
  - Volume backup/restore (crypto-shred testing)
  - Zero-downtime deploy (blue/green readiness)
  - Helm ↔ Compose parity (resource limits, env var names)
  - Logging aggregation (Loki/Promtail)
  - Observability (Prometheus/Grafana scrapes)
  - Secrets rotation (Redis TLS cert updates)
- **Duration:** ~45 minutes per platform
- **Gate:** Required before any tag

---

## Inference Backend Specification

### macOS (v5.0+)
```yaml
Backend: Ollama (host-resident, PRE-INSTALLED REQUIRED)
Location: localhost:11434 (or custom port via --ollama-port)
Models: mistral:7b, phi:latest (or user-pulled)
Pull Command: ollama pull <model>  # Run BEFORE install.sh
Architecture: User-space inference (no Linux kernel isolation)
```

**Prerequisites on macOS:**
1. Download + install Ollama from ollama.com
2. Start Ollama before running install.sh: `OLLAMA_HOST=127.0.0.1:11434 ollama serve`
3. (Optional) Pre-pull a model: `ollama pull mistral:7b`
4. install.sh will verify Ollama is reachable; if not found, it pauses for 5 seconds (Ctrl+C to abort)

**Why Ollama on macOS?**
- Native Metal acceleration for Apple Silicon
- Simpler host lifecycle (no container runtime for inference engine)
- Temporary solution; macOS will gain KUROSHIO-native when the runtime supports it

---

### Linux (v5.0+)
```yaml
Backend: KUROSHIO (first-party inference engine)
Services:
  - kuroshio-classifier: PII/prompt-injection detection (keeps-loaded model)
  - kuroshio-chat: Conversational inference (llama3.1, mistral, qwen, etc.)
  - kuroshio-puller: Model downloader → shared kuroshio_models volume
Location: Internal ringfence network (caddy:11435 → /kuroshio endpoint)
Models: Downloaded via kuroshio-puller to /root/.ollama (persistence)
Architecture: Fully containerized, seccomp+AppArmor isolation, no host binary
```

**Why KUROSHIO on Linux?**
- Deterministic runtime (no host inference engine version drift)
- Security-hardened container profile (seccomp, read-only rootfs where possible)
- First-party control of inference engine (no supply-chain risk from external Ollama updates)
- Mesh identity integration (PQC signatures on classifier requests)

---

## Test Matrix

| Platform | Runtime | Tier-A | Tier-B | Tier-C | Inference Backend |
|----------|---------|--------|--------|--------|-------------------|
| macOS    | Docker  | ✓      | ✓      | ✓      | Ollama (localhost:11434) |
| Linux    | Docker  | ✓*     | ✓      | ✓      | KUROSHIO (caddy:11435) |
| Linux    | Podman  | ✓*     | ✓      | ✓      | KUROSHIO (caddy:11435) |

*Tier-A runs once on macOS; results apply to all platforms (conformance is runtime-invariant).

---

## Running YTF

### Prerequisite: Ollama availability (macOS only)
**On macOS, verify Ollama is running BEFORE install:**

```bash
# Check default port (11434)
curl http://127.0.0.1:11434/api/tags | jq '.models[] | .name'

# If Ollama not found, start it:
OLLAMA_HOST=127.0.0.1:11434 ollama serve

# If running on custom port, note it for installer:
./install.sh --ollama-port <custom_port>
```

If Ollama is not available on macOS, the installer will **warn and pause 5 seconds** (you can Ctrl+C to abort).

---

### Prerequisite: Install + Healthz
```bash
cd /path/to/yashigani
./install.sh --deploy demo --runtime docker  # (or podman on Linux)

# Wait for all containers healthy
curl -s https://localhost:8443/healthz --insecure | jq '.status'
# Expected: "healthy"
```

### Tier-A (macOS only)
```bash
cd /path/to/yashigani
YTF_PYTHON=~/.venv YTF_EVIDENCE_ROOT=~/testing_runs/v50-testing/conformance \
  ./scripts/run-test-framework.sh --tier a \
  --target https://localhost:8443 \
  --runtime docker \
  --version 5.0.0 \
  --platform macos
```

**Expected output:** `PASS: 45/45 conformance checks`

---

### Tier-B (macOS + Linux, parallel)

#### macOS terminal:
```bash
# 1. Run Tier-B tests
cd /path/to/yashigani
YTF_PYTHON=~/.venv YTF_EVIDENCE_ROOT=~/testing_runs/v50-testing/macos-tier-b \
  ./scripts/run-test-framework.sh --tier b \
  --target https://localhost:8443 \
  --runtime docker \
  --version 5.0.0 \
  --platform macos

# 2. Test Ollama model import (new models)
ollama pull qwen2.5:7b
# Verify new model appears in /v1/models
curl -s https://localhost:8443/v1/models \
  --header "Authorization: Bearer $YASHIGANI_ADMIN_TOKEN" \
  --insecure | jq '.data[] | select(.id | contains("qwen")) | .id'
```

#### Linux (x8x) terminal:
```bash
# 1. Run Tier-B tests
cd ~/yashigani
YTF_PYTHON=~/.venv YTF_EVIDENCE_ROOT=~/testing_runs/v50-testing/linux-tier-b \
  ./scripts/run-test-framework.sh --tier b \
  --target https://localhost:8443 \
  --runtime docker \
  --version 5.0.0 \
  --platform linux

# 2. Test model imports to KUROSHIO (both sources)

# 2a. Import Ollama-format model to KUROSHIO
# (e.g., manually export a local ollama model, then import to KUROSHIO)
ollama pull mistral:7b
# Export and push to KUROSHIO (requires custom loader — document here)

# 2b. Import Hugging Face GGUF model directly to KUROSHIO
# (Download GGUF from HF Hub, mount to kuroshio_model_store, verify)
# Example: meta-llama/Llama-2-7b-chat-GGUF (quantized)
# Download URL: https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.Q4_K_M.gguf
curl -L https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.Q4_K_M.gguf \
  -o /tmp/llama-2-7b-chat.Q4_K_M.gguf
# Copy to KUROSHIO model store
docker exec kuroshio-chat cp /tmp/llama-2-7b-chat.Q4_K_M.gguf /data/model-store/
# Verify model is accessible to classifier/chat
docker exec kuroshio-classifier ls -lh /data/model-store/
```

**Expected output:** 
- macOS: `PASS: all runtime checks` + Ollama model import verified
- Linux: `PASS: all runtime checks` + both Ollama and Hugging Face models in KUROSHIO model-store

---

### Tier-C (macOS + Linux, serial)

Run after Tier-B passes on both platforms.

#### macOS:
```bash
cd /path/to/yashigani

# 1. Run Tier-C lifecycle tests
YTF_PYTHON=~/.venv YTF_EVIDENCE_ROOT=~/testing_runs/v50-testing/macos-tier-c \
  ./scripts/run-test-framework.sh --tier c \
  --target https://localhost:8443 \
  --runtime docker \
  --version 5.0.0 \
  --platform macos

# 2. Model lifecycle on macOS: Pull model(s) sized for available GPU/VRAM
# M4 GPU with 24GB VRAM — test with models that fit:
#   - phi:latest (~3GB, fastest)
#   - mistral:7b (~5GB, balanced)
#   - llama2:13b (~8GB, heavier)
# Verify models persist across restart
ollama pull mistral:7b
docker restart ollama
sleep 10
ollama ls | grep mistral
# Expected: mistral model still present
```

#### Linux (x8x):
```bash
cd ~/yashigani

# 1. Run Tier-C lifecycle tests (install → test → teardown)
YTF_PYTHON=~/.venv YTF_EVIDENCE_ROOT=~/testing_runs/v50-testing/linux-tier-c \
  ./scripts/run-test-framework.sh --tier c \
  --target https://localhost:8443 \
  --runtime docker \
  --version 5.0.0 \
  --platform linux

# 2. Model lifecycle: verify persistence of both Ollama and Hugging Face models in KUROSHIO
# After install→test→teardown, the kuroshio_models volume should retain all imported models
docker volume inspect kuroshio_models
# Expected: data path shows model files from Ollama + HF imports

# 3. Stress-test model switching during lifecycle
# (Download multiple models, verify they survive volume unmount/remount)
```

**Expected output:** 
- macOS: `PASS: install→test→teardown lifecycle` + Ollama models persist across restart
- Linux: `PASS: install→test→teardown lifecycle` + KUROSHIO volume retains all models (Ollama + HF)

---

## Inference Backend Testing Notes

### Ollama (macOS)
- **Import source:** Ollama Hub (ollama.ai/library)
- **Model selection:** Size models to available GPU VRAM (e.g., M4 24GB → mistral:7b, phi:latest, llama2:13b)
- **Pull command:** `ollama pull <model>` (downloads to host `/Users/max/.ollama/models`)
- **Verify:** `curl -s http://localhost:11434/api/tags | jq '.models[].name'`
- **Tier-B test:** Verify model import works, models appear in `/v1/models` list
- **Tier-C test:** Verify model persistence across restart (teardown/restart of ollama process)
- **Known limitation:** No crypto-shred; models persist on host disk after teardown

### KUROSHIO (Linux)
- **Import sources:** 
  1. Ollama Hub models (via custom export/load mechanism — document in KUROSHIO integration guide)
  2. Hugging Face GGUF quantized models (direct download + copy to model-store)
- **Model store:** `/data/model-store/` (containerized, `kuroshio_models` volume for persistence)
- **Pull/import:** Manual download (HF) or export from Ollama, then copy to `kuroshio_model_store` volume
- **Verify:** `docker exec kuroshio-chat ls -lh /data/model-store/` + check classifier loads it
- **Tier-B test:** Import both Ollama-format and HF GGUF models, verify classifier/chat access them
- **Tier-C test:** Verify `kuroshio_models` volume survives full lifecycle (install→test→teardown)
- **Security gate:** Classifier runs on isolated ringfence network (no direct host bridge)

---

## Release Gate Checklist

Before tagging **v5.x.y**:

- [ ] Tier-A PASS on macOS (Ollama backend)
- [ ] Tier-B PASS on macOS (Ollama backend)
- [ ] Tier-B PASS on Linux Docker (KUROSHIO backend)
- [ ] Tier-B PASS on Linux Podman (KUROSHIO backend)
- [ ] Tier-C PASS on macOS (Ollama backend)
- [ ] Tier-C PASS on Linux Docker (KUROSHIO backend)
- [ ] Tier-C PASS on Linux Podman (KUROSHIO backend)
- [ ] Laura pentest (offensive security sweep)
- [ ] Iris audit (integration/cross-runtime drift)
- [ ] Ava e2e (UI automation, headed + headless)
- [ ] Release summary written (`AgnosticSecurity/Operations/Releases/yashigani/5.0.0.md`)
- [ ] Release retro written (`AgnosticSecurity/Operations/Compliance/yashigani/5.0.0/retro.md`)

All checks GREEN → Tag `v5.0.0` → Release notes published.

---

## Troubleshooting

| Issue | Tier-A | Tier-B (macOS) | Tier-B (Linux) | Tier-C |
|-------|--------|----------------|----------------|--------|
| Ollama unavailable (macOS) | N/A | Ollama not running on 11434; start: `OLLAMA_HOST=127.0.0.1:11434 ollama serve` | N/A | N/A |
| Healthz 503 | Docker dead; restart | Ollama crashed or unreachable | Containers crashed; check logs | Lifecycle broken |
| Model not found | API mock issue | `ollama pull <model>` before test | Puller failed; check volume | Persistence lost |
| RBAC denied | Policy gate wrong | Policy/cache sync | Same | Same |
| OPA blocking | Test identity issue | Ingress rule trigger | Ringfence rule trigger | Test teardown issue |
| TLS cert invalid | Caddy cert issue | Cert pinning mismatch | Same | Cert rotation failed |

Check logs:
```bash
# macOS
docker logs gateway
docker logs ollama

# Linux KUROSHIO
podman logs kuroshio-classifier
podman logs kuroshio-chat
```

---

## Document History

| Date | Author | Change |
|------|--------|--------|
| 2026-08-22 | Maxine | Initial YTF.md: Tier-A/B/C structure, inference backend parity (Ollama macOS, KUROSHIO Linux) |
