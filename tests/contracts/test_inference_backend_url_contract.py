"""
Inference-backend URL contract — the YSG-RISK-136 follow-up gate.

WHY THIS EXISTS
---------------
YSG-RISK-136 (HIGH, status: mitigated, fix_in_version v4.1.2) closed a
Compose<->K8s parity drift where gateway/backoffice reached the inference
backend by a DIRECT `:11434` connection instead of the Caddy mesh front.
`allow-ollama-ingress` (v4.1 Phase 1b-ii / LAURA-I1-01) admits ONLY the caddy
pod on 11434, so a direct URL is NetworkPolicy-blocked and every backend call
dies.

That register entry names its own root cause and prescribes this gate verbatim:

    "Test-gap (root cause the regression shipped undetected): [...]
     tests/contracts/test_agent_base_url_port.py [...] does NOT scan gateway's
     own ollamaUrl/OLLAMA_BASE_URL values -- so neither existing contract test
     asserts helm/yashigani/values.yaml actually SETS the mesh URL.
     Follow-up: extend test_agent_base_url_port.py (or a sibling contract test)
     to assert gateway.env.ollamaUrl / backoffice OLLAMA_BASE_URL never default
     to a direct :11434 connection -- closing the same blind spot that let this
     regression through."

The follow-up was never built. On 2026-08-24 that blind spot let the SAME risk
regress twice in one merge, both times through hunks git auto-merged with no
conflict — so no human reviewed them:

  - LAURA-V50-001: helm/yashigani/templates/backoffice.yaml ended up with TWO
    `OLLAMA_BASE_URL` keys in one container spec. Kubernetes applies duplicate
    env names in order and the LAST wins, so a stale v3.1.2 entry defaulting to
    `http://yashigani-ollama:11434` silently overrode the correct mesh value set
    ~80 lines above. No `backoffice.ollamaUrl` key exists in values.yaml, so it
    ALWAYS fell through to that broken default.
  - FIND-0824-GATEWAY-OLLAMA-URL-LOST: docker-compose.yml's gateway block lost
    OLLAMA_BASE_URL entirely to a KUROSHIO_BASE_URL swap that nothing reads.

Both fail CLOSED (an unreachable backend is rejected, not bypassed), so neither
is an exposure — they are silent AVAILABILITY regressions of a control that
reports itself healthy. Exactly the class a contract gate catches and a live
smoke test does not.

A third instance, FIND-0824-DUP-SEMANTIC-INTENT, was found by generalising the
duplicate check below to the whole rendered chart.

WHAT THIS ASSERTS
-----------------
  1. No duplicate env key within a single RENDERED container spec — checked on
     `helm template` output, not source text, because per-file text counting
     false-positives on initContainers (which legitimately repeat keys) and on
     comments.
  2. No inference-backend URL resolves to a direct `:11434` connection.
  3. gateway and backoffice both actually SET an inference-backend URL — the
     register's literal "actually SETS" requirement. Dropping the var is not a
     pass.

Per YTF §5.14, a fix is not verified until the bench fails without it: these
were confirmed RED against the pre-fix tree (2 OLLAMA_BASE_URL keys; gateway
compose block carrying only KUROSHIO_BASE_URL) and GREEN after.
"""
from __future__ import annotations

import collections
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
HELM_CHART = REPO_ROOT / "helm" / "yashigani"
HELM_VALUES = HELM_CHART / "values.yaml"

INFERENCE_CLIENTS = ("gateway", "backoffice")
BACKEND_URL_VARS = ("OLLAMA_BASE_URL", "KUROSHIO_BASE_URL")

# A direct backend connection — what allow-ollama-ingress blocks.
_DIRECT_BACKEND_RE = re.compile(
    r"https?://[A-Za-z0-9._-]*(?:ollama|kuroshio)[A-Za-z0-9._-]*:11434"
)


def _strip_comments(text: str) -> str:
    """Drop YAML comment lines/tails before matching.

    Learned twice in one day: Iris found 3 false-RED tests in
    test_k8s_install_criticals.py caused by a naive string search hitting an
    earlier COMMENT, and the first cut of THIS gate repeated the mistake —
    firing on the explanatory `# default "http://ollama:11434" — wrong on two
    counts` comment that documents the fix. A gate that fires on the prose
    describing a fix is worse than no gate: it trains people to ignore it.
    """
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if "#" in line and line.count('"') % 2 == 0 and line.count("'") % 2 == 0:
            line = line.split("#", 1)[0]
        out.append(line)
    return "\n".join(out)


def _compose_env(service: str) -> dict:
    doc = yaml.safe_load(COMPOSE.read_text())
    env = (doc.get("services", {}).get(service, {}) or {}).get("environment", {}) or {}
    if isinstance(env, list):
        out = {}
        for item in env:
            k, _, v = str(item).partition("=")
            out[k] = v
        return out
    return env


def _render_chart() -> list[dict]:
    """Render the chart. Skips (never soft-passes) if helm is unavailable."""
    if not shutil.which("helm"):
        pytest.skip("helm not installed — chart-render assertions cannot run")
    proc = subprocess.run(
        [
            "helm", "template", "contract-test", str(HELM_CHART),
            # validate-security.yaml fail-closes without this; supplying a
            # throwaway value exercises the real render path.
            "--set", "internalBearer.value=" + "0" * 64,
        ],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        pytest.fail(f"helm template failed:\n{proc.stderr[-2000:]}")
    return [d for d in yaml.safe_load_all(proc.stdout) if d]


def _containers(doc: dict):
    spec = doc.get("spec") or {}
    tmpl = (spec.get("template") or {}).get("spec")
    if tmpl is None:
        tmpl = ((spec.get("jobTemplate") or {}).get("spec", {})
                .get("template", {}).get("spec"))
    for group in ("initContainers", "containers"):
        for c in ((tmpl or {}).get(group) or []):
            yield doc.get("kind"), (doc.get("metadata") or {}).get("name", "?"), group, c


# ---------------------------------------------------------------------------
# 1. Duplicate-key class (LAURA-V50-001 / FIND-0824-DUP-SEMANTIC-INTENT)
# ---------------------------------------------------------------------------

def test_no_duplicate_env_keys_in_any_rendered_container():
    """No container may declare the same env name twice.

    Generalised deliberately to ALL env keys, not just backend URLs: the second
    instance of this class (FIND-0824-DUP-SEMANTIC-INTENT, on the DP-Y-003
    tool-poisoning classifier toggle) would have been missed by a
    backend-URL-only check.
    """
    offenders = []
    for doc in _render_chart():
        for kind, name, group, c in _containers(doc):
            keys = [e.get("name") for e in (c.get("env") or []) if isinstance(e, dict)]
            for k, n in collections.Counter(keys).items():
                if n > 1:
                    offenders.append(f"{kind}/{name} [{group}:{c.get('name')}] {k} x{n}")
    assert not offenders, (
        "Duplicate env key in a rendered container — Kubernetes takes the LAST "
        "value, so the later (often stale) entry silently becomes authoritative:\n  "
        + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# 2. Direct :11434 class (YSG-RISK-136 proper)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("service", INFERENCE_CLIENTS)
def test_compose_backend_url_is_not_a_direct_connection(service):
    env = _compose_env(service)
    for var in BACKEND_URL_VARS:
        val = str(env.get(var, ""))
        assert not _DIRECT_BACKEND_RE.search(val), (
            f"docker-compose.yml {service}.{var}={val!r} is a DIRECT backend "
            "connection. allow-ollama-ingress admits only the caddy pod on "
            ":11434 — use the mesh front (YSG-RISK-136)."
        )


def test_rendered_chart_has_no_direct_backend_url():
    """The render is authoritative: whatever a template's default is, what
    actually ships is what Kubernetes receives."""
    offenders = []
    for doc in _render_chart():
        for kind, name, group, c in _containers(doc):
            for e in (c.get("env") or []):
                if not isinstance(e, dict):
                    continue
                if e.get("name") in BACKEND_URL_VARS and _DIRECT_BACKEND_RE.search(
                    str(e.get("value", ""))
                ):
                    offenders.append(
                        f"{kind}/{name}[{c.get('name')}] {e['name']}={e.get('value')!r}"
                    )
    assert not offenders, (
        "Rendered chart ships a direct-:11434 backend URL — the exact drift "
        "YSG-RISK-136 closed:\n  " + "\n  ".join(offenders)
    )


def test_helm_values_backend_urls_are_not_direct_connections():
    hits = _DIRECT_BACKEND_RE.findall(_strip_comments(HELM_VALUES.read_text()))
    assert not hits, (
        f"helm/yashigani/values.yaml ships direct backend URL default(s): {hits}."
    )


# ---------------------------------------------------------------------------
# 3. "Actually SETS" class (FIND-0824-GATEWAY-OLLAMA-URL-LOST)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("service", INFERENCE_CLIENTS)
def test_compose_service_actually_sets_an_inference_backend_url(service):
    """Dropping the var entirely is not a pass.

    src/ reads OLLAMA_BASE_URL in a dozen places; unset, the code falls back to
    its own "http://ollama:11434" — the very direct connection YSG-RISK-136
    closed. The 2026-08-24 merge dropped it from the gateway block in favour of
    KUROSHIO_BASE_URL, which has ZERO readers in src/
    (FIND-0824-KUROSHIO-UNWIRED), leaving the inspection escalation path dead.
    """
    env = _compose_env(service)
    val = str(env.get("OLLAMA_BASE_URL", "")).strip()
    assert val, (
        f"docker-compose.yml {service} does not set OLLAMA_BASE_URL. "
        "KUROSHIO_BASE_URL does NOT substitute — nothing in src/ reads it yet."
    )


def test_rendered_gateway_and_backoffice_both_set_a_backend_url():
    found = {}
    for doc in _render_chart():
        for kind, name, group, c in _containers(doc):
            if group != "containers":
                continue
            for e in (c.get("env") or []):
                if isinstance(e, dict) and e.get("name") == "OLLAMA_BASE_URL":
                    found[name] = e.get("value")
    for svc in ("yashigani-gateway", "yashigani-backoffice"):
        assert found.get(svc), (
            f"{svc} does not set OLLAMA_BASE_URL in the rendered chart — this is "
            "fix (2) of YSG-RISK-136's own remediation."
        )
