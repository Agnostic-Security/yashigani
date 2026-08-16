"""
Agent OPENAI_API_BASE port contract (BUG-V241-LANGFLOW-LETTA-BASE-URL regression gate).

Static contract: asserts that every agent bundle that calls back to the gateway
(langflow, letta, openclaw) routes through the plain-HTTP mesh port (8081), NOT
the mTLS-only port (8080).

Background
----------
Gateway exposes two listeners:
  :8080 — full mTLS (ssl.CERT_REQUIRED); requires client cert on every connection.
  :8081 — plain HTTP; protected by network isolation (langflow_isolated /
           letta_isolated / openclaw_isolated bridges, Docker internal networks).

Langflow, letta, and openclaw run with cap_drop:[ALL] and mount no client certs
— they cannot complete a TLS handshake with :8080.  They MUST use :8081.

Open WebUI was fixed to use :8081 in v2.23.4.  Langflow and letta were fixed
by e4f38f8.  Openclaw was missed because its gateway URL is in a JSON config
file (openclaw.json), not an env var — Ava cycle 5 discovered it (BUG-V241-
OPENCLAW-EXTENDED, 2026-05-25).

These tests:
  - FAIL against docker-compose.yml pre-Su-fix (8080 values present)
  - PASS after Su's fix (8080 → 8081)
  - Are added to the CI gate (ci.yml unit-test run) so they catch regression
    before any compose change ships

Extended (BUG-V241-OPENCLAW-EXTENDED / YSG-RISK-230): cover JSON config files
(openclaw.json baseUrl) and Helm env vars (OPENCLAW_UPSTREAM_URL) per
[[feedback_brief_cue_adjacent_abstractions]] — assertion scope is now
"every gateway-URL reference in any agent config (env var, JSON, YAML) uses
:8081, never :8080".

A1 amendment principle: absence of a dispatch test = SKIP, not PASS.
Prior E2E sweeps proved container-healthy and route-existence but NOT the
OPENAI_API_BASE callback leg.  This gate closes that assumption gap.

YSG-RISK-059 / YSG-RISK-230 / OWASP ASVS v5 V11.1 / A1 amendment.

Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parents[2]
_COMPOSE_FILE = _REPO_ROOT / "docker" / "docker-compose.yml"
_HELM_VALUES_FILE = _REPO_ROOT / "helm" / "yashigani" / "values.yaml"

# Canonical ports (see docker-compose.yml comments + mesh_entrypoint.py)
_MESH_PORT = 8081   # plain-HTTP internal mesh — agents MUST target this
_MTLS_PORT = 8080   # mTLS-only — agents MUST NOT use this as OPENAI_API_BASE


def _compose_text() -> str:
    assert _COMPOSE_FILE.exists(), f"Compose file not found: {_COMPOSE_FILE}"
    return _COMPOSE_FILE.read_text()


def _extract_service_section(compose_text: str, service_name: str) -> str:
    """
    Extract a service section from compose YAML text.

    Returns lines from the '  <service_name>:' header up to (but not including)
    the next sibling service definition at the same 2-space indent level.
    Sufficient for OPENAI_API_BASE extraction.
    """
    lines = compose_text.splitlines()
    result_lines: list[str] = []
    inside = False

    for line in lines:
        if re.match(rf'^  {re.escape(service_name)}:', line):
            inside = True
            result_lines = [line]
            continue
        if inside:
            # Stop at next sibling (2-space indent, letter, colon) — not a deeper level
            if re.match(r'^  [a-zA-Z_-]', line) and not line.startswith('   '):
                break
            result_lines.append(line)

    return '\n'.join(result_lines)


class TestAgentBaseUrlPort:
    """
    Regression gate for BUG-V241-LANGFLOW-LETTA-BASE-URL.

    Asserts that agent OPENAI_API_BASE values use port 8081 (mesh) not 8080 (mTLS).
    """

    def test_langflow_openai_api_base_uses_mesh_port(self):
        """
        Langflow MUST use http://gateway:8081/v1, NOT http://gateway:8080/v1.

        Port 8080 requires mutual TLS; langflow presents no client cert.
        Every langflow inference call fails silently with TLS handshake error
        when this is misconfigured.

        FAILS pre-Su-fix: OPENAI_API_BASE: http://gateway:8080/v1
        PASSES post-Su-fix: OPENAI_API_BASE: http://gateway:8081/v1

        Regression: BUG-V241-LANGFLOW-LETTA-BASE-URL / YSG-RISK-059.
        Control: ASVS V11.1 (Application Logic) / A1 amendment principle.
        """
        text = _compose_text()
        section = _extract_service_section(text, "langflow")
        assert section, "langflow service section not found in docker-compose.yml"

        match = re.search(r'OPENAI_API_BASE:\s*(\S+)', section)
        assert match, "OPENAI_API_BASE not found in langflow service section"

        url = match.group(1)
        # v4.1 three-agent wrap (2026-07-07): the base URL now dials
        # langflow's egress FORWARDER; the :8081 mesh-port hop moved to the
        # :18790 /deliver/llm handle (tests/invariants/
        # test_openclaw_egress_gateway.py::test_llm_eval_and_deliver_handles_present).
        assert url == "http://egress-langflow:9400/llm/v1", (
            f"langflow OPENAI_API_BASE must dial its egress forwarder.\n"
            f"  Current value: {url}\n"
            f"  Required:      http://egress-langflow:9400/llm/v1\n"
            f"  A direct gateway URL here reopens the sidecar bypass "
            f"(unified-sidecar design §2.4)."
        )
        assert f":{_MTLS_PORT}" not in url, (
            f"langflow OPENAI_API_BASE uses mTLS port {_MTLS_PORT}: {url}"
        )

    def test_letta_openai_api_base_uses_mesh_port(self):
        """
        Letta MUST use http://gateway:8081/v1, NOT http://gateway:8080/v1.

        Same rationale as langflow. Letta also has cap_drop:[ALL] and no
        client cert mount for the gateway mTLS listener.

        Note: letta-pgbouncer appears before letta in the compose services
        block.  _extract_service_section matches on '^  letta:' which is
        the standalone service name (not letta-pgbouncer:), so extraction
        is unambiguous.

        FAILS pre-Su-fix: OPENAI_API_BASE: http://gateway:8080/v1
        PASSES post-Su-fix: OPENAI_API_BASE: http://gateway:8081/v1

        Regression: BUG-V241-LANGFLOW-LETTA-BASE-URL / YSG-RISK-059.
        """
        text = _compose_text()
        section = _extract_service_section(text, "letta")
        assert section, "letta service section not found in docker-compose.yml"

        match = re.search(r'OPENAI_API_BASE:\s*(\S+)', section)
        assert match, f"OPENAI_API_BASE not found in letta service section. Section: {section[:300]}"

        url = match.group(1)
        # v4.1 three-agent wrap (2026-07-07): forwarder URL — see langflow note.
        assert url == "http://egress-letta:9400/llm/v1", (
            f"letta OPENAI_API_BASE must dial its egress forwarder.\n"
            f"  Current value: {url}\n"
            f"  Required:      http://egress-letta:9400/llm/v1\n"
            f"  A direct gateway URL here reopens the sidecar bypass "
            f"(unified-sidecar design §2.4)."
        )
        assert f":{_MTLS_PORT}" not in url, (
            f"letta OPENAI_API_BASE uses mTLS port {_MTLS_PORT}: {url}"
        )

    def test_open_webui_openai_api_base_url_uses_mesh_port(self):
        """
        Open WebUI MUST use http://gateway:8081/v1 (via OPENAI_API_BASE_URL).

        This is the correct reference implementation (fixed in v2.23.4).
        This test guards against regression to port 8080.
        """
        text = _compose_text()
        section = _extract_service_section(text, "open-webui")
        if not section:
            pytest.skip("open-webui removed in 4.0 (ui4 SPA served by backoffice)")

        match = re.search(r'OPENAI_API_BASE_URL:\s*(\S+)', section)
        assert match, "OPENAI_API_BASE_URL not found in open-webui service section"

        url = match.group(1)
        assert f":{_MESH_PORT}" in url, (
            f"open-webui OPENAI_API_BASE_URL does not use mesh port {_MESH_PORT}: {url}"
        )

    def test_all_agent_base_urls_use_same_mesh_port(self):
        """
        Parity: langflow, letta, and open-webui MUST all point at port 8081.

        Any divergence is a misconfiguration — one service will fail while
        others succeed, making the bug non-obvious.

        Documents the invariant: every service that calls the gateway for LLM
        inference MUST use the internal mesh port (8081), never the mTLS port.
        """
        # v4.1 three-agent wrap (2026-07-07): each agent dials ITS OWN
        # egress forwarder — same port (9400), per-agent host. The :8081
        # mesh-port invariant moved to the :18790 /deliver/llm handle.
        text = _compose_text()
        urls: dict[str, str] = {}
        expected = {
            "langflow": "http://egress-langflow:9400/llm/v1",
            "letta": "http://egress-letta:9400/llm/v1",
        }

        for service, env_var in [
            ("langflow",   "OPENAI_API_BASE"),
            ("letta",      "OPENAI_API_BASE"),
        ]:
            section = _extract_service_section(text, service)
            if not section:
                continue
            match = re.search(rf'{re.escape(env_var)}:\s*(\S+)', section)
            if match:
                urls[service] = match.group(1)

        assert len(urls) == 2, f"Could not extract agent base URLs: {urls}"
        wrong = {svc: u for svc, u in urls.items() if u != expected[svc]}
        assert not wrong, (
            "Agents not dialling their own egress forwarder:\n"
            + "\n".join(f"  {svc}: {u} (expected {expected[svc]})" for svc, u in wrong.items())
        )

    def test_no_agent_uses_mtls_port_as_base_url(self):
        """
        Exhaustive scan: no service's OPENAI_API_BASE / OPENAI_API_BASE_URL
        should reference gateway:8080.

        Catches new agent bundles added without the mesh-port requirement.
        """
        text = _compose_text()

        # Find all OPENAI_API_BASE* values across the entire compose file
        wrong_instances = []
        for match in re.finditer(
            r'(OPENAI_API_BASE(?:_URL)?:\s*(http://gateway:\d+/v1))',
            text
        ):
            full_match = match.group(1)
            url = match.group(2)
            if f":{_MTLS_PORT}" in url:
                # Find the service this belongs to (look backwards for service name)
                pos = match.start()
                preceding = text[:pos]
                service_matches = list(re.finditer(r'^  ([a-zA-Z_-]+):', preceding, re.MULTILINE))
                service_name = service_matches[-1].group(1) if service_matches else "unknown"
                wrong_instances.append(f"  {service_name}: {full_match.strip()}")

        assert not wrong_instances, (
            f"Found services using mTLS port {_MTLS_PORT} as OPENAI_API_BASE:\n"
            + "\n".join(wrong_instances)
            + f"\n\nFix: change all instances to gateway:{_MESH_PORT}/v1\n"
            f"BUG-V241-LANGFLOW-LETTA-BASE-URL / YSG-RISK-059"
        )


class TestHelmAgentBaseUrlPort:
    """
    Helm values.yaml parity: same port assertion as compose.

    The CHANGELOG entry for BUG-V241-LANGFLOW-LETTA-BASE-URL documents that
    both docker-compose.yml AND helm/yashigani/values.yaml were affected.
    This class guards both surfaces.
    """

    def _helm_text(self) -> str:
        assert _HELM_VALUES_FILE.exists(), f"Helm values.yaml not found: {_HELM_VALUES_FILE}"
        return _HELM_VALUES_FILE.read_text()

    def test_helm_langflow_openai_api_base_uses_mesh_port(self):
        """
        Helm values: langflow OPENAI_API_BASE must use yashigani-gateway:8081, not :8080.
        """
        text = self._helm_text()
        # Find all OPENAI_API_BASE values in Helm values.yaml
        # Helm uses yashigani-gateway (service name) instead of gateway
        matches = list(re.finditer(r'OPENAI_API_BASE:\s*"?(http://[^"\s]+)"?', text))
        assert matches, "No OPENAI_API_BASE found in Helm values.yaml"

        # v4.1 three-agent wrap (2026-07-07): Helm agents dial their egress
        # forwarder Services (yashigani-egress-<agent>:9400/llm/v1).
        allowed = {
            "http://yashigani-egress-langflow:9400/llm/v1",
            "http://yashigani-egress-letta:9400/llm/v1",
        }
        for match in matches:
            url = match.group(1).strip('"')
            assert f":{_MTLS_PORT}" not in url, (
                f"Helm values.yaml OPENAI_API_BASE uses mTLS port {_MTLS_PORT}: {url}"
            )
            assert url in allowed, (
                f"Helm values.yaml OPENAI_API_BASE not a per-agent forwarder URL: {url}\n"
                f"  Allowed: {sorted(allowed)}\n"
                f"  A direct gateway URL reopens the sidecar bypass (design §2.4)."
            )

    def test_helm_no_agent_uses_mtls_port_as_base_url(self):
        """
        Exhaustive scan of Helm values.yaml: no OPENAI_API_BASE should reference
        the mTLS port (8080). Catches new agent bundles added without the mesh-port
        requirement in the Helm chart.
        """
        text = self._helm_text()
        wrong = []
        for match in re.finditer(r'OPENAI_API_BASE:\s*"?(http://[^"\s]+)"?', text):
            url = match.group(1).strip('"')
            if f":{_MTLS_PORT}" in url:
                wrong.append(url)

        assert not wrong, (
            f"Helm values.yaml has OPENAI_API_BASE using mTLS port {_MTLS_PORT}:\n"
            + "\n".join(f"  {u}" for u in wrong)
            + f"\n  Fix: change to port {_MESH_PORT}. BUG-V241-LANGFLOW-LETTA-BASE-URL."
        )

    def test_helm_openclaw_upstream_url_uses_mesh_port(self):
        """
        Helm values: OPENCLAW_UPSTREAM_URL must use yashigani-gateway:8081, not :8080.

        openclaw has cap_drop:[ALL] and mounts no client cert — it cannot complete
        the mTLS handshake on :8080. OPENCLAW_UPSTREAM_URL is the Helm-side
        equivalent of openclaw.json baseUrl; both must target :8081.

        BUG-V241-OPENCLAW-EXTENDED / YSG-RISK-230.
        """
        text = self._helm_text()
        match = re.search(r'OPENCLAW_UPSTREAM_URL:\s*"?(http://[^"\s]+)"?', text)
        if match is None:
            pytest.skip("OPENCLAW_UPSTREAM_URL not found in Helm values.yaml")

        url = match.group(1).strip('"')
        assert f":{_MTLS_PORT}" not in url, (
            f"Helm OPENCLAW_UPSTREAM_URL uses mTLS port {_MTLS_PORT}: {url}\n"
            f"  Fix: change to http://yashigani-gateway:{_MESH_PORT}\n"
            f"  BUG-V241-OPENCLAW-EXTENDED / YSG-RISK-230"
        )
        assert f":{_MESH_PORT}" in url, (
            f"Helm OPENCLAW_UPSTREAM_URL uses unexpected port: {url}\n"
            f"  Expected port {_MESH_PORT} (plain-HTTP mesh). BUG-V241-OPENCLAW-EXTENDED."
        )


class TestOpenclawJsonConfig:
    """
    Regression gate for BUG-V241-OPENCLAW-EXTENDED.

    openclaw reads its gateway URL from docker/openclaw/openclaw.json (the
    baseUrl field in the providers.yashigani block). This file is mounted
    read-only into the openclaw container at /etc/openclaw/openclaw.json.

    Prior contract tests only checked env vars (OPENAI_API_BASE*). openclaw's
    JSON config was missed — Ava cycle 5 caught it at runtime.

    Per [[feedback_brief_cue_adjacent_abstractions]]: any assertion about
    agent gateway-URL routing MUST cover ALL config surfaces — env var,
    JSON, YAML — not just the one format tested first.

    YSG-RISK-230.
    """

    _OPENCLAW_JSON = _REPO_ROOT / "docker" / "openclaw" / "openclaw.json"

    def test_openclaw_json_exists(self):
        """openclaw.json must exist — it is the authoritative config for compose installs."""
        assert self._OPENCLAW_JSON.exists(), (
            f"docker/openclaw/openclaw.json not found at {self._OPENCLAW_JSON}.\n"
            f"  This file is required: openclaw reads baseUrl from it at startup."
        )

    def test_openclaw_json_base_url_port(self):
        """
        openclaw.json baseUrl must use gateway:8081 (plain-HTTP mesh), not :8080 (mTLS).

        Port 8080 requires mutual TLS; openclaw presents no client cert (cap_drop:[ALL],
        no cert mount per PROBE-AG1 fix). Every openclaw inference call fails with a
        TLS handshake error when baseUrl points at :8080.

        FAILS pre-Su-fix: "baseUrl": "http://gateway:8080/v1"
        PASSES post-Su-fix: "baseUrl": "http://gateway:8081/v1"

        BUG-V241-OPENCLAW-EXTENDED / YSG-RISK-230.
        """
        if not self._OPENCLAW_JSON.exists():
            pytest.skip("openclaw.json not found")

        data = json.loads(self._OPENCLAW_JSON.read_text())
        providers = data.get("models", {}).get("providers", {})
        assert "yashigani" in providers, (
            f"openclaw.json: models.providers.yashigani block not found.\n"
            f"  Keys present: {list(providers.keys())}"
        )

        base_url = providers["yashigani"].get("baseUrl", "")
        assert base_url, "openclaw.json: models.providers.yashigani.baseUrl is missing or empty"
        # v4.1 three-agent wrap (2026-07-07): baseUrl dials the openclaw
        # egress forwarder; the :8081 hop moved to the :18790 /deliver/llm
        # handle. A direct gateway URL reopens the sidecar bypass.
        assert base_url == "http://egress-openclaw:9400/llm/v1", (
            f"openclaw.json baseUrl must dial the egress forwarder.\n"
            f"  Current value: {base_url!r}\n"
            f"  Required:      http://egress-openclaw:9400/llm/v1"
        )
        assert f":{_MTLS_PORT}" not in base_url, (
            f"openclaw.json baseUrl uses mTLS port {_MTLS_PORT}: {base_url!r}\n"
            f"  BUG-V241-OPENCLAW-EXTENDED — the mTLS listener requires a "
            f"client cert openclaw does not hold."
        )

    def test_openclaw_json_base_url_scheme(self):
        """
        openclaw.json baseUrl must use http:// (not https://).

        The mesh port :8081 is plain HTTP protected by network isolation
        (openclaw_isolated internal bridge). Using https:// would cause TLS
        negotiation against a plain-HTTP listener — connection reset.
        """
        if not self._OPENCLAW_JSON.exists():
            pytest.skip("openclaw.json not found")

        data = json.loads(self._OPENCLAW_JSON.read_text())
        base_url = data.get("models", {}).get("providers", {}).get("yashigani", {}).get("baseUrl", "")
        if not base_url:
            pytest.skip("baseUrl not found in openclaw.json")

        assert base_url.startswith("http://"), (
            f"openclaw.json baseUrl must use http:// (plain, not TLS).\n"
            f"  Current: {base_url!r}\n"
            f"  The mesh port {_MESH_PORT} is plain HTTP — https:// would fail."
        )

    def test_openclaw_json_no_gateway_mtls_port_anywhere(self):
        """
        Exhaustive scan: no field in openclaw.json should reference gateway:8080.

        Catches future additions of new provider blocks or endpoint overrides that
        inadvertently point at the mTLS-only port.

        BUG-V241-OPENCLAW-EXTENDED / YSG-RISK-230 — class-level assertion.
        """
        if not self._OPENCLAW_JSON.exists():
            pytest.skip("openclaw.json not found")

        raw = self._OPENCLAW_JSON.read_text()
        assert f"gateway:{_MTLS_PORT}" not in raw, (
            f"openclaw.json contains gateway:{_MTLS_PORT} reference.\n"
            f"  All gateway URLs must use port {_MESH_PORT} (plain-HTTP mesh).\n"
            f"  BUG-V241-OPENCLAW-EXTENDED / YSG-RISK-230"
        )
