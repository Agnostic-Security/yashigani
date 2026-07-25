"""
Regression test -- TD-2026-07-25-01: @langflow bundled agent doesn't
dispatch (405 / 502).

Two pre-existing bugs at 250b486d (4.1.2 line), both mirrored from the 5.0
line fix (commit ee820113 "route bundled langflow agent through its
mesh-aware client") so 4.1.2 and 5.0 do not diverge:

  (a) install.sh register_agent_bundles() registered agent__langflow with
      protocol="openai" (letta correctly uses protocol="letta") -> the
      gateway's dispatch fell into the generic OpenAI-compat branch
      (POST {upstream}/v1/chat/completions), which Langflow doesn't serve
      (it needs the auto_login + api_key + flow-run dance implemented in
      gateway/langflow_client.py::langflow_chat).

  (b) Even with (a) fixed, that SAME generic branch also builds a bare
      httpx.AsyncClient() (no client cert) against the registered upstream.
      For a Caddy MESH-INGRESS-FRONTED agent (https://caddy:<port>/agents/
      <tenant>/<system>, terminating mTLS require_and_verify against the
      internal CA -- see gateway/_dispatch_client.py), a bare client fails
      CERTIFICATE_VERIFY_FAILED at the TLS handshake. openclaw legitimately
      dispatches through this same generic branch against the same kind of
      mesh front, so it carries the identical bug -- the fix must therefore
      detect mesh-front upstreams (any protocol) and swap to
      agent_dispatch_client(), while leaving genuinely-external
      admin-registered upstreams (https://agent.example.com) on the bare
      client (they are not behind our internal mesh CA).

This test proves (a) statically against install.sh's source and (b) both
statically (source-level: the mesh-front regex + agent_dispatch_client swap
are present and reachable) and behaviourally (the regex correctly
classifies mesh-front vs external upstream strings).

NOT covered here (requires a live rebuilt stack, see brief part (c)):
end-to-end proof that langflow_chat() actually returns a completion --
that needs a running Langflow container reachable through the mesh front.
_ensure_initialized() in gateway/langflow_client.py self-provisions a
default "Yashigani Chat" flow from Langflow's "Basic Prompting" starter
template on first call, so no additional demo-content wiring is required
once (a)+(b) land and the gateway/backoffice images are rebuilt -- but that
self-provisioning path itself needs a live Langflow container to exercise.

Last updated: 2026-07-25T00:00:00+01:00
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-token-for-unit-tests")

REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"
OPENAI_ROUTER = REPO_ROOT / "src" / "yashigani" / "gateway" / "openai_router.py"


class TestInstallShLangflowProtocolRegistration:
    """(a) install.sh must register agent__langflow with protocol="langflow",
    never "openai" -- matching letta's protocol="letta" pattern."""

    def test_langflow_case_registers_langflow_protocol(self):
        source = INSTALL_SH.read_text()
        # Isolate the `langflow)` case arm inside register_agent_bundles()'s
        # case statement -- from the "langflow)" label up to the next
        # top-level case arm ("letta)").
        m = re.search(
            r'langflow\)\s+local _name="agent__langflow".*?(?=\n\s+letta\)\s+local)',
            source,
            re.DOTALL,
        )
        assert m is not None, (
            "Could not locate the langflow case arm in "
            "register_agent_bundles() -- install.sh structure changed; "
            "update this test's regex."
        )
        arm = m.group(0)
        assert '_proto="langflow"' in arm, (
            "TD-2026-07-25-01(a) regression: install.sh must register "
            'agent__langflow with _proto="langflow", not "openai" -- '
            "otherwise dispatch falls into the generic OpenAI-compat branch "
            "which Langflow does not serve."
        )
        assert '_proto="openai"' not in arm

    def test_letta_registration_unaffected_reference_pattern(self):
        """Sanity: letta's protocol registration (the pattern langflow now
        matches) is untouched."""
        source = INSTALL_SH.read_text()
        assert re.search(
            r'letta\)\s+local _name="letta".*?_proto="letta"', source, re.DOTALL
        ), "letta registration pattern moved/changed -- re-verify langflow mirrors it."


class TestOpenaiRouterMeshFrontDispatch:
    """(b) the generic OpenAI-compat dispatch branch must present the mesh
    client leaf (agent_dispatch_client()) for Caddy mesh-ingress-front
    upstreams, and keep the bare httpx client only for genuinely external
    admin-registered upstreams."""

    # Kept in sync with openai_router.py's inline `_mesh_front_re` (mirrors
    # backoffice/bundled_envelopes.py::_FRONT_UPSTREAM_RE, ee820113).
    _MESH_FRONT_RE = re.compile(
        r"^https://caddy:\d{4,5}/agents/[a-zA-Z0-9][a-zA-Z0-9\-_]{0,62}"
        r"/[a-zA-Z0-9][a-zA-Z0-9\-_]{0,62}/?$"
    )

    def test_source_wires_mesh_front_detection_before_bare_client(self):
        source = OPENAI_ROUTER.read_text()
        assert "_mesh_front_re" in source, (
            "TD-2026-07-25-01(b) regression: openai_router.py's generic "
            "agent-dispatch branch must detect Caddy mesh-ingress-front "
            "upstreams before choosing an httpx client."
        )
        assert "from yashigani.gateway._dispatch_client import agent_dispatch_client" in source
        # The bare client must be reachable only in the non-mesh-front else
        # branch, not unconditionally.
        assert "_agent_client_cm = httpx.AsyncClient(timeout=120.0)" in source
        assert "_agent_client_cm = agent_dispatch_client(timeout=120.0)" in source

    @pytest.mark.parametrize(
        "upstream,expected",
        [
            ("https://caddy:9705/agents/default/langflow", True),
            ("https://caddy:9671/agents/default/openclaw", True),
            ("https://caddy:9775/agents/default/letta", True),
            ("https://caddy:65535/agents/tenant-1/system-2", True),
            # Genuinely external admin-registered upstream -- must NOT match.
            ("https://agent.example.com/v1", False),
            ("https://agent.example.com", False),
            # Not the mesh front shape even though it mentions caddy.
            ("https://caddy.evil.example:9705/agents/default/langflow", False),
            ("http://caddy:9705/agents/default/langflow", False),  # http, not https
            ("", False),
        ],
    )
    def test_mesh_front_regex_classifies_correctly(self, upstream, expected):
        assert bool(self._MESH_FRONT_RE.match(upstream)) is expected

    def test_regex_literal_matches_openai_router_source(self):
        """Guards against the test's copy of the regex silently drifting
        from the real one in openai_router.py -- if someone changes the
        pattern there, this test must be updated too (not silently pass
        against a stale duplicate)."""
        source = OPENAI_ROUTER.read_text()
        pattern_source = (
            'r"^https://caddy:\\d{4,5}/agents/[a-zA-Z0-9][a-zA-Z0-9\\-_]{0,62}"\n'
        )
        assert pattern_source.strip() in source or (
            r"^https://caddy:\d{4,5}/agents/[a-zA-Z0-9][a-zA-Z0-9\-_]{0,62}" in source
        ), "openai_router.py's _mesh_front_re pattern text changed -- update this test's copy."


class TestNoHelmBundledAgentRegistration:
    """Documents (does not "fix") that Helm has no bundled-agent
    registration mechanism equivalent to install.sh's
    register_agent_bundles() -- compose-only, per Captain's finding. If a
    helm registration path is ever added, it must also use protocol=
    "langflow" for langflow, and this test should be extended to cover it."""

    def test_no_helm_agent_registration_script_exists(self):
        """Scoped to actual registration LOGIC (register_agent_bundles or an
        equivalent bash/python registration call), not incidental references
        to the agent_id string -- policy/agents.rego legitimately references
        "agent__langflow" as a policy subject and is not a registration
        mechanism, so it's excluded from this check."""
        helm_dir = REPO_ROOT / "helm"
        if not helm_dir.exists():
            pytest.skip("no helm/ directory in this checkout")
        hits = []
        for path in helm_dir.rglob("*"):
            if path.is_file() and path.suffix in (".sh", ".py", ".yaml", ".yml"):
                try:
                    text = path.read_text(errors="ignore")
                except (UnicodeDecodeError, OSError):
                    continue
                if "register_agent_bundles" in text:
                    hits.append(str(path))
        assert hits == [], (
            "A Helm file now defines/calls register_agent_bundles -- Helm "
            "has grown a bundled-agent registration path since this test "
            "was written; verify it also uses protocol=\"langflow\" and "
            "update this test's assumption."
        )
