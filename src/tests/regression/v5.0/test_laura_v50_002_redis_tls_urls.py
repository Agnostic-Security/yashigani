"""
Regression test — LAURA-V50-002 (Critical): A5 model-integrity, multi-turn
conversation-risk, T1 rule-promotion, and the MCP rug-pull manifest-reapproval
gate all constructed their Redis client from a hardcoded PLAINTEXT
"redis://redis:6379/1" fallback (via
os.getenv("YASHIGANI_REDIS_URL", "redis://redis:6379/1")). The deployment's
Redis is TLS-only on 6380 and rejects plaintext connections outright, so
every one of these was 100%-reproducibly unreachable in the default
docker-compose.yml deploy:

  - A5 model-integrity pin store  -> fails CLOSED -> blocks every local-model
    completion (full inference outage, incl. /v1/embeddings).
  - Multi-turn conversation-risk accumulator -> fails OPEN -> the slow-burn
    detector never accumulates across requests (silently permanently inert).
  - T1 rule-promotion store -> persistence broken.
  - MCP rug-pull manifest-reapproval gate -> same anti-pattern.
  - backoffice agent_policies._registry_store() -> same anti-pattern (this
    site is NOT observed broken live because docker-compose.yml DOES set
    YASHIGANI_REDIS_URL correctly for the backoffice service — but it was a
    latent trap for any deploy that omits the env var, so it is fixed too).

Fix: route all five sites through the shared TLS-aware build_redis_url()
helper (gateway/_redis_url.py) instead of the hardcoded plaintext fallback,
and hoist the gateway's `_gw_redis_url` closure above the A5/
conversation-risk/rule-promotion blocks (which previously pre-dated its
definition in entrypoint.py).

These tests prove, via AST/source inspection (importing entrypoint.py at
module level requires a live secrets dir / KMS / OPA env this unit-test
context does not have — same convention as
test_backoffice_break_glass_redis_timeout.py):

  A. Zero remaining occurrences of the broken pattern
     `os.getenv("YASHIGANI_REDIS_URL", "redis://redis:6379` anywhere in
     entrypoint.py or agent_policies.py.
  B. All five fixed call sites now route through build_redis_url() /
     _gw_redis_url() (gateway_client cert for gateway sites,
     backoffice_client cert for the backoffice site).
  C. `_gw_redis_url` is DEFINED before the A5/conversation-risk/
     rule-promotion blocks that use it (the ordering bug called out in the
     brief — those blocks are textually earlier in _build_app than the
     helper's old definition site).
  D. build_redis_url(), called exactly the way _gw_redis_url(1) calls it
     (use_tls=True, client_cert_name="gateway_client"), against the SAME
     env vars docker-compose.yml sets for the gateway (REDIS_HOST=redis,
     REDIS_PORT=6380, REDIS_USE_TLS=true) produces a rediss:// URL on 6380
     with the gateway client cert — never plaintext 6379.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from yashigani.gateway._redis_url import build_redis_url

SRC = Path(__file__).parent.parent.parent.parent / "yashigani"
GATEWAY_ENTRYPOINT_SRC = SRC / "gateway" / "entrypoint.py"
AGENT_POLICIES_SRC = SRC / "backoffice" / "routes" / "agent_policies.py"

_BROKEN_PATTERN = 'os.getenv("YASHIGANI_REDIS_URL", "redis://redis:6379'


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# A — the broken pattern is gone everywhere
# ---------------------------------------------------------------------------

class TestBrokenPatternEliminated:
    def test_entrypoint_has_no_hardcoded_plaintext_fallback(self):
        src = _read(GATEWAY_ENTRYPOINT_SRC)
        assert _BROKEN_PATTERN not in src, (
            "gateway/entrypoint.py still contains the hardcoded plaintext "
            "redis://redis:6379 fallback (LAURA-V50-002 regression)"
        )

    def test_agent_policies_has_no_hardcoded_plaintext_fallback(self):
        src = _read(AGENT_POLICIES_SRC)
        assert _BROKEN_PATTERN not in src, (
            "backoffice/routes/agent_policies.py still contains the "
            "hardcoded plaintext redis://redis:6379 fallback "
            "(LAURA-V50-002 regression)"
        )

    def test_no_bare_redis_6379_literal_in_executable_code(self):
        # Belt-and-braces: no *code* line (as opposed to an explanatory
        # "# LAURA-V50-002: was ..." comment documenting the historical bug)
        # references the plaintext port.
        src = _read(GATEWAY_ENTRYPOINT_SRC)
        offending = [
            line for line in src.splitlines()
            if "6379" in line and not line.strip().startswith("#")
        ]
        assert not offending, f"code lines still reference plaintext 6379: {offending}"


# ---------------------------------------------------------------------------
# B — all five call sites now use the TLS-aware builder
# ---------------------------------------------------------------------------

class TestFixedCallSitesUseTlsBuilder:
    def _gateway_tree(self):
        return ast.parse(_read(GATEWAY_ENTRYPOINT_SRC))

    def _calls_to(self, tree, func_name: str):
        """Return AST Call nodes calling a bare-name function (e.g. _gw_redis_url)."""
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == func_name:
                    out.append(node)
        return out

    def test_gw_redis_url_defined_exactly_once(self):
        tree = self._gateway_tree()
        defs = [n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "_gw_redis_url"]
        assert len(defs) == 1, f"_gw_redis_url should be defined once; found {len(defs)}"

    def test_gw_redis_url_called_at_least_four_times(self):
        # A5 pin store, conversation-risk, rule-promotion, manifest-reapproval
        # (plus the many pre-existing healthy call sites — rate limiter, RBAC,
        # JWT inspector, etc.) all call _gw_redis_url(...).
        tree = self._gateway_tree()
        calls = self._calls_to(tree, "_gw_redis_url")
        assert len(calls) >= 12, (
            f"expected _gw_redis_url to be called at every gateway Redis "
            f"call site (>=12, including the 4 newly-fixed ones); found "
            f"{len(calls)}"
        )

    def test_a5_conversation_promotion_manifest_sites_call_gw_redis_url_db1(self):
        """Each of the 4 previously-broken sites now calls _gw_redis_url(1)
        and carries a LAURA-V50-002 fix marker comment."""
        src = _read(GATEWAY_ENTRYPOINT_SRC)
        assert src.count("LAURA-V50-002") >= 4, (
            f"expected >=4 LAURA-V50-002 fix-marker comments (hoist + 4 "
            f"call sites); found {src.count('LAURA-V50-002')}"
        )
        assert src.count("_gw_redis_url(1)") >= 4, (
            f"expected _gw_redis_url(1) at all 4 previously-broken sites "
            f"(A5, conversation-risk, rule-promotion, manifest-reapproval) "
            f"plus the pre-existing JWT/pubsub/alias db-1 sites; found "
            f"{src.count('_gw_redis_url(1)')}"
        )

    def test_agent_policies_uses_build_redis_url_with_backoffice_client(self):
        src = _read(AGENT_POLICIES_SRC)
        assert "from yashigani.gateway._redis_url import build_redis_url" in src
        assert 'client_cert_name="backoffice_client"' in src


# ---------------------------------------------------------------------------
# C — ordering: _gw_redis_url is defined BEFORE the blocks that call it
# ---------------------------------------------------------------------------

class TestOrderingFix:
    def test_gw_redis_url_defined_before_a5_block(self):
        src = _read(GATEWAY_ENTRYPOINT_SRC)
        def_idx = src.index("def _gw_redis_url(")
        a5_idx = src.index("A5 (5.0): ollama model-integrity verifier")
        assert def_idx < a5_idx, (
            "_gw_redis_url must be defined BEFORE the A5 model-integrity "
            "block (which calls it) — this was the ordering bug the brief "
            "called out"
        )

    def test_gw_redis_url_defined_before_conversation_risk_block(self):
        src = _read(GATEWAY_ENTRYPOINT_SRC)
        def_idx = src.index("def _gw_redis_url(")
        cr_idx = src.index("multi-turn conversational-injection tracker")
        assert def_idx < cr_idx

    def test_gw_redis_url_defined_before_rule_promotion_block(self):
        src = _read(GATEWAY_ENTRYPOINT_SRC)
        def_idx = src.index("def _gw_redis_url(")
        rp_idx = src.index("5.0 T1: LLM→mechanical rule promotion")
        assert def_idx < rp_idx


# ---------------------------------------------------------------------------
# D — build_redis_url(), called the way _gw_redis_url(1) calls it, against the
#     SAME env vars docker-compose.yml sets for the gateway, is TLS/6380 and
#     never plaintext 6379.
# ---------------------------------------------------------------------------

class TestBuildRedisUrlMatchesGatewayEnv:
    @pytest.fixture
    def gateway_env(self, monkeypatch, tmp_path):
        # Mirror docker/docker-compose.yml gateway service env block.
        monkeypatch.setenv("REDIS_HOST", "redis")
        monkeypatch.setenv("REDIS_PORT", "6380")
        monkeypatch.setenv("REDIS_USE_TLS", "true")
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "redis_password").write_text("testpw123")
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets_dir))
        return str(secrets_dir)

    def test_db1_url_is_tls_on_6380_with_gateway_cert(self, gateway_env):
        # Exactly how _gw_redis_url(1) calls build_redis_url() at the 4
        # newly-fixed sites (A5, conversation-risk, rule-promotion,
        # manifest-reapproval).
        url = build_redis_url(
            1,
            use_tls=True,
            secrets_dir=gateway_env,
            client_cert_name="gateway_client",
        )
        assert url.startswith("rediss://"), url
        assert ":6380@" in url or ":6380/" in url, url
        assert "/1?" in url, url
        assert "gateway_client.crt" in url
        assert "gateway_client.key" in url
        assert "6379" not in url

    def test_db3_url_for_backoffice_agent_policies_site(self, gateway_env):
        # Exactly how the fixed _registry_store() in agent_policies.py calls
        # build_redis_url() (db 3, backoffice_client cert).
        url = build_redis_url(
            3,
            use_tls=True,
            secrets_dir=gateway_env,
            client_cert_name="backoffice_client",
        )
        assert url.startswith("rediss://"), url
        assert ":6380" in url, url
        assert "/3?" in url, url
        assert "backoffice_client.crt" in url
        assert "6379" not in url
