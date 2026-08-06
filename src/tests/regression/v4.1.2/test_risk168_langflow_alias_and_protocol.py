"""
Regression tests — YSG-RISK-168 (chat-path repair, 2026-07-30).

Two independent bugs on the bundled `@langflow` agent, both live-confirmed
against the docker-leg stack:

1. Alias mismatch: install.sh registers the bundled Langflow agent as
   `agent__langflow` (double underscore). backoffice/routes/user_agents.py's
   `list_user_mentions()` derives the mention-menu handle via
   `_normalize_alias("agent__langflow")`, which collapses the double
   underscore to a single one -> offers `@agent_langflow`. gateway/
   openai_router.py's global-registry lookup did an EXACT match against the
   raw registry name -> 404 via the ONLY UI-offered handle. Live-confirmed:
   `POST /user/chat/completions {"model": "@agent_langflow"}` -> 404
   agent_not_found.

2. Wrong protocol: install.sh registers agent__langflow with protocol=
   "openai". openai_router.py only routes through langflow_client.
   langflow_chat() (Langflow's real /api/v1/run/{flow_id} contract) when
   protocol=="langflow" -- "openai" falls into the generic OpenAI-compat
   branch that POSTs {upstream}/v1/chat/completions, a path Langflow's own
   server does not implement. Live-confirmed: addressing the exact registry
   name `@agent__langflow` resolves the 404 but then 405s upstream.
"""
from __future__ import annotations

import os
import re

_REPO_ROOT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
)
_INSTALL_SH = os.path.join(_REPO_ROOT, "install.sh")


def _read_install_sh() -> str:
    with open(_INSTALL_SH, "r", encoding="utf-8") as fh:
        return fh.read()


class TestRisk168InstallShProtocol:
    """install.sh must register langflow with protocol='langflow' in BOTH the
    compose (register_agent_bundles) and k8s (k8s_register_agent_bundles)
    registration functions."""

    def test_compose_registration_uses_langflow_protocol(self):
        sh = _read_install_sh()
        match = re.search(
            r'_name="agent__langflow"[^\n]*_proto="(\w+)"',
            sh,
        )
        assert match is not None, "Cannot find compose langflow case _proto in install.sh"
        assert match.group(1) == "langflow", (
            f"compose register_agent_bundles(): langflow _proto must be "
            f"'langflow' (YSG-RISK-168), got: {match.group(1)!r}"
        )

    def test_k8s_registration_uses_langflow_protocol(self):
        sh = _read_install_sh()
        match = re.search(
            r'langflow\)\s+_name="agent__langflow"\s+_proto="(\w+)"',
            sh,
        )
        assert match is not None, "Cannot find k8s langflow case _proto in install.sh"
        assert match.group(1) == "langflow", (
            f"k8s_register_agent_bundles(): langflow _proto must be "
            f"'langflow' (YSG-RISK-168), got: {match.group(1)!r}"
        )


class TestRisk168AliasNormalizationParity:
    """openai_router.py's _normalize_alias() must byte-match
    user_agents.py's canonical definition, and the global-registry lookup
    must resolve either the mention-menu handle OR the raw registry name."""

    def test_normalize_alias_functions_are_identical_logic(self):
        from yashigani.backoffice.routes.user_agents import _normalize_alias as ua_norm
        from yashigani.gateway.openai_router import _normalize_alias as router_norm

        cases = [
            "agent__langflow",
            "agent_langflow",
            "Agent__LangFlow",
            "123abc",
            "___",
            "a-b--c",
        ]
        for name in cases:
            assert router_norm(name) == ua_norm(name), (
                f"openai_router._normalize_alias and user_agents._normalize_alias "
                f"diverged for {name!r}: {router_norm(name)!r} != {ua_norm(name)!r}"
            )

    def test_mention_menu_handle_normalizes_to_registry_name(self):
        """The exact live-observed collision: registry name 'agent__langflow'
        must normalize to the SAME handle the mention menu offers
        ('agent_langflow')."""
        from yashigani.gateway.openai_router import _normalize_alias

        registry_name = "agent__langflow"
        mention_handle = "agent_langflow"  # what list_user_mentions() offers

        assert _normalize_alias(registry_name) == _normalize_alias(mention_handle), (
            "YSG-RISK-168 regression: normalized registry name and "
            "mention-menu handle must match so the global-registry lookup "
            "resolves either form"
        )

    def test_global_registry_lookup_uses_normalized_comparison(self):
        """openai_router.py's global-registry match loop must compare
        NORMALIZED handles, not raw exact strings (source-level guard —
        the live dispatch path requires a running gateway + Redis + agent
        registry to exercise end-to-end)."""
        import inspect

        from yashigani.gateway import openai_router

        src = inspect.getsource(openai_router)
        assert "_normalize_alias(agent.get(\"name\", \"\")) == _agent_name_norm" in src, (
            "Global agent-registry lookup must compare normalized handles "
            "(YSG-RISK-168) — found raw/exact comparison instead"
        )
