# Last updated: 2026-07-07T00:00:00+00:00
"""
Unit tests — bundled-agent capability-envelope bootstrap (v4.1 §2.5).

Contract under test (backoffice/bundled_envelopes.py):

  * Registry-derived: only agents registered with a Caddy ingress-front
    upstream (https://caddy:<port>/agents/<tenant>/<system>) are candidates.
  * CLOSED allowlist: only bundled systems (openclaw/langflow/letta) are ever
    auto-minted — a BYO agent behind a caddy front NEVER gets an auto
    envelope (its approval path is the onboarding ceremony).
  * Idempotent: an existing ACTIVE envelope is never superseded.
  * Honest record: tool-less envelope, transitional service-leaf SPIFFE
    recorded with svid_issued=False, provenance == verify-mcp key.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from yashigani.backoffice.bundled_envelopes import (
    bootstrap_bundled_agent_envelopes,
    bundled_targets_from_registry,
)
from yashigani.mcp.envelope_service import TOPOLOGY_RING_FENCED

_TD = "yashigani.internal"  # legacy default trust domain (env unset in tests)


def _registry(agents: list[dict]) -> MagicMock:
    reg = MagicMock()
    reg.list_all = MagicMock(return_value=agents)
    return reg


def _agent(upstream: str, name: str = "x") -> dict:
    return {"agent_id": f"agnt_{name}", "name": name, "upstream_url": upstream,
            "status": "active"}


_BUNDLED_AGENTS = [
    _agent("https://caddy:9705/agents/default/langflow", "agent__langflow"),
    _agent("https://caddy:9775/agents/default/letta", "letta"),
    _agent("https://caddy:9671/agents/default/openclaw", "openclaw"),
]


def _svc(active: dict[str, object] | None = None) -> MagicMock:
    """Envelope service mock; ``active`` maps provenance_id -> record."""
    active = active or {}
    svc = MagicMock()

    async def _get(provenance_id: str):
        return active.get(provenance_id)

    svc.get_active_envelope = AsyncMock(side_effect=_get)
    svc.mint_envelope = AsyncMock(return_value=101)
    return svc


class TestBundledTargets:
    def test_bundled_fronts_detected(self):
        targets = bundled_targets_from_registry(_registry(_BUNDLED_AGENTS))
        assert targets == [
            ("default", "langflow"),
            ("default", "letta"),
            ("default", "openclaw"),
        ]

    def test_byo_caddy_fronted_agent_never_auto_minted(self):
        """Closed allowlist: a BYO system behind a caddy front is NOT a
        target — auto-minting it would bypass the onboarding ceremony."""
        agents = [_agent("https://caddy:9640/agents/default/byo-crm", "byo")]
        assert bundled_targets_from_registry(_registry(agents)) == []

    def test_direct_upstreams_ignored(self):
        agents = [
            _agent("http://langflow:7860", "old-direct"),
            _agent("https://evil.example/agents/default/langflow", "spoof"),
            _agent("", "empty"),
        ]
        assert bundled_targets_from_registry(_registry(agents)) == []

    def test_deduplicated(self):
        agents = [_BUNDLED_AGENTS[0], _BUNDLED_AGENTS[0]]
        assert bundled_targets_from_registry(_registry(agents)) == [
            ("default", "langflow"),
        ]


class TestBootstrap:
    @pytest.mark.asyncio
    async def test_mints_missing_envelopes_for_bundled_agents(self):
        svc = _svc()
        minted = await bootstrap_bundled_agent_envelopes(
            svc, _registry(_BUNDLED_AGENTS),
        )
        assert minted == ["default:langflow", "default:letta", "default:openclaw"]
        assert svc.mint_envelope.await_count == 3

        # Inspect the langflow mint: honest, tool-less, transitional identity.
        env = svc.mint_envelope.await_args_list[0].args[0]
        kwargs = svc.mint_envelope.await_args_list[0].kwargs
        assert env.provenance_id == "default:langflow"   # verify-mcp key
        assert env.tenant_id == "default"
        assert env.tools == {}
        assert kwargs["server_id"] == "langflow"
        assert kwargs["topology"] == TOPOLOGY_RING_FENCED
        assert kwargs["operator_identity"] == "system:bundled-agent-bootstrap"
        assert kwargs["svid_spiffe_id"] == f"spiffe://{_TD}/langflow"
        assert kwargs["svid_issued"] is False   # no per-instance leaf minted

    @pytest.mark.asyncio
    async def test_idempotent_existing_active_envelope_skipped(self):
        existing = MagicMock()
        existing.id = 7
        svc = _svc(active={
            "default:langflow": existing,
            "default:letta": existing,
            "default:openclaw": existing,
        })
        minted = await bootstrap_bundled_agent_envelopes(
            svc, _registry(_BUNDLED_AGENTS),
        )
        assert minted == []
        svc.mint_envelope.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_partial_mint_only_missing(self):
        existing = MagicMock()
        existing.id = 7
        svc = _svc(active={"default:langflow": existing})
        minted = await bootstrap_bundled_agent_envelopes(
            svc, _registry(_BUNDLED_AGENTS),
        )
        assert minted == ["default:letta", "default:openclaw"]

    @pytest.mark.asyncio
    async def test_registry_none_is_noop(self):
        svc = _svc()
        assert await bootstrap_bundled_agent_envelopes(svc, None) == []
        svc.mint_envelope.assert_not_awaited()
        svc.get_active_envelope.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_registry_is_noop(self):
        svc = _svc()
        assert await bootstrap_bundled_agent_envelopes(svc, _registry([])) == []
        svc.mint_envelope.assert_not_awaited()
