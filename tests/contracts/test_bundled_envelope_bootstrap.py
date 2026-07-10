# Last updated: 2026-07-10T00:00:00+00:00
"""
SEC-ENVELOPE-001 — bundled-agent capability-envelope bootstrap contracts.

Covers the cold-install gap where both bootstrap_bundled_agent_envelopes passes
in the backoffice lifespan fire with an EMPTY agent registry (backoffice starts
at compose_up / step 10; register_agent_bundles runs at step 11b — AFTER the
lifespan has already completed).

Without the install.sh fix: mcp_tool_surface_pins = 0 rows on a cold install.
With the fix: register_agent_bundles mints envelopes in the same Python block
that writes agent_registry + durable_store.

Contracts
---------
B1  bundled_targets_from_registry — returns (tenant, system) pairs only for
    agents whose upstream_url matches the Caddy ingress-front shape AND whose
    system segment is in the _BUNDLED_INGRESS_AGENTS allowlist.

B2  bundled_targets_from_registry — ignores agents with non-matching URLs
    (direct http/https to the raw agent container).

B3  bundled_targets_from_registry — BYO agent registered at a Caddy front but
    with a system name NOT in the allowlist is excluded.

B4  bootstrap_bundled_agent_envelopes — mints one envelope per (tenant, system)
    pair when no ACTIVE envelope exists.  Returns the list of minted provenance
    ids.

B5  bootstrap_bundled_agent_envelopes — idempotent: an ACTIVE envelope already
    present causes a SKIP (get_active_envelope returns non-None); mint is NOT
    called a second time.

B6  bootstrap_bundled_agent_envelopes — returns [] when agent_registry is None.

B7  Cold-install ordering regression: bootstrap fires with empty registry (step 10
    lifespan timing) → 0 minted; after agents are added (step 11b timing), a
    second bootstrap call → correct envelopes minted.  Demonstrates that the
    install.sh fix (mint inside register_agent_bundles) is the correct layer.

B8  The egress_posture recorded in the minted ServerEnvelope matches the
    _BUNDLED_INGRESS_AGENTS map (INTERNAL for langflow/letta, OUTBOUND for
    openclaw).

B9  bundled_targets_from_registry — duplicate (tenant, system) from two agent
    registrations is de-duplicated to a single target.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, call

import pytest

# ---------------------------------------------------------------------------
# Fake AgentRegistry — synchronous, backed by a plain list of dicts
# ---------------------------------------------------------------------------

class _FakeRegistry:
    """Minimal AgentRegistry stub that just holds a list of agent dicts."""

    def __init__(self, agents: list[dict]) -> None:
        self._agents = agents

    def list_all(self) -> list[dict]:
        return list(self._agents)

    def add(self, agent: dict) -> None:
        self._agents.append(agent)


# ---------------------------------------------------------------------------
# Fake CapabilityEnvelopeService — async, tracks calls
# ---------------------------------------------------------------------------

class _FakeEnvelopeService:
    """Async stub for CapabilityEnvelopeService.

    ``_active`` maps provenance_id → int (envelope id, non-zero = exists).
    ``mint_calls`` records every (env, kwargs) pair passed to mint_envelope.
    """

    def __init__(self, active: Optional[dict] = None) -> None:
        self._active: dict[str, int] = active or {}
        self.mint_calls: list[tuple] = []
        self._next_id = 1

    async def get_active_envelope(self, provenance_id: str) -> Optional[object]:
        eid = self._active.get(provenance_id)
        if eid is None:
            return None
        # Return a minimal record-like object with an .id attribute
        rec = MagicMock()
        rec.id = eid
        return rec

    async def mint_envelope(self, env, **kwargs) -> int:
        eid = self._next_id
        self._next_id += 1
        self._active[env.provenance_id] = eid
        self.mint_calls.append((env, kwargs))
        return eid


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _agent(system: str, tenant: str = "default", port: int = 9705,
           name: Optional[str] = None) -> dict:
    """Build a fake agent_registry entry with the Caddy ingress-front URL shape."""
    return {
        "agent_id": f"agnt_{system}",
        "name": name or f"agent__{system}",
        "upstream_url": f"https://caddy:{port}/agents/{tenant}/{system}",
        "status": "active",
    }


def _byo_agent(system: str, tenant: str = "default") -> dict:
    """A BYO agent registered at a Caddy ingress front but with a non-bundled name."""
    return {
        "agent_id": f"agnt_byo_{system}",
        "name": f"byo_{system}",
        "upstream_url": f"https://caddy:9888/agents/{tenant}/{system}",
        "status": "active",
    }


def _direct_agent(name: str = "my-llm") -> dict:
    """A plain agent with a direct (non-Caddy-front) upstream_url."""
    return {
        "agent_id": "agnt_direct",
        "name": name,
        "upstream_url": "http://my-llm:8080",
        "status": "active",
    }


def _run(coro):
    """Run an async coroutine in a new event loop (pytest-anyio not required)."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# B1 — bundled_targets_from_registry: correct matches returned
# ---------------------------------------------------------------------------

def test_b1_bundled_targets_correct_agents():
    from yashigani.backoffice.bundled_envelopes import bundled_targets_from_registry

    registry = _FakeRegistry([
        _agent("langflow", port=9705),
        _agent("letta", port=9775),
        _agent("openclaw", port=9671),
    ])
    targets = bundled_targets_from_registry(registry)
    assert set(targets) == {
        ("default", "langflow"),
        ("default", "letta"),
        ("default", "openclaw"),
    }


# ---------------------------------------------------------------------------
# B2 — bundled_targets_from_registry: direct-URL agents excluded
# ---------------------------------------------------------------------------

def test_b2_direct_url_agent_excluded():
    from yashigani.backoffice.bundled_envelopes import bundled_targets_from_registry

    registry = _FakeRegistry([
        _direct_agent(),
        _agent("langflow", port=9705),
    ])
    targets = bundled_targets_from_registry(registry)
    assert len(targets) == 1
    assert targets[0] == ("default", "langflow")


# ---------------------------------------------------------------------------
# B3 — bundled_targets_from_registry: BYO Caddy-front with unlisted system excluded
# ---------------------------------------------------------------------------

def test_b3_byo_caddy_front_excluded():
    from yashigani.backoffice.bundled_envelopes import bundled_targets_from_registry

    # "my-byo-mcp" is NOT in _BUNDLED_INGRESS_AGENTS
    registry = _FakeRegistry([
        _byo_agent("my-byo-mcp"),
        _agent("letta", port=9775),
    ])
    targets = bundled_targets_from_registry(registry)
    assert len(targets) == 1
    assert targets[0] == ("default", "letta")


# ---------------------------------------------------------------------------
# B4 — bootstrap_bundled_agent_envelopes: mints envelopes for all targets
# ---------------------------------------------------------------------------

def test_b4_bootstrap_mints_all_envelopes():
    from yashigani.backoffice.bundled_envelopes import bootstrap_bundled_agent_envelopes

    registry = _FakeRegistry([
        _agent("langflow", port=9705),
        _agent("letta", port=9775),
    ])
    svc = _FakeEnvelopeService()
    minted = _run(bootstrap_bundled_agent_envelopes(svc, registry))
    assert set(minted) == {"default:langflow", "default:letta"}
    assert len(svc.mint_calls) == 2
    minted_pids = {c[0].provenance_id for c in svc.mint_calls}
    assert minted_pids == {"default:langflow", "default:letta"}


# ---------------------------------------------------------------------------
# B5 — bootstrap_bundled_agent_envelopes: idempotent skip when envelope active
# ---------------------------------------------------------------------------

def test_b5_bootstrap_idempotent_when_envelope_active():
    from yashigani.backoffice.bundled_envelopes import bootstrap_bundled_agent_envelopes

    registry = _FakeRegistry([
        _agent("langflow", port=9705),
        _agent("letta", port=9775),
    ])
    # langflow already has an ACTIVE envelope
    svc = _FakeEnvelopeService(active={"default:langflow": 42})
    minted = _run(bootstrap_bundled_agent_envelopes(svc, registry))
    # Only letta should be minted
    assert minted == ["default:letta"]
    assert len(svc.mint_calls) == 1
    assert svc.mint_calls[0][0].provenance_id == "default:letta"


# ---------------------------------------------------------------------------
# B6 — bootstrap_bundled_agent_envelopes: graceful skip when registry is None
# ---------------------------------------------------------------------------

def test_b6_bootstrap_skips_when_registry_none():
    from yashigani.backoffice.bundled_envelopes import bootstrap_bundled_agent_envelopes

    svc = _FakeEnvelopeService()
    minted = _run(bootstrap_bundled_agent_envelopes(svc, None))
    assert minted == []
    assert svc.mint_calls == []


# ---------------------------------------------------------------------------
# B7 — Cold-install ordering regression
# ---------------------------------------------------------------------------

def test_b7_cold_install_ordering_regression():
    """
    Demonstrates the race that the install.sh fix closes.

    Phase A (lifespan timing — step 10, backoffice starts):
      Agent registry is empty on cold install (Redis db/3 uninitialised).
      bootstrap_bundled_agent_envelopes → 0 envelopes minted.

    Phase B (register_agent_bundles timing — step 11b):
      Agents are written to the registry.
      A second bootstrap call (as done by the install.sh fix) → envelopes minted.

    Without the install.sh fix, Phase B never fires and mcp_tool_surface_pins
    stays at 0 rows for the lifetime of the container.
    """
    from yashigani.backoffice.bundled_envelopes import bootstrap_bundled_agent_envelopes

    # Phase A: empty registry (lifespan timing — backoffice just started)
    registry = _FakeRegistry([])
    svc = _FakeEnvelopeService()
    minted_phase_a = _run(bootstrap_bundled_agent_envelopes(svc, registry))
    assert minted_phase_a == [], (
        "Phase A: lifespan bootstrap must produce 0 envelopes on cold install "
        "(agents not yet registered)"
    )
    assert svc.mint_calls == []

    # Phase B: agents added (register_agent_bundles step 11b timing)
    registry.add(_agent("langflow", port=9705))
    registry.add(_agent("letta", port=9775))
    registry.add(_agent("openclaw", port=9671))

    # Second bootstrap call — as installed by the install.sh fix
    minted_phase_b = _run(bootstrap_bundled_agent_envelopes(svc, registry))
    assert set(minted_phase_b) == {"default:langflow", "default:letta", "default:openclaw"}, (
        "Phase B: bootstrap after agent registration must mint all bundled envelopes"
    )
    assert len(svc.mint_calls) == 3


# ---------------------------------------------------------------------------
# B8 — egress_posture matches _BUNDLED_INGRESS_AGENTS map
# ---------------------------------------------------------------------------

def test_b8_egress_posture_correct_per_agent():
    from yashigani.backoffice.bundled_envelopes import (
        _BUNDLED_INGRESS_AGENTS,
        bootstrap_bundled_agent_envelopes,
    )

    registry = _FakeRegistry([
        _agent("langflow", port=9705),
        _agent("letta", port=9775),
        _agent("openclaw", port=9671),
    ])
    svc = _FakeEnvelopeService()
    _run(bootstrap_bundled_agent_envelopes(svc, registry))

    for env, _ in svc.mint_calls:
        system = env.provenance_id.split(":")[-1]
        expected_posture = _BUNDLED_INGRESS_AGENTS[system]
        assert env.egress_posture == expected_posture, (
            f"egress_posture for {system}: expected {expected_posture!r}, "
            f"got {env.egress_posture!r}"
        )


# ---------------------------------------------------------------------------
# B9 — duplicate (tenant, system) de-duplicated
# ---------------------------------------------------------------------------

def test_b9_duplicate_targets_deduplicated():
    from yashigani.backoffice.bundled_envelopes import bundled_targets_from_registry

    registry = _FakeRegistry([
        _agent("langflow", port=9705, name="agent__langflow_1"),
        _agent("langflow", port=9705, name="agent__langflow_2"),  # duplicate system
    ])
    targets = bundled_targets_from_registry(registry)
    assert targets == [("default", "langflow")], (
        "Duplicate (tenant, system) must produce exactly one target"
    )
