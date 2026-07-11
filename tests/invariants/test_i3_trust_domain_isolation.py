"""
I3 — Per-instance SPIFFE trust-domain isolation (MI-6 / YSG-RISK-061).

INVARIANT (must ALWAYS hold): a non-legacy instance ACCEPTS its own
``<project>.yashigani.internal`` identities and REJECTS foreign / legacy ones, and
a legacy (single-instance) deployment is UNCHANGED. Every app-layer SPIFFE
validator/minter resolves the authority through the single helper
``yashigani.identity.trust_domain`` — none hardcodes ``yashigani.internal``.

Why an invariant: Nico's MI-6 review (F1–F6) found six validators that previously
hardcoded the legacy domain. If any future change reintroduces a hardcoded domain,
a multi-instance deployment either fails closed against its OWN workloads or — if
an accept set widens — risks accepting a foreign label (the TLS-anchor backstop
still catches it, but the label compare must stay exact). This locks the
single-source-of-truth so the regression can't recur silently.

Asserted here: the helper's accept-own / reject-foreign string logic, legacy
default preserved byte-for-byte, and that the six validator modules import the
helper (no hardcoded-domain reintroduction).

LIVE-PROOF (#44): the hard cross-instance proof — mint a leaf in instance B's
trust domain, present it to instance A, expect X.509 chain rejection at the TLS
handshake — is the two-live-instance VM item (Nico/Lu both flag it). That backstop
is cryptographic and independent of this code; here we prove the app-layer
self-trust contract.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from yashigani.identity.trust_domain import (
    agent_spiffe_uri,
    audit_signer_spiffe_id,
    gateway_issuer_prefix,
    spiffe_agents_prefix,
    trust_domain,
)


class _TD:
    """Namespace shim so the tests read as ``td.trust_domain()`` etc. (the
    ``yashigani.identity`` package re-exports the FUNCTION ``trust_domain``, which
    shadows the submodule name — so we bind the functions explicitly here)."""

    trust_domain = staticmethod(trust_domain)
    spiffe_agents_prefix = staticmethod(spiffe_agents_prefix)
    agent_spiffe_uri = staticmethod(agent_spiffe_uri)
    gateway_issuer_prefix = staticmethod(gateway_issuer_prefix)
    audit_signer_spiffe_id = staticmethod(audit_signer_spiffe_id)


td = _TD()

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src" / "yashigani"

LEGACY = "yashigani.internal"
PROJECT = "apac"
OWN_DOMAIN = f"{PROJECT}.yashigani.internal"


# --------------------------------------------------------------------------- #
# Helper behaviour: accept-own / reject-foreign / legacy-unchanged
# --------------------------------------------------------------------------- #

def test_legacy_default_when_env_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset env ⇒ legacy authority byte-for-byte (single-instance unchanged)."""
    monkeypatch.delenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", raising=False)
    assert td.trust_domain() == LEGACY
    assert td.spiffe_agents_prefix() == f"spiffe://{LEGACY}/agents"


def test_blank_env_falls_back_to_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", "   ")
    assert td.trust_domain() == LEGACY


def test_non_legacy_instance_trusts_its_own_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-legacy instance resolves to its OWN <project>.yashigani.internal —
    so its validators accept its own workloads."""
    monkeypatch.setenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", OWN_DOMAIN)
    assert td.trust_domain() == OWN_DOMAIN
    assert td.spiffe_agents_prefix() == f"spiffe://{OWN_DOMAIN}/agents"
    assert td.agent_spiffe_uri("tenant-a", "goose") == (
        f"spiffe://{OWN_DOMAIN}/agents/tenant-a/goose"
    )
    assert td.gateway_issuer_prefix() == f"https://gateway.{OWN_DOMAIN}/"
    assert td.audit_signer_spiffe_id() == f"spiffe://{OWN_DOMAIN}/audit"


def test_own_identity_accepted_foreign_and_legacy_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The startswith() accept check used by every validator: own ✓, foreign ✗,
    legacy ✗ (on a non-legacy instance)."""
    monkeypatch.setenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", OWN_DOMAIN)
    own_prefix = td.spiffe_agents_prefix() + "/"

    own = f"spiffe://{OWN_DOMAIN}/agents/tenant-a/goose"
    foreign = "spiffe://eu.yashigani.internal/agents/tenant-a/goose"
    legacy = f"spiffe://{LEGACY}/agents/tenant-a/goose"

    assert own.startswith(own_prefix), "instance must accept its OWN identity"
    assert not foreign.startswith(own_prefix), "instance must REJECT a foreign domain"
    assert not legacy.startswith(own_prefix), (
        "a non-legacy instance must REJECT the legacy domain (no substring leak)"
    )

    # issuer accept check (principal_token / mcp jwt): own iss ✓, foreign iss ✗
    iss_prefix = td.gateway_issuer_prefix()
    assert f"{iss_prefix}tenant-a".startswith(iss_prefix)
    assert not "https://gateway.eu.yashigani.internal/tenant-a".startswith(iss_prefix)


def test_legacy_instance_accepts_legacy_rejects_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backward-compat: a legacy instance accepts legacy identities and rejects a
    project-scoped one (no cross-acceptance the other way either)."""
    monkeypatch.delenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", raising=False)
    legacy_prefix = td.spiffe_agents_prefix() + "/"
    assert f"spiffe://{LEGACY}/agents/t/a".startswith(legacy_prefix)
    assert not f"spiffe://{OWN_DOMAIN}/agents/t/a".startswith(legacy_prefix)


# --------------------------------------------------------------------------- #
# Single-source-of-truth: the six F1–F6 validator modules consume the helper
# (no hardcoded-domain reintroduction).
# --------------------------------------------------------------------------- #

# Module → the helper symbol(s) it must import from identity.trust_domain.
_VALIDATOR_MODULES = {
    "pool/manager.py": {"spiffe_agents_prefix", "agent_spiffe_uri", "trust_domain"},
    "gateway/principal_token.py": {"agent_spiffe_uri", "gateway_issuer_prefix", "trust_domain"},
    "manifest/linter.py": {"spiffe_agents_prefix", "agent_spiffe_uri", "trust_domain"},
    "mcp/broker.py": {"spiffe_agents_prefix", "agent_spiffe_uri", "gateway_issuer_prefix", "trust_domain"},
    "mcp/_jwt.py": {"agent_spiffe_uri", "gateway_issuer_prefix", "trust_domain"},
    "audit/sinks.py": {"audit_signer_spiffe_id", "trust_domain"},
}


def _imported_trust_domain_symbols(path: Path) -> set[str]:
    """Symbols imported from yashigani.identity.trust_domain in a module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and (
            node.module.endswith("identity.trust_domain")
            or node.module.endswith("identity")
        ):
            for alias in node.names:
                out.add(alias.name)
    return out


@pytest.mark.parametrize("rel", sorted(_VALIDATOR_MODULES))
def test_validator_consumes_trust_domain_helper(rel: str) -> None:
    """Each F1–F6 validator imports at least one trust-domain helper — proving it
    resolves the authority from the single source, not a hardcoded literal."""
    path = SRC / rel
    assert path.exists(), f"validator module missing: {path}"
    imported = _imported_trust_domain_symbols(path)
    expected = _VALIDATOR_MODULES[rel]
    assert imported & expected, (
        f"{rel} must import a trust-domain helper from yashigani.identity.trust_domain "
        f"(expected one of {sorted(expected)}, found {sorted(imported)}). A hardcoded "
        f"'yashigani.internal' here re-creates the MI-6 self-rejection / drift bug."
    )


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """ast node ids of docstring constants (first stmt of module/class/func)."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


@pytest.mark.parametrize("rel", sorted(_VALIDATOR_MODULES))
def test_validator_has_no_hardcoded_legacy_domain_string_constant(rel: str) -> None:
    """No validator has a CODE string-constant that hardcodes a constructed
    ``spiffe://yashigani.internal/...`` URI — the domain must come from the helper.

    Docstrings are excluded (they legitimately reference the legacy name as an
    example), as are template/example strings carrying a ``{`` placeholder or
    backtick. We flag only a bare, non-templated URI literal used as a value —
    that is the MI-6 regression (a hardcoded domain re-creating the self-rejection
    / drift bug).
    """
    path = SRC / rel
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    doc_ids = _docstring_nodes(tree)
    bad = "spiffe://yashigani.internal/"
    offending: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if id(node) in doc_ids:
            continue
        s = node.value
        if not s.startswith(bad):
            continue
        # template/example forms (carry a placeholder or doc backtick) are not a
        # hardcoded value used to build an identity.
        if "{" in s or "`" in s:
            continue
        offending.append(s)
    assert not offending, (
        f"{rel} has a hardcoded '{bad}' URI string-constant in code — build it from "
        f"trust_domain()/spiffe_agents_prefix() instead. Offending constants: "
        f"{offending}"
    )
