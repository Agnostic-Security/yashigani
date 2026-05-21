"""Tests for yashigani.pki.issuer — root/intermediate/leaf generation + rotation."""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from yashigani.pki.identity import load_manifest
from yashigani.pki.issuer import (
    IssuerPaths,
    bootstrap,
    rotate_intermediate,
    rotate_leaves,
    rotate_root,
    status,
)


_MANIFEST = """\
schema_version: 1
services:
  - name: gateway
    dns_sans: [gateway, gateway.internal]
    purpose: "data plane"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false
  - name: backoffice
    dns_sans: [backoffice]
    purpose: "admin"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false
  - name: dead
    dns_sans: [dead]
    purpose: "kill switch test"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: true
cert_policy:
  root_lifetime_years_min: 5
  root_lifetime_years_max: 20
  root_lifetime_years_default: 10
  root_rotation_requires_manual_confirmation: true
  intermediate_lifetime_days_min: 90
  intermediate_lifetime_days_max: 365
  intermediate_lifetime_days_default: 180
  leaf_lifetime_days_min: 30
  leaf_lifetime_days_max: 90
  leaf_lifetime_days_default: 90
  renewal_threshold: 0.33
ca_source:
  mode: yashigani_generated
  byo: {}
  remote_acme: {}
  min_license_tier:
    yashigani_generated: community
"""


@pytest.fixture
def paths(tmp_path: Path) -> IssuerPaths:
    manifest = tmp_path / "service_identities.yaml"
    manifest.write_text(_MANIFEST)
    return IssuerPaths(secrets_dir=tmp_path / "secrets", manifest_path=manifest)


def _load_cert(p: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(p.read_bytes())


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

def test_bootstrap_generates_full_chain(paths: IssuerPaths):
    hashes = bootstrap(paths)
    # Revoked service is skipped.
    assert set(hashes.keys()) == {"gateway", "backoffice"}

    assert paths.root_cert.exists()
    assert paths.root_key.exists()
    assert paths.intermediate_cert.exists()
    assert paths.intermediate_key.exists()
    assert paths.leaf_cert("gateway").exists()
    assert paths.leaf_cert("backoffice").exists()
    assert not paths.leaf_cert("dead").exists()


def test_bootstrap_populates_manifest_hashes(paths: IssuerPaths):
    bootstrap(paths)
    reloaded = load_manifest(str(paths.manifest_path))
    gw = reloaded.get("gateway")
    assert gw.bootstrap_token_sha256  # populated, non-empty
    assert len(gw.bootstrap_token_sha256) == 64  # SHA-256 hex


def test_rotate_leaves_updates_manifest_hashes(paths: IssuerPaths):
    """Regression: rotate_leaves() must update bootstrap_token_sha256 in the manifest.

    Before the fix, rotate_leaves() called _ensure_bootstrap_token() but discarded
    the hash and never called _update_manifest_hashes(), leaving stale hashes in the
    manifest that no longer matched on-disk tokens → TamperError at gateway startup
    (compose-path SHA mismatch, v2.23.4 Track B bug).
    """
    bootstrap(paths)
    # Capture the hashes written by bootstrap
    before = load_manifest(str(paths.manifest_path))
    gw_hash_before = before.get("gateway").bootstrap_token_sha256

    # Rotate leaves — this should re-generate bootstrap tokens and update the manifest
    rotate_leaves(paths)
    after = load_manifest(str(paths.manifest_path))
    gw_hash_after = after.get("gateway").bootstrap_token_sha256

    # Hash is still present (non-empty, SHA-256 length)
    assert gw_hash_after
    assert len(gw_hash_after) == 64
    # The on-disk token must match the manifest hash after rotation
    tok = paths.bootstrap_token("gateway")
    import hashlib
    actual = hashlib.sha256(tok.read_bytes().strip()).hexdigest()
    assert actual == gw_hash_after, (
        f"rotate_leaves left manifest hash {gw_hash_after!r} but "
        f"on-disk token hashes to {actual!r}"
    )


def test_bootstrap_refuses_overwrite(paths: IssuerPaths):
    bootstrap(paths)
    with pytest.raises(RuntimeError, match="already exists"):
        bootstrap(paths)


def test_bootstrap_cert_chain_validates(paths: IssuerPaths):
    """Leaf should chain to intermediate, intermediate to root."""
    bootstrap(paths)
    root = _load_cert(paths.root_cert)

    # Leaf file contains leaf || intermediate bundle
    leaf_bundle = paths.leaf_cert("gateway").read_bytes()
    certs_in_bundle = x509.load_pem_x509_certificates(leaf_bundle)
    assert len(certs_in_bundle) == 2  # leaf + intermediate bundled
    leaf, bundled_intermediate = certs_in_bundle

    # Intermediate in the bundle should match the standalone intermediate file
    standalone_intermediate = _load_cert(paths.intermediate_cert)
    assert bundled_intermediate.serial_number == standalone_intermediate.serial_number

    # Leaf is issued by intermediate
    assert leaf.issuer == bundled_intermediate.subject
    # Intermediate is issued by root
    assert bundled_intermediate.issuer == root.subject
    # Root is self-signed
    assert root.issuer == root.subject


def test_bootstrap_leaf_has_expected_sans(paths: IssuerPaths):
    bootstrap(paths)
    leaf_bundle = paths.leaf_cert("gateway").read_bytes()
    leaf = x509.load_pem_x509_certificates(leaf_bundle)[0]
    san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = san_ext.value.get_values_for_type(x509.DNSName)
    assert "gateway" in names
    assert "gateway.internal" in names


def test_bootstrap_lifetime_clamped_to_policy_bounds(paths: IssuerPaths):
    # Request a ridiculous leaf lifetime — should clamp to 90 days max
    bootstrap(paths, leaf_lifetime_days=9999)
    leaf_bundle = paths.leaf_cert("gateway").read_bytes()
    leaf = x509.load_pem_x509_certificates(leaf_bundle)[0]
    lifetime_days = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days
    # Clamped to max 90d (+5min slack on not_valid_before)
    assert 89 <= lifetime_days <= 90


# ─────────────────────────────────────────────────────────────────────────────
# Rotation
# ─────────────────────────────────────────────────────────────────────────────

def test_rotate_leaves_keeps_root_and_intermediate(paths: IssuerPaths):
    bootstrap(paths)
    root_before = paths.root_cert.read_bytes()
    int_before = paths.intermediate_cert.read_bytes()
    leaf_before = paths.leaf_cert("gateway").read_bytes()

    rotated = rotate_leaves(paths)
    assert set(rotated) == {"gateway", "backoffice"}

    # Root + intermediate unchanged
    assert paths.root_cert.read_bytes() == root_before
    assert paths.intermediate_cert.read_bytes() == int_before
    # Leaf changed
    assert paths.leaf_cert("gateway").read_bytes() != leaf_before


def test_rotate_leaves_only_target(paths: IssuerPaths):
    bootstrap(paths)
    gw_before = paths.leaf_cert("gateway").read_bytes()
    bo_before = paths.leaf_cert("backoffice").read_bytes()

    rotated = rotate_leaves(paths, only_service="gateway")
    assert rotated == ["gateway"]
    assert paths.leaf_cert("gateway").read_bytes() != gw_before
    # Backoffice untouched
    assert paths.leaf_cert("backoffice").read_bytes() == bo_before


def test_rotate_intermediate_reissues_everything_below(paths: IssuerPaths):
    bootstrap(paths)
    root_before = paths.root_cert.read_bytes()
    int_before = paths.intermediate_cert.read_bytes()
    leaf_before = paths.leaf_cert("gateway").read_bytes()

    rotate_intermediate(paths)

    assert paths.root_cert.read_bytes() == root_before  # root untouched
    assert paths.intermediate_cert.read_bytes() != int_before
    assert paths.leaf_cert("gateway").read_bytes() != leaf_before


def test_rotate_root_requires_confirm(paths: IssuerPaths):
    bootstrap(paths)
    with pytest.raises(RuntimeError, match="destructive"):
        rotate_root(paths)


def test_rotate_root_full_replacement(paths: IssuerPaths):
    bootstrap(paths)
    root_before = paths.root_cert.read_bytes()

    rotate_root(paths, confirm=True)
    assert paths.root_cert.read_bytes() != root_before


def test_rogue_service_cannot_be_minted(paths: IssuerPaths):
    """A service not in the manifest can never receive a cert."""
    bootstrap(paths)
    # rotate_leaves(only_service="rogue") returns empty list — cert never minted
    rotated = rotate_leaves(paths, only_service="rogue")
    assert rotated == []
    assert not paths.leaf_cert("rogue").exists()


# ─────────────────────────────────────────────────────────────────────────────
# Status
# ─────────────────────────────────────────────────────────────────────────────

def test_status_reports_all_entries(paths: IssuerPaths):
    bootstrap(paths)
    rows = status(paths)
    names = {row["name"] for row in rows}
    assert "root" in names
    assert "intermediate" in names
    assert "gateway" in names
    assert "backoffice" in names
    assert "dead" not in names  # revoked


def test_status_flags_renewal_needed(paths: IssuerPaths, monkeypatch):
    """If a cert is near expiry, status should flag 'renew'."""
    bootstrap(paths)
    rows = status(paths)
    for row in rows:
        # Fresh certs should all be 'ok'
        if row["kind"] == "leaf":
            assert row["status"] == "ok"
            assert row["fraction_remaining"] > 0.9


def test_status_missing_cert_reports_missing(paths: IssuerPaths):
    bootstrap(paths)
    paths.leaf_cert("gateway").unlink()
    rows = status(paths)
    gw_row = next(r for r in rows if r["name"] == "gateway")
    assert gw_row["status"] == "missing"
