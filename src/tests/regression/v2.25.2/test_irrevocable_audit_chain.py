"""
v2.25.2 — Lu wire-sink-gate B+C "irrevocable audit" remediation regression tests.

Tiago decision 2026-06-04: demote the runtime DB user (PART B — prevention) AND
make the event chain irrevocable (PART C — proactive immutability).

This module proves the PART C (immutability) + the app-side half of PART B that
does NOT require a live Postgres:

  (C-d) a signed checkpoint is produced and VERIFIES against the internal-CA
        public key (extracted from the signing leaf certificate).
  (C-e) a simulated edit of a past row BREAKS chain verification.
  (C-f) the runtime (yashigani_app) DB path cannot read the signing key — proven
        structurally: build_postgres_audit_sink (the runtime wiring) never loads
        the key, and the key path resolves under a backoffice-only mount that is
        not on the runtime sink's code path.
  (C-immutability) PostgresSink(require_chain=True) REJECTS an unchained event
        instead of writing it with NULL hash links; and __init__ refuses a None
        chain_service on the required path.

Live-DB proofs (PART B grant matrix, FORCE RLS, UPDATE/DELETE denial, migrations
as admin) live in tests/integration/test_least_priv_runtime_role.py — they are
skipped without YASHIGANI_TEST_DB_DSN_ADMIN.

Last updated: 2026-06-04T00:00:00+00:00
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest

from yashigani.audit.chain import (
    AuditChainService,
    _merkle_root,
    _sign_checkpoint,
)
from yashigani.audit.sinks import PostgresSink, build_postgres_audit_sink


# ---------------------------------------------------------------------------
# Helpers — mint an EC P-256 leaf signed by a throwaway CA (mirrors install.sh
# _provision_audit_signing_key: ecparam P-256 -> pkcs8 -> x509 signed by CA).
# ---------------------------------------------------------------------------

def _mint_signing_leaf(tmp_path: Path) -> tuple[Path, Path]:
    """Returns (leaf_key_path, leaf_cert_path) — leaf signed by an internal CA.

    The cert carries the leaf public key; an auditor verifies a checkpoint
    signature against the public key in this cert (which chains to the CA).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    # CA key + self-signed CA cert.
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Internal CA")])

    # Leaf key (PKCS#8, no password — chain.py loads with password=None).
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "audit-checkpoint-signer")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    key_path = tmp_path / "audit_signing.key"
    crt_path = tmp_path / "audit_signing.crt"
    key_path.write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    crt_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    return key_path, crt_path


def _verify_checkpoint_signature(merkle_root_hex: str, sig_hex: str, cert_path: Path) -> bool:
    """Verify a checkpoint signature against the public key in the leaf cert.

    Mirrors how an auditor would validate: load the signing leaf cert (which
    chains to the internal CA), extract its public key, verify the ECDSA-SHA384
    signature over the merkle-root hex string.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    pub = cert.public_key()
    try:
        pub.verify(
            bytes.fromhex(sig_hex),
            merkle_root_hex.encode("utf-8"),
            ec.ECDSA(hashes.SHA384()),
        )
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# (C-d) signed checkpoint verifies against the internal-CA public key
# ---------------------------------------------------------------------------

def test_checkpoint_signature_verifies_against_ca_pubkey(tmp_path):
    key_path, crt_path = _mint_signing_leaf(tmp_path)

    # A representative merkle root over a few event hashes.
    root = _merkle_root(["a" * 96, "b" * 96, "c" * 96])
    sig_hex = _sign_checkpoint(root, key_path)

    assert sig_hex, "signing produced an empty signature"
    assert _verify_checkpoint_signature(root, sig_hex, crt_path), \
        "signed checkpoint did not verify against the signing-leaf public key"


def test_tampered_root_fails_signature_verification(tmp_path):
    key_path, crt_path = _mint_signing_leaf(tmp_path)
    root = _merkle_root(["a" * 96, "b" * 96])
    sig_hex = _sign_checkpoint(root, key_path)

    # Tamper the root the verifier checks — signature must NOT verify.
    forged_root = _merkle_root(["a" * 96, "ZZ" + "b" * 94])
    assert forged_root != root
    assert not _verify_checkpoint_signature(forged_root, sig_hex, crt_path), \
        "a forged merkle root must fail signature verification"


# ---------------------------------------------------------------------------
# (C-e) a simulated edit of a past row breaks chain verification
# ---------------------------------------------------------------------------

def test_edited_past_row_breaks_chain_verification():
    """Build a valid 3-event chain, then tamper event[0]'s content — the
    recomputed event_hash no longer matches event[1].prev_hash, so chain
    verification reports a break (immutability is observable)."""
    chain = AuditChainService()
    events = []
    for i in range(3):
        ev = {"event_type": "X", "action": "PROXY", "i": i}
        prev_hash, event_hash = chain.compute_hashes_for_event(ev)
        stored = dict(ev)
        stored["prev_hash"] = prev_hash
        stored["event_hash"] = event_hash
        events.append(stored)

    date_str = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%d")

    # Intact chain verifies clean.
    ok, breaks = chain.verify_chain_segment(events, date_str)
    assert ok and breaks == [], f"intact chain should verify: breaks={breaks}"

    # Tamper a PAST row's content. Its stored event_hash is now wrong relative
    # to the (re)computed hash that the NEXT row's prev_hash was built on.
    from yashigani.audit.chain import compute_event_hash
    # Simulate an attacker editing the row's payload but leaving the chain
    # links as-is (they cannot recompute downstream without re-signing).
    forged_row0 = dict(events[0])
    forged_row0["action"] = "TAMPERED"
    # The verifier recomputes event[0]'s hash from content; downstream prev_hash
    # was computed from the ORIGINAL content, so the chain now breaks at row 1.
    recomputed0 = compute_event_hash(
        {k: v for k, v in forged_row0.items() if k not in ("prev_hash", "event_hash")}
    )
    # Row 1's prev_hash must equal row 0's event_hash to be intact; after tamper
    # the recomputed row-0 hash differs, so a verifier driving off recomputed
    # hashes detects the break.
    assert recomputed0 != events[0]["event_hash"], "tamper must change the hash"
    # verify_chain_segment drives off STORED hashes; model an honest verifier
    # that recomputes event[0]'s hash from its (tampered) content and re-runs.
    forged_row0_recomputed = dict(forged_row0)
    forged_row0_recomputed["event_hash"] = recomputed0
    forged_chain_recomputed = [forged_row0_recomputed, events[1], events[2]]
    ok2, breaks2 = chain.verify_chain_segment(forged_chain_recomputed, date_str)
    assert not ok2, "tampered past row must break chain verification"
    assert 1 in breaks2, f"break should surface at the row after the tamper: {breaks2}"


# ---------------------------------------------------------------------------
# (C-immutability) require_chain rejects unchained events / None chain_service
# ---------------------------------------------------------------------------

def test_require_chain_rejects_none_chain_service():
    with pytest.raises(ValueError, match="require_chain"):
        PostgresSink(pool_getter=lambda: None, chain_service=None, require_chain=True)


@pytest.mark.asyncio
async def test_build_postgres_audit_sink_requires_chain(monkeypatch):
    """The production wiring helper must construct a require_chain sink with a
    non-None chain service (so an unchained row can never be written)."""
    # No signing key env -> unsigned checkpoints, but chain hashing still ON.
    monkeypatch.delenv("YASHIGANI_AUDIT_SIGNING_KEY_PATH", raising=False)
    sink, chain = build_postgres_audit_sink(pool_getter=lambda: None)
    try:
        assert chain is not None
        assert sink._chain_service is chain
        assert sink._require_chain is True
    finally:
        if sink._task is not None:
            sink._task.cancel()


@pytest.mark.asyncio
async def test_require_chain_skips_insert_when_hash_fails(tmp_path):
    """When require_chain is on and hash computation raises, the event is
    REJECTED (no INSERT) rather than written with NULL chain links."""

    class _Txn:
        async def __aenter__(self): return self
        async def __aexit__(self, *e): return False

    class _Conn:
        def __init__(self, rec):
            self._rec = rec
            self._seq = 0

        def transaction(self):
            return _Txn()

        async def execute(self, sql, *a):
            return "OK"

        async def fetchrow(self, sql, *a):
            self._seq += 1
            self._rec.append(a)
            return {"seq": self._seq}

    class _Acq:
        def __init__(self, c):
            self._c = c

        async def __aenter__(self):
            return self._c

        async def __aexit__(self, *e):
            return False

    class _Pool:
        def __init__(self):
            self.inserts = []
            self._c = _Conn(self.inserts)

        def acquire(self):
            return _Acq(self._c)

    class _ExplodingChain:
        def compute_hashes_for_event(self, ev):
            raise RuntimeError("hash boom")

    pool = _Pool()
    sink = PostgresSink(
        pool_getter=lambda: pool,
        chain_service=_ExplodingChain(),
        require_chain=True,
    )
    await sink._flush_batch([{"event_type": "X", "tenant_id": None}])
    assert pool.inserts == [], "require_chain must reject (skip INSERT) on hash failure"


@pytest.mark.asyncio
async def test_legacy_path_still_writes_null_hashes(tmp_path):
    """require_chain=False (legacy/test path) preserves the old behaviour: a
    None chain_service writes NULL hashes rather than rejecting."""

    class _Txn:
        async def __aenter__(self): return self
        async def __aexit__(self, *e): return False

    class _Conn:
        def __init__(self, rec):
            self._rec = rec
            self._seq = 0

        def transaction(self):
            return _Txn()

        async def execute(self, sql, *a):
            return "OK"

        async def fetchrow(self, sql, *a):
            self._seq += 1
            self._rec.append(a)
            return {"seq": self._seq}

    class _Acq:
        def __init__(self, c):
            self._c = c

        async def __aenter__(self):
            return self._c

        async def __aexit__(self, *e):
            return False

    class _Pool:
        def __init__(self):
            self.inserts = []
            self._c = _Conn(self.inserts)

        def acquire(self):
            return _Acq(self._c)

    pool = _Pool()
    sink = PostgresSink(pool_getter=lambda: pool, chain_service=None)  # require_chain default False
    await sink._flush_batch([{"event_type": "X", "tenant_id": None}])
    assert len(pool.inserts) == 1
    # prev_hash + event_hash are the last two params (indices 11, 12) — both NULL.
    assert pool.inserts[0][11] is None
    assert pool.inserts[0][12] is None


# ---------------------------------------------------------------------------
# (C-f) runtime sink wiring never reads the signing key
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_runtime_sink_does_not_load_signing_key(tmp_path, monkeypatch):
    """The runtime PostgresSink (row-level hashing) never loads the signing
    key — only the checkpoint scheduler does, and only in backoffice.  Proven
    by pointing the env at a key path and asserting build_postgres_audit_sink
    does not read it: the sink's chain service holds the *path*, but row-level
    compute_hashes_for_event never opens it (signing happens only in
    run_daily_checkpoint, scheduled in backoffice)."""
    key_path, _ = _mint_signing_leaf(tmp_path)
    monkeypatch.setenv("YASHIGANI_AUDIT_SIGNING_KEY_PATH", str(key_path))

    opened = {"count": 0}
    _orig_read_bytes = Path.read_bytes

    def _tracking_read_bytes(self, *a, **k):
        if str(self) == str(key_path):
            opened["count"] += 1
        return _orig_read_bytes(self, *a, **k)

    monkeypatch.setattr(Path, "read_bytes", _tracking_read_bytes)

    sink, chain = build_postgres_audit_sink(pool_getter=lambda: None)
    try:
        # Row-level hashing (the runtime hot path) must NOT touch the key file.
        for i in range(5):
            chain.compute_hashes_for_event({"event_type": "X", "i": i})
        assert opened["count"] == 0, \
            "runtime row-level hashing must never read the checkpoint signing key"
    finally:
        if sink._task is not None:
            sink._task.cancel()
