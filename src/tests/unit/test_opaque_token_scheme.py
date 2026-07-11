"""
Opaque per-file-salted token scheme — PART 1 + PART 2 proofs (DECIDED 2026-06-10).

These assert the scheme-level guarantees the brief calls out, at the PIPELINE
level (end-to-end through inspect + re-render) rather than the unit-engine level:

PART 1:
  * tokens are OPAQUE (no class / count leak);
  * same value in two docs → DIFFERENT tokens (per-file uniqueness);
  * same value in one doc → SAME token (within-doc coherence);
  * reconstitution is exact (local re-merge via the user's table);
  * integrity-verify catches cross-file splice (foreign-salt tokens rejected);
  * the output-holder cannot reverse a token without the original/secret.

PART 2 (Laura D1):
  * an operate-on sensitive field on a CLOUD-bound (mode-B) PSEUDONYMIZE is NOT
    blobbed to the cloud — it routes local (default) or fails closed.
"""
from __future__ import annotations

import re
from unittest.mock import patch

import pytest

from yashigani.documents.extractor import ExtractorRegistry
from yashigani.documents.pipeline import (
    DISPOSITION_BLOCK,
    DISPOSITION_PSEUDONYMIZE,
    DISPOSITION_ROUTE_LOCAL,
    OPERATE_ON_ALLOW_BLOB,
    OPERATE_ON_BLOCK,
    DocumentInspectionPipeline,
)
from yashigani.documents.token_scheme import (
    TOKEN_CHARS,
    compute_doc_hash,
    derive_token,
)
from yashigani.documents.pseudonymize import local_remerge

_OPAQUE_RE = re.compile(rf"^[a-z2-7]{{{TOKEN_CHARS}}}$")

# DP-Y-002 §3.1: the secret is now MANDATORY.  Tests construct the pipeline with
# a fixed test secret so the fail-closed secret guard does not fire.  Tests that
# exercise PSEUDONYMIZE re-render still fail at the sandbox stage (pre-existing
# limitation: the extractor image is not available in unit test environments) —
# those are pre-existing failures, not caused by the §3.1 hardening.
_TEST_SECRET = b"test-deploy-secret-for-unit-tests-only-32b"


def _pipeline(**kw) -> DocumentInspectionPipeline:
    # Provision a test secret so the DP-Y-002 §3.1 fail-closed guard passes.
    # Re-render still requires the sandbox (pre-existing limitation for unit tests).
    with patch(
        "yashigani.documents.pipeline.load_deployment_secret",
        return_value=_TEST_SECRET,
    ):
        return DocumentInspectionPipeline(small_set_escalation=False, **kw)


# ---------------------------------------------------------------------------
# PART 1 — opacity, per-file uniqueness, coherence, reconstitution.
# ---------------------------------------------------------------------------

_EMAIL = "alice@example.com"


def _csv_two_rows() -> bytes:
    # Same email in two rows → coherence; reference-only classes only → no
    # operate-on routing interference.
    return (
        "name,email\n"
        f"Alice,{_EMAIL}\n"
        f"Alice Again,{_EMAIL}\n"
    ).encode()


def test_token_opaque_no_class_or_count_leak_end_to_end():
    pipe = _pipeline()
    r = pipe.inspect(_csv_two_rows(), "text/csv", request_id="r1",
                     requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    assert r.disposition == DISPOSITION_PSEUDONYMIZE, r.block_reason
    out = r.forward_bytes.decode()
    assert _EMAIL not in out  # original gone
    # Every token in the table is opaque (12 base32 chars, no [TAG_N]).
    for tok in r.correspondence_table.rows:
        assert _OPAQUE_RE.match(tok), f"non-opaque token {tok!r}"
        assert "EMAIL" not in tok.upper() and "[" not in tok


def test_same_value_two_docs_different_tokens_end_to_end():
    pipe = _pipeline()
    doc1 = _csv_two_rows()
    # A second document with the SAME email but different surrounding bytes →
    # different doc_hash salt → different token for the same value.
    doc2 = ("contact,email\n" f"Bob,{_EMAIL}\n").encode()
    r1 = pipe.inspect(doc1, "text/csv", request_id="d1",
                      requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    r2 = pipe.inspect(doc2, "text/csv", request_id="d2",
                      requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    tok1 = next(t for t, v in r1.correspondence_table.rows.items() if v == _EMAIL)
    tok2 = next(t for t, v in r2.correspondence_table.rows.items() if v == _EMAIL)
    assert tok1 != tok2, "same value in two docs must derive different tokens"
    assert r1.doc_hash != r2.doc_hash


def test_within_doc_coherence_same_value_same_token():
    pipe = _pipeline()
    r = pipe.inspect(_csv_two_rows(), "text/csv", request_id="c1",
                     requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    out = r.forward_bytes.decode()
    tok = next(t for t, v in r.correspondence_table.rows.items() if v == _EMAIL)
    assert out.count(tok) == 2  # both rows collapsed to the SAME token


def test_reconstitution_exact_via_local_remerge():
    pipe = _pipeline()
    r = pipe.inspect(_csv_two_rows(), "text/csv", request_id="rc1",
                     requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    tokenized = r.forward_bytes.decode()
    restored = local_remerge(tokenized, r.correspondence_table.rows)
    assert _EMAIL in restored
    assert restored.count(_EMAIL) == 2  # exact reconstitution of both rows


# ---------------------------------------------------------------------------
# PART 1 — integrity verify: cross-file splice rejected.
# ---------------------------------------------------------------------------

def test_integrity_verify_accepts_matching_doc():
    pipe = _pipeline()
    doc = _csv_two_rows()
    r = pipe.inspect(doc, "text/csv", request_id="iv1",
                     requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    mapping = r.correspondence_table.rows
    res = pipe.verify_integrity(doc, mapping, r.doc_hash)
    assert res.ok is True
    assert res.salt_match is True
    assert res.foreign_tokens == []


def test_integrity_verify_rejects_cross_file_splice():
    """A mapping minted under document A paired with document B's bytes is a
    splice — the salt mismatches AND the tokens do not re-derive under B's salt."""
    pipe = _pipeline()
    doc_a = _csv_two_rows()
    doc_b = ("contact,email\n" f"Bob,{_EMAIL}\n").encode()
    ra = pipe.inspect(doc_a, "text/csv", request_id="iva",
                      requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    # Pair A's mapping + A's claimed hash with B's bytes → splice.
    res = pipe.verify_integrity(doc_b, ra.correspondence_table.rows, ra.doc_hash)
    assert res.ok is False
    assert res.salt_match is False          # recomputed hash != claimed
    assert res.foreign_tokens               # A's tokens are foreign under B's salt


def test_output_holder_cannot_reverse_without_original():
    """The party holding ONLY the tokenized output (no table, no secret) cannot
    recover the originals.  The token is a keyed, salted HMAC truncation — there
    is no value structure to invert and no way to brute-force without the secret
    + the candidate value.  We assert the cleartext simply isn't present and a
    naive guess fails to validate without knowing the value."""
    pipe = _pipeline()
    r = pipe.inspect(_csv_two_rows(), "text/csv", request_id="oh1",
                     requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    out = r.forward_bytes.decode()
    assert _EMAIL not in out
    # The output holder has the doc_hash (it can hash the bytes) but NOT the
    # deployment secret; even knowing both the salt AND the secret, a wrong
    # candidate VALUE does not reproduce the token — dictionary / confirmation
    # attacks on unknown values are defeated by the keyed HMAC (DP-Y-002 §3.1).
    salt = r.doc_hash
    tok = next(t for t, v in r.correspondence_table.rows.items() if v == _EMAIL)
    wrong = derive_token(salt, "wrong@guess.com", secret=_TEST_SECRET)
    assert wrong != tok  # a wrong candidate value never reproduces the token


# ---------------------------------------------------------------------------
# PART 2 (Laura D1) — operate-on sensitive fields are not blobbed to cloud.
# ---------------------------------------------------------------------------

def _csv_with_salary() -> bytes:
    # SALARY is an operate-on sensitive class (the model sums/compares it).
    return (
        "name,email,salary\n"
        "Alice,alice@example.com,52000\n"
        "Bob,bob@example.com,61000\n"
        "Carol,carol@example.com,48000\n"
    ).encode()


def test_modeb_operate_on_sensitive_routes_local_not_blobbed():
    """Mode B (cloud round-trip): a salary column must NOT be opaque-blobbed to
    the cloud (the model would hallucinate a number).  Default routing → local."""
    pipe = _pipeline()
    r = pipe.inspect(_csv_with_salary(), "text/csv", request_id="p2a",
                     requested_action="PSEUDONYMIZE", pseudonymize_mode="B")
    assert r.disposition == DISPOSITION_ROUTE_LOCAL, r.block_reason
    assert r.route_local is True
    assert any("SALARY" in c for c in r.operate_on_classes)
    # The LOCAL route gets the ORIGINAL bytes (values stay in-estate); they are
    # NOT tokenized to the cloud, and no replacer map / cloud round-trip is set.
    assert r.forward_bytes == _csv_with_salary()
    assert r.mode_b_roundtrip is None


def test_modeb_operate_on_block_routing_fails_closed():
    """When the operator configures BLOCK (no local route), an operate-on
    sensitive field fails closed rather than being blobbed to the cloud."""
    pipe = _pipeline()
    r = pipe.inspect(_csv_with_salary(), "text/csv", request_id="p2b",
                     requested_action="PSEUDONYMIZE", pseudonymize_mode="B",
                     operate_on_routing=OPERATE_ON_BLOCK)
    assert r.disposition == DISPOSITION_BLOCK
    assert "operate-on sensitive" in (r.block_reason or "")


def test_modeb_reference_only_still_tokenizes_to_cloud():
    """A reference-only set (names/emails only) is safe to opaque-tokenise to the
    cloud — the seam does NOT fire, mode B proceeds normally."""
    pipe = _pipeline()
    doc = ("name,email\nAlice,alice@example.com\nBob,bob@example.com\n").encode()
    r = pipe.inspect(doc, "text/csv", request_id="p2c",
                     requested_action="PSEUDONYMIZE", pseudonymize_mode="B")
    assert r.disposition == DISPOSITION_PSEUDONYMIZE, r.block_reason
    assert r.route_local is False
    assert r.mode_b_roundtrip is not None  # cloud round-trip wired


def test_field_role_carried_on_matches():
    """Every match carries its field role so a policy can route on it."""
    pipe = _pipeline()
    r = pipe.inspect(_csv_with_salary(), "text/csv", request_id="p2d",
                     requested_action="LOG")
    roles = {m.data_class: m.field_role for m in r.matches}
    # Email → reference-only; salary → operate-on.
    assert roles.get("PII.EMAIL") == "REFERENCE_ONLY"
    assert roles.get("PII.SALARY") == "OPERATE_ON"
