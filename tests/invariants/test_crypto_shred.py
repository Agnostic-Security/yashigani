"""Crypto-shred erasure — core invariant tests (GDPR Art 17 over the audit chain).

Proves the load-bearing invariants of src/yashigani/audit/crypto_shred.py:
  1. Human-vs-NHI field selection (agent identifiers NEVER sealed).
  2. Encrypt-at-reference: subject fields sealed to a stable ciphertext envelope.
  3. Erasure destroys the DEK → data becomes unrecoverable.
  4. Chain integrity survives erasure: the sealed ciphertext is byte-stable, so
     the SHA-384 leaf hash (computed over the sealed dict) is unchanged by a
     later DEK destruction.

Design: Products/Yashigani/crypto-shred-erasure-design-5.0-20260712.md
"""

import dataclasses
import json

import pytest

from yashigani.audit import crypto_shred as cs


class _FakeRedis:
    def __init__(self):
        self.d, self.h = {}, {}

    def get(self, k):
        return self.d.get(k)

    def set(self, k, v):
        self.d[k] = v

    def delete(self, k):
        return 1 if self.d.pop(k, None) is not None else 0

    def hset(self, k, field=None, value=None, mapping=None):
        self.h.setdefault(k, {})
        if mapping:
            self.h[k].update(mapping)
        elif field is not None:
            self.h[k][field] = value

    def hget(self, k, f):
        return self.h.get(k, {}).get(f)


class _FakeKMS:
    def __init__(self):
        self.d = {}

    def get_secret(self, k):
        if k not in self.d:
            raise KeyError(k)
        return self.d[k]

    def set_secret(self, k, v):
        self.d[k] = v


@dataclasses.dataclass
class _Evt:
    tenant_id: str = "t1"
    admin_account: str = "alice@corp.com"        # human subject -> seal
    operator_identity: str = "carol@corp.com"    # human subject -> seal
    identity_id: str = "spiffe://td/agents/x"    # NHI (agent) -> NEVER seal
    agent_id: str = "agent-7"                     # NHI -> NEVER seal
    scope: str = "user"
    scope_id: str = "bob@corp.com"               # conditional (scope==user) -> seal
    reason: str = "login"                         # non-subject -> never seal


@pytest.fixture()
def shredder(monkeypatch):
    monkeypatch.setenv("YASHIGANI_SUBJECT_ID_SALT", "unit-test-salt")
    ks = cs.CryptoShredKeyStore(_FakeRedis(), _FakeKMS(), dsn="")
    return cs.Shredder(ks)


def test_human_vs_nhi_field_selection(shredder):
    e = shredder.seal(_Evt())
    assert cs.is_envelope(e.admin_account)
    assert cs.is_envelope(e.operator_identity)
    assert cs.is_envelope(e.scope_id)                 # scope == "user"
    assert e.identity_id == "spiffe://td/agents/x"    # NHI untouched
    assert e.agent_id == "agent-7"                     # NHI untouched
    assert e.reason == "login"                         # non-subject untouched


def test_conditional_scope_id_not_sealed_when_org(shredder):
    e = _Evt(scope="org", scope_id="org-123")
    e = shredder.seal(e)
    assert e.scope_id == "org-123"                     # not a user -> cleartext


def test_seal_is_idempotent(shredder):
    e = shredder.seal(_Evt())
    first = e.admin_account
    e = shredder.seal(e)                               # re-seal must be a no-op
    assert e.admin_account == first


def test_unseal_round_trip(shredder):
    e = shredder.seal(_Evt())
    assert shredder.unseal_value("t1", e.admin_account, "admin_account") == "alice@corp.com"


def test_erasure_makes_data_unrecoverable_and_chain_stable(shredder):
    e = shredder.seal(_Evt())
    before = json.dumps(dataclasses.asdict(e), sort_keys=True)

    subject = cs.derive_subject_id("t1", "alice@corp.com")
    cert = shredder.erase_subject("t1", subject)
    assert cert["shredded"] and cert["dek_existed"]

    # data is now irrecoverable
    assert shredder.unseal_value("t1", e.admin_account, "admin_account") is None
    # ciphertext (hence the chain leaf hash over the sealed dict) is byte-stable
    after = json.dumps(dataclasses.asdict(e), sort_keys=True)
    assert before == after


def test_idnt_subject_id_passthrough():
    assert cs.derive_subject_id("t1", "idnt_abc123") == "idnt_abc123"
    other = cs.derive_subject_id("t1", "someone@corp.com")
    assert other.startswith("subj_") and len(other) == len("subj_") + 32


def test_derive_subject_id_case_insensitive():
    a = cs.derive_subject_id("t1", "Alice@Corp.com")
    b = cs.derive_subject_id("t1", "alice@corp.com")
    assert a == b
