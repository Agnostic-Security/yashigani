"""
Deterministic gate suite — DocumentPolicyStore (2.26 productionised policy layer).

Mode: DETERMINISTIC GATE. Runs against fakeredis — no live Redis required.

Coverage:
  DPS-01  seed_defaults() seeds the demo matrix on an empty namespace
  DPS-02  seed_defaults() is idempotent (no clobber of operator policies)
  DPS-03  add_policy() write-through + fresh monotonic id
  DPS-04  add_policy() rejects out-of-vocab rows (fail-closed validation)
  DPS-05  remove_policy() write-through; returns existence
  DPS-06  persistence: a fresh store over the SAME redis replays state
  DPS-07  to_opa_document() shape matches what policy/document.rego consumes
  DPS-08  config get/set write-through + replay

Author: Tom. Last updated: 2026-06-09.
"""
from __future__ import annotations

import fakeredis
import pytest

from yashigani.documents.policy_store import DocumentPolicyStore


@pytest.fixture
def redis_client():
    return fakeredis.FakeStrictRedis()


def test_dps_01_seed_defaults(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    policies = store.list_policies()
    assert len(policies) == 3
    actions = {p["action"] for p in policies}
    assert actions == {"BLOCK", "PSEUDONYMIZE", "LOG"}


def test_dps_02_seed_idempotent(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    added = store.add_policy(
        data_class="SECRET", format="any", route="any", action="BLOCK",
        description="operator rule",
    )
    # Re-seeding must NOT clobber the operator's rule.
    store.seed_defaults()
    ids = {p["id"] for p in store.list_policies()}
    assert added["id"] in ids
    assert len(store.list_policies()) == 4


def test_dps_03_add_write_through_fresh_id(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    p1 = store.add_policy(data_class="PHI", format="pdf", route="any", action="REDACT")
    p2 = store.add_policy(data_class="PHI", format="docx", route="any", action="REDACT")
    assert p1["id"] != p2["id"]
    # Persisted: a fresh store sees both.
    fresh = DocumentPolicyStore(redis_client)
    fresh_ids = {p["id"] for p in fresh.list_policies()}
    assert p1["id"] in fresh_ids and p2["id"] in fresh_ids


def test_dps_04_rejects_out_of_vocab(redis_client):
    store = DocumentPolicyStore(redis_client)
    with pytest.raises(ValueError):
        store.add_policy(data_class="PII", format="any", route="any", action="DROP")
    with pytest.raises(ValueError):
        store.add_policy(data_class="PII", format="exe", route="any", action="LOG")
    with pytest.raises(ValueError):
        store.add_policy(data_class="PII", format="any", route="moon", action="LOG")


def test_dps_05_remove(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    assert store.remove_policy("1") is True
    assert store.remove_policy("1") is False
    assert all(p["id"] != "1" for p in store.list_policies())
    # Removal persisted.
    fresh = DocumentPolicyStore(redis_client)
    assert all(p["id"] != "1" for p in fresh.list_policies())


def test_dps_06_persistence_replay(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.add_policy(data_class="IP_MARKING", format="any", route="any", action="BLOCK")
    fresh = DocumentPolicyStore(redis_client)
    assert any(p["data_class"] == "IP_MARKING" for p in fresh.list_policies())


def test_dps_07_to_opa_document_shape(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    doc = store.to_opa_document()
    assert set(doc.keys()) == {"policies", "config"}
    assert isinstance(doc["policies"], list) and len(doc["policies"]) == 3
    row = doc["policies"][0]
    assert set(row.keys()) == {
        "data_class", "format", "route", "action",
        "pseudonymize_mode", "small_set_escalation",
    }
    assert set(doc["config"].keys()) == {
        "detokenize_role", "map_ttl_seconds", "small_set_threshold",
    }


def test_dps_08_config_write_through(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.set_config(detokenize_role="custom-role", map_ttl_seconds=60)
    fresh = DocumentPolicyStore(redis_client)
    cfg = fresh.get_config()
    assert cfg["detokenize_role"] == "custom-role"
    assert cfg["map_ttl_seconds"] == 60
    # untouched key keeps default
    assert cfg["small_set_threshold"] == 20
