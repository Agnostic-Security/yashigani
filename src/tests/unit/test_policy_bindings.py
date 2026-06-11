"""#16 — unit tests for the policy-binding store + OPA push namespace."""
import json

import pytest

from yashigani.policy_bindings.store import BindingStore, PolicyBinding
from yashigani.policy_bindings import opa_push


class _FakeRedis:
    """Minimal in-memory Redis stand-in (set/get/delete/scan) for db/3."""

    def __init__(self):
        self.kv = {}

    def set(self, k, v):
        self.kv[k] = v

    def get(self, k):
        return self.kv.get(k)

    def delete(self, k):
        self.kv.pop(k, None)

    def scan(self, cursor, match="*", count=200):
        import fnmatch
        keys = [k for k in self.kv if fnmatch.fnmatch(k, match)]
        return 0, keys


def _store():
    return BindingStore(_FakeRedis())


def test_add_get_list_remove_roundtrip():
    s = _store()
    b = s.add(PolicyBinding(policy_name="deny_secrets", scope_kind="agent", scope_id="openclaw", direction="ingress"))
    assert s.get(b.id).policy_name == "deny_secrets"
    assert len(s.list()) == 1
    assert s.remove(b.id) is True
    assert s.get(b.id) is None
    assert s.remove("nope") is False


def test_replay_from_redis_on_construct():
    r = _FakeRedis()
    s1 = BindingStore(r)
    b = s1.add(PolicyBinding(policy_name="p", scope_kind="human", direction="both"))
    # new store on the same redis must replay the binding
    s2 = BindingStore(r)
    assert s2.get(b.id) is not None
    assert s2.get(b.id).policy_name == "p"


def test_invalid_scope_kind_and_direction_rejected():
    s = _store()
    with pytest.raises(ValueError):
        s.add(PolicyBinding(policy_name="p", scope_kind="martian", direction="ingress"))
    with pytest.raises(ValueError):
        s.add(PolicyBinding(policy_name="p", scope_kind="agent", direction="sideways"))
    with pytest.raises(ValueError):
        s.add(PolicyBinding(policy_name="", scope_kind="agent", direction="ingress"))


def test_scope_key_specific_vs_wildcard():
    assert PolicyBinding("p", "agent", "ingress", scope_id="openclaw").scope_key() == "agent:openclaw"
    assert PolicyBinding("p", "agent", "ingress", scope_id="").scope_key() == "agent:*"


def test_to_opa_document_shape_and_both_direction():
    s = _store()
    s.add(PolicyBinding(policy_name="deny_secrets", scope_kind="agent", scope_id="openclaw", direction="ingress"))
    s.add(PolicyBinding(policy_name="audit_all", scope_kind="agent", scope_id="", direction="both"))
    doc = s.to_opa_document()
    assert set(doc.keys()) == {"client_bindings"}
    cb = doc["client_bindings"]
    assert cb["agent:openclaw"]["ingress"] == ["deny_secrets"]
    assert cb["agent:openclaw"]["egress"] == []
    # "both" lands in both lists under the wildcard scope key
    assert cb["agent:*"]["ingress"] == ["audit_all"]
    assert cb["agent:*"]["egress"] == ["audit_all"]


def test_disabled_binding_excluded_from_opa_document():
    s = _store()
    s.add(PolicyBinding(policy_name="off", scope_kind="agent", scope_id="x", direction="ingress", enabled=False))
    assert s.to_opa_document()["client_bindings"] == {}


def test_push_targets_client_bindings_namespace_not_yashigani():
    # Guard the namespace-clobber invariant from the design.
    assert opa_push._OPA_DATA_PATH == "/v1/data/client_bindings"
    assert "yashigani" not in opa_push._OPA_DATA_PATH
