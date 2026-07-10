"""#21: audit SIEM targets are loaded from deployment config at startup.

The forwarding target set is owned by the deployment layer (install.sh / compose
env), not the running app's admin state — so it survives restarts and is
populated when a SIEM (e.g. bundled Wazuh) is selected at install. None
configured → none forwarded.
"""
import json

import pytest

from yashigani.audit.writer import SiemTarget, siem_targets_from_env

ENV = "YASHIGANI_SIEM_TARGETS"


def test_unset_returns_empty(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    assert siem_targets_from_env() == []  # none configured → none


def test_empty_string_returns_empty(monkeypatch):
    monkeypatch.setenv(ENV, "   ")
    assert siem_targets_from_env() == []


def test_loads_a_wazuh_target(monkeypatch):
    monkeypatch.setenv(ENV, json.dumps([{
        "name": "wazuh-bundled",
        "target_type": "elastic_opensearch",
        "url": "https://wazuh-indexer:9200",
        "auth_header": "Authorization",
        "auth_value": "Basic c2VjcmV0",
    }]))
    targets = siem_targets_from_env()
    assert len(targets) == 1
    t = targets[0]
    assert isinstance(t, SiemTarget)
    assert t.name == "wazuh-bundled"
    assert t.target_type == "elastic_opensearch"
    assert t.url == "https://wazuh-indexer:9200"
    assert t.enabled is True  # defaulted


def test_malformed_json_returns_empty_never_raises(monkeypatch):
    monkeypatch.setenv(ENV, "{not json")
    assert siem_targets_from_env() == []


def test_non_array_returns_empty(monkeypatch):
    monkeypatch.setenv(ENV, json.dumps({"name": "x"}))
    assert siem_targets_from_env() == []


def test_entry_missing_required_field_is_skipped_others_kept(monkeypatch):
    monkeypatch.setenv(ENV, json.dumps([
        {"name": "good", "target_type": "webhook", "url": "https://siem.example/in",
         "auth_value": "tok"},
        {"name": "bad-no-url", "target_type": "webhook", "auth_value": "tok"},
    ]))
    targets = siem_targets_from_env()
    assert [t.name for t in targets] == ["good"]


def test_mesh_mtls_target_needs_no_shared_secret(monkeypatch):
    # #21: the bundled-Wazuh target authenticates by mesh leaf cert (mesh_mtls),
    # so auth_value is optional — the entry must still load.
    monkeypatch.setenv(ENV, json.dumps([{
        "name": "wazuh-bundled",
        "target_type": "elastic_opensearch",
        "url": "https://wazuh-indexer:9200/_bulk",
        "mesh_mtls": True,
    }]))
    targets = siem_targets_from_env()
    assert len(targets) == 1
    t = targets[0]
    assert t.mesh_mtls is True
    assert t.auth_value == ""  # cert identity, no shared secret


def test_header_auth_target_defaults_mesh_mtls_false(monkeypatch):
    monkeypatch.setenv(ENV, json.dumps([{
        "name": "splunk",
        "target_type": "splunk_hec",
        "url": "https://splunk.example.com/services/collector",
        "auth_value": "Splunk tok",
    }]))
    t = siem_targets_from_env()[0]
    assert t.mesh_mtls is False
    assert t.auth_value == "Splunk tok"
