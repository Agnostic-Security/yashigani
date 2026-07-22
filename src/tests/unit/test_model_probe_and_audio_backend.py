"""
5.0 T4a/T4b — A5 model probe + A6 ollama transcription backend (parse + wiring).

The live GET/POST is verified on the rig; the parse/resolve/refresh logic is
unit-tested here, plus that a probed digest makes the A5 verifier actually
mismatch (the loop the probe closes).
"""
from __future__ import annotations

import hashlib

import pytest

import json as _json

from yashigani.inspection.model_probe import (
    blob_path_for_digest,
    parse_tags_digests,
    probe_weights_sha256,
    refresh_into,
    resolve_weights_blob_path,
    weights_digest_from_manifest,
)
from yashigani.inspection.audio_backends import parse_transcription
from yashigani.inspection.model_integrity import (
    ModelIntegrityVerifier, ModelPinStore, Pin,
)


class _FakeRedis:
    def __init__(self):
        self.kv = {}
    def get(self, k):
        return self.kv.get(k)
    def set(self, k, v, ex=None, nx=False):
        self.kv[k] = v; return True
    def scan_iter(self, m):
        return iter([k for k in self.kv if k.startswith(m.rstrip("*"))])


class TestManifestParse:
    def test_parses_name_and_digest(self):
        data = {"models": [
            {"name": "qwen2.5:3b", "digest": "sha256:abc123"},
            {"model": "llama3.1:8b", "digest": "sha256:def456"},
        ]}
        out = parse_tags_digests(data)
        assert out == {"qwen2.5:3b": "sha256:abc123", "llama3.1:8b": "sha256:def456"}

    def test_empty_and_none(self):
        assert parse_tags_digests(None) == {}
        assert parse_tags_digests({}) == {}
        assert parse_tags_digests({"models": [{"name": "x"}]}) == {}  # no digest


class TestBlobResolve:
    def test_resolves_present_blob(self, tmp_path):
        blob = tmp_path / "sha256-deadbeef"
        blob.write_bytes(b"weights")
        assert blob_path_for_digest("sha256:deadbeef", str(tmp_path)) == str(blob)
        assert blob_path_for_digest("sha256-deadbeef", str(tmp_path)) == str(blob)

    def test_absent_blob_is_none(self, tmp_path):
        assert blob_path_for_digest("sha256:missing", str(tmp_path)) is None
        assert blob_path_for_digest("", str(tmp_path)) is None

    def test_weights_digest_from_manifest(self):
        manifest = {"layers": [
            {"mediaType": "application/vnd.ollama.image.template", "digest": "sha256:tpl"},
            {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:WEIGHTS"},
        ]}
        assert weights_digest_from_manifest(manifest) == "sha256:WEIGHTS"
        assert weights_digest_from_manifest({"layers": []}) == ""
        assert weights_digest_from_manifest(None) == ""

    def test_manifest_walk_to_weights_blob(self, tmp_path):
        # Lay out an ollama-style store: manifests/<reg>/library/<model>/<tag>
        # and blobs/sha256-<weights>. probe must walk manifest → weights layer.
        blob_dir = tmp_path / "blobs"
        blob_dir.mkdir()
        (blob_dir / "sha256-WEIGHTS").write_bytes(b"the actual weights tensors")
        man_dir = tmp_path / "manifests"
        model_dir = man_dir / "registry.ollama.ai" / "library" / "qwen2.5"
        model_dir.mkdir(parents=True)
        (model_dir / "3b").write_text(_json.dumps({"layers": [
            {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:WEIGHTS"},
        ]}))
        path = resolve_weights_blob_path("qwen2.5:3b", str(man_dir), str(blob_dir))
        assert path == str(blob_dir / "sha256-WEIGHTS")
        out = probe_weights_sha256({"qwen2.5:3b": "sha256:manifestdigest"},
                                   blob_dir=str(blob_dir), manifest_dir=str(man_dir))
        assert out["qwen2.5:3b"] == hashlib.sha256(b"the actual weights tensors").hexdigest()


class TestRefreshAndVerifierLoop:
    def test_refresh_populates_and_verifier_mismatches(self, tmp_path, monkeypatch):
        # Probe returns a digest that does NOT match the pin → verifier blocks.
        monkeypatch.setattr(
            "yashigani.inspection.model_probe.probe_manifest_digests",
            lambda base, timeout=5.0: {"qwen2.5:3b": "sha256:OBSERVED_EVIL"},
        )
        digests, weights = {}, {}
        n = refresh_into(digests, weights, "http://ollama:0", blob_dir=str(tmp_path))
        assert n == 1
        assert digests["qwen2.5:3b"] == "sha256:OBSERVED_EVIL"

        store = ModelPinStore(_FakeRedis())
        store.put(Pin("qwen2.5:3b", weights_sha256="", manifest_digest="sha256:GOOD"))
        v = ModelIntegrityVerifier(store)
        r = v.verify("qwen2.5:3b", observed_manifest_digest=digests["qwen2.5:3b"])
        assert r.ok is False and r.reason == "manifest_mismatch"

    def test_refresh_never_raises_on_probe_error(self, monkeypatch):
        def _boom(base, timeout=5.0):
            raise ConnectionError("ollama down")
        monkeypatch.setattr(
            "yashigani.inspection.model_probe.probe_manifest_digests", _boom)
        digests, weights = {}, {}
        assert refresh_into(digests, weights, "http://ollama:0") == 0
        assert digests == {}


class TestTranscriptionParse:
    @pytest.mark.parametrize("resp,expected", [
        ({"text": "hello world"}, "hello world"),
        ({"transcript": " padded "}, "padded"),
        ({"response": "from response"}, "from response"),
        ({}, ""),
        ({"other": "x"}, ""),
        (None, ""),
        ("not a dict", ""),
    ])
    def test_parse(self, resp, expected):
        assert parse_transcription(resp) == expected
