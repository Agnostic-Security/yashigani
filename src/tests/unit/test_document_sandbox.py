"""
Unit tests for the sandboxed-extractor runtime (plan §6 B1, Captain).

Covers the parts that need NO container daemon:
  - the decompression-bomb / zip-bomb / nesting / entry-count guard
    (bomb_guard.py) — a malicious archive is KILLED by the guard, a benign one
    passes (this is the in-jail first line of containment);
  - the hardened-XML parser factory (XXE / billion-laughs settings);
  - the runner's hardening spec (egress=none, ro-rootfs, caps dropped, non-root,
    seccomp, resource caps) is correct — asserted on the kwargs the runner hands
    the backend, so the security boundary is regression-locked without a daemon;
  - the runner dispatch + fail-closed mapping using a FAKE backend (crash /
    timeout / over-cap / ok=False all map to the right exception);
  - SandboxedExtractor maps a worker ok=True result to an ExtractionResult, and
    every failure path fails closed.

The LIVE containment proof (a real parser process killed on resource abuse) is
the separate harness ``scripts/extractor_sandbox_containment.py`` run under both
Docker and Podman — this file proves the LOGIC; that script proves the JAIL.
"""
from __future__ import annotations

import io
import zipfile

import pytest

from yashigani.documents.bomb_guard import (
    BombGuardLimits,
    DecompressionBombError,
    guard_zip_bytes,
    harden_xml_parser,
)
from yashigani.documents.extractor import (
    DocumentExtractionError,
    ExtractorNotAvailableError,
    ExtractorRegistry,
)
from yashigani.documents.detection import DetectedType
from yashigani.documents.sandbox import (
    SandboxConfig,
    SandboxJobError,
    SandboxJobResult,
    SandboxUnavailableError,
    SandboxedExtractorRunner,
)


# ---------------------------------------------------------------------------
# Decompression-bomb guard
# ---------------------------------------------------------------------------

def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    return buf.getvalue()


def test_guard_passes_benign_ooxml_shaped_zip():
    # A handful of small XML parts — a realistic docx skeleton. Must pass.
    data = _make_zip({
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<document><body>hello</body></document>",
        "docProps/core.xml": b"<coreProperties/>",
    })
    total = guard_zip_bytes(data, BombGuardLimits())
    assert total > 0


def test_guard_kills_high_ratio_zip_bomb():
    # 50 MiB of zeros compresses to a few KiB → ratio is enormous → BOMB.
    bomb = _make_zip({"bomb.bin": b"\x00" * (50 * 1024 * 1024)})
    with pytest.raises(DecompressionBombError) as ei:
        guard_zip_bytes(bomb, BombGuardLimits(max_compression_ratio=200.0))
    assert "ratio" in str(ei.value) or "per-entry cap" in str(ei.value)


def test_guard_kills_per_entry_size_bomb():
    bomb = _make_zip({"big.bin": b"A" * (10 * 1024 * 1024)})
    limits = BombGuardLimits(
        max_entry_decompressed_bytes=1 * 1024 * 1024,
        max_compression_ratio=1_000_000.0,  # don't let ratio fire first
    )
    with pytest.raises(DecompressionBombError) as ei:
        guard_zip_bytes(bomb, limits)
    assert "per-entry cap" in str(ei.value)


def test_guard_kills_entry_count_bomb():
    many = {f"f{i}.txt": b"x" for i in range(5000)}
    bomb = _make_zip(many)
    with pytest.raises(DecompressionBombError) as ei:
        guard_zip_bytes(bomb, BombGuardLimits(max_entry_count=4096))
    assert "entries" in str(ei.value)


def test_guard_kills_nested_zip_over_depth():
    inner = _make_zip({"a.txt": b"hi"})
    mid = _make_zip({"inner.zip": inner})
    outer = _make_zip({"mid.zip": mid})
    with pytest.raises(DecompressionBombError) as ei:
        guard_zip_bytes(outer, BombGuardLimits(max_nesting_depth=1,
                                               max_compression_ratio=1e9))
    assert "nesting depth" in str(ei.value)


def test_guard_total_size_cap():
    data = _make_zip({
        "a.bin": b"A" * (2 * 1024 * 1024),
        "b.bin": b"B" * (2 * 1024 * 1024),
    })
    limits = BombGuardLimits(
        max_total_decompressed_bytes=3 * 1024 * 1024,
        max_entry_decompressed_bytes=10 * 1024 * 1024,
        max_compression_ratio=1e9,
    )
    with pytest.raises(DecompressionBombError) as ei:
        guard_zip_bytes(data, limits)
    assert "total decompressed" in str(ei.value)


def test_bomb_guard_limits_validation():
    with pytest.raises(ValueError):
        BombGuardLimits(max_total_decompressed_bytes=0)
    with pytest.raises(ValueError):
        BombGuardLimits(max_compression_ratio=1.0)


# ---------------------------------------------------------------------------
# Hardened XML parser (XXE / billion-laughs)
# ---------------------------------------------------------------------------

def test_hardened_xml_parser_does_not_expand_entities():
    lxml = pytest.importorskip("lxml")
    from lxml import etree

    parser = harden_xml_parser()
    billion_laughs = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE lolz ['
        b'  <!ENTITY lol "lol">'
        b'  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">'
        b']>'
        b'<lolz>&lol2;</lolz>'
    )
    root = etree.fromstring(billion_laughs, parser=parser)
    # resolve_entities=False → the entity is NOT expanded into text.
    assert "lollollol" not in (root.text or "")


# ---------------------------------------------------------------------------
# Runner hardening spec — regression-lock the security boundary (no daemon)
# ---------------------------------------------------------------------------

def test_runner_hardening_kwargs_enforce_isolation():
    cfg = SandboxConfig()
    kw = SandboxedExtractorRunner._hardened_run_kwargs("job", ["--job", "extract"], cfg)
    # Isolation invariants — these are the security boundary (plan §6).
    assert kw["network_disabled"] is True          # egress = NONE
    assert kw["read_only"] is True                  # ro rootfs
    assert kw["cap_drop"] == ["ALL"]                # all caps dropped
    assert kw["cap_add"] == []                      # none added
    assert kw["user"].startswith("65532")           # non-root numeric UID
    assert "no-new-privileges:true" in kw["security_opt"]
    assert kw["seccomp_path"].endswith("yashigani-extractor.json")
    assert kw["apparmor_profile"] == "yashigani-extractor"
    # No host bind mounts — only a small noexec tmpfs.
    assert "/tmp" in kw["tmpfs"]
    assert "noexec" in kw["tmpfs"]["/tmp"]
    # Resource caps present.
    assert kw["mem_limit"] == cfg.mem_limit
    assert kw["memswap_limit"] == cfg.mem_limit      # swap disabled
    # CPU quota is set where the cpu cgroup controller is delegated; on rootless
    # Podman without cpu delegation it degrades to 0 (no quota) — isolation is
    # preserved by the wall-clock + mem caps, so accept either.
    assert kw["nano_cpus"] in (int(cfg.cpus * 1_000_000_000), 0)
    assert kw["pids_limit"] == cfg.pids_limit


def test_sandbox_config_from_env_overrides(monkeypatch):
    monkeypatch.setenv("YASHIGANI_EXTRACTOR_TIMEOUT_S", "5")
    monkeypatch.setenv("YASHIGANI_EXTRACTOR_MEM_LIMIT", "256m")
    monkeypatch.setenv("YASHIGANI_EXTRACTOR_PIDS_LIMIT", "32")
    cfg = SandboxConfig.from_env()
    assert cfg.timeout_s == 5
    assert cfg.mem_limit == "256m"
    assert cfg.pids_limit == 32


def test_sandbox_config_from_env_rejects_garbage(monkeypatch):
    monkeypatch.setenv("YASHIGANI_EXTRACTOR_TIMEOUT_S", "not-a-number")
    monkeypatch.setenv("YASHIGANI_EXTRACTOR_PIDS_LIMIT", "-9")
    cfg = SandboxConfig.from_env()
    assert cfg.timeout_s == 20    # default
    assert cfg.pids_limit == 64   # default (rejected the negative)


# ---------------------------------------------------------------------------
# Runner dispatch + fail-closed mapping (fake backend, no daemon)
# ---------------------------------------------------------------------------

class _FakeBackend:
    """Stand-in for ContainerBackend.run_extractor_job."""

    def __init__(self, *, stdout=b"", exit_code=0, killed=False, raises=None):
        self._stdout = stdout
        self._exit_code = exit_code
        self._killed = killed
        self._raises = raises
        self.last_kwargs = None

    def run_extractor_job(self, *, stdin, timeout_s, **kwargs):
        self.last_kwargs = {"stdin_len": len(stdin), "timeout_s": timeout_s, **kwargs}
        if self._raises is not None:
            raise self._raises
        return (self._stdout, self._exit_code, self._killed)


def _runner(backend):
    return SandboxedExtractorRunner(backend=backend)


def test_run_job_success_parses_worker_result():
    out = b'{"ok":true,"segments":[{"text":"hi","kind":"BODY","location":"page=1"}],"extraction_complete":true,"detected_format":"pdf"}'
    r = _runner(_FakeBackend(stdout=out)).run_job(
        b"x", job="extract", fmt="pdf", declared_mime="application/pdf")
    assert r.ok is True
    assert r.extraction_complete is True
    assert r.segments[0]["text"] == "hi"


def test_run_job_killed_maps_to_joberor():
    with pytest.raises(SandboxJobError) as ei:
        _runner(_FakeBackend(killed=True, exit_code=137)).run_job(
            b"x", job="extract", fmt="docx", declared_mime="")
    assert ei.value.killed is True
    assert "killed" in ei.value.reason


def test_run_job_nonzero_exit_maps_to_joberor():
    with pytest.raises(SandboxJobError) as ei:
        _runner(_FakeBackend(exit_code=70)).run_job(
            b"x", job="extract", fmt="docx", declared_mime="")
    assert "exited 70" in ei.value.reason


def test_run_job_output_amplification_capped():
    big = b'{"ok":true,"segments":[],"extraction_complete":true}' + b" " * (40 * 1024 * 1024)
    runner = SandboxedExtractorRunner(
        backend=_FakeBackend(stdout=big),
        config=SandboxConfig(max_output_bytes=1024),
    )
    with pytest.raises(SandboxJobError) as ei:
        runner.run_job(b"x", job="extract", fmt="docx", declared_mime="")
    assert "output" in ei.value.reason


def test_run_job_non_json_output_fails_closed():
    with pytest.raises(SandboxJobError):
        _runner(_FakeBackend(stdout=b"not json")).run_job(
            b"x", job="extract", fmt="docx", declared_mime="")


def test_run_job_contained_ok_false():
    out = b'{"ok":false,"reason":"zip bomb ratio 1000:1"}'
    r = _runner(_FakeBackend(stdout=out)).run_job(
        b"x", job="extract", fmt="docx", declared_mime="")
    assert r.ok is False
    assert "bomb" in r.reason


def test_runner_passes_hardened_kwargs_to_backend():
    fb = _FakeBackend(stdout=b'{"ok":true,"segments":[],"extraction_complete":true}')
    _runner(fb).run_job(b"doc-bytes", job="extract", fmt="xlsx", declared_mime="")
    kw = fb.last_kwargs
    assert kw["network_disabled"] is True
    assert kw["read_only"] is True
    assert kw["cap_drop"] == ["ALL"]
    assert kw["stdin_len"] == len(b"doc-bytes")


# ---------------------------------------------------------------------------
# SandboxedExtractor integration into the registry (fail-closed mapping)
# ---------------------------------------------------------------------------

def test_sandboxed_extractor_unavailable_maps_to_not_available():
    class _NoBackend(SandboxedExtractorRunner):
        def _resolve_backend(self):
            raise SandboxUnavailableError("no backend")

    reg = ExtractorRegistry(sandbox_runner=_NoBackend(backend=None))
    pdf = b"%PDF-1.7\nstuff"
    with pytest.raises(ExtractorNotAvailableError):
        reg.extract(pdf, "application/pdf")


def test_sandboxed_extractor_job_failure_maps_to_extraction_error():
    runner = SandboxedExtractorRunner(backend=_FakeBackend(exit_code=70))
    reg = ExtractorRegistry(sandbox_runner=runner)
    with pytest.raises(DocumentExtractionError):
        reg.extract(b"%PDF-1.7\nstuff", "application/pdf")


def test_sandboxed_extractor_contained_maps_to_extraction_error():
    out = b'{"ok":false,"reason":"zip bomb"}'
    runner = SandboxedExtractorRunner(backend=_FakeBackend(stdout=out))
    reg = ExtractorRegistry(sandbox_runner=runner)
    # OOXML magic so detection routes to the sandboxed docx extractor.
    ooxml = b"PK\x03\x04" + b"\x00" * 40
    with pytest.raises(DocumentExtractionError):
        reg.extract(ooxml, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")


def test_sandboxed_extractor_success_yields_segments():
    out = (b'{"ok":true,"segments":['
           b'{"text":"secret","kind":"COMMENT","location":"word/comments.xml"}'
           b'],"extraction_complete":true,"detected_format":"docx"}')
    runner = SandboxedExtractorRunner(backend=_FakeBackend(stdout=out))
    reg = ExtractorRegistry(sandbox_runner=runner)
    ooxml = b"PK\x03\x04" + b"\x00" * 40
    result = reg.extract(
        ooxml,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    assert result.extraction_complete is True
    assert result.segments[0].text == "secret"
    assert result.segments[0].kind.value == "COMMENT"
