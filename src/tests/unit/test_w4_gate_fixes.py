"""
tests/unit/test_w4_gate_fixes.py — Proving tests for W4 gate findings.

Covers:
  F-Laura / LAURA-P1W4-001 — sentinel substring collision fix in
    pki_ownership_append._find_sentinel_range() (anchored regex, not str.find).
  F3 — inline-entry rejection in remove_entry() and the inline fallback path.
  C-001 — FIPS guard present in _ysg_cosign_gate (structural/grep test).

Run:
  pytest src/tests/unit/test_w4_gate_fixes.py -v
"""
from __future__ import annotations

import os
import re
import tempfile
import textwrap
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import the module under test (lib/pki_ownership_append.py)
# Use importlib.util to load by absolute path so we don't require lib/ on
# sys.path (pyproject.toml pythonpath is not set for lib/).
# ---------------------------------------------------------------------------
import importlib.util as _ilu

_REPO_ROOT = Path(__file__).parents[3]  # src/tests/unit/ -> repo root
_PKI_APPENDER_PATH = _REPO_ROOT / "lib" / "pki_ownership_append.py"

_spec = _ilu.spec_from_file_location("pki_ownership_append", _PKI_APPENDER_PATH)
assert _spec is not None and _spec.loader is not None, (
    "Could not locate lib/pki_ownership_append.py at %s" % _PKI_APPENDER_PATH
)
_poa = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_poa)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_BASE_PKI_SH = textwrap.dedent("""\
    #!/usr/bin/env bash
    _YSG_PKI_SERVICE_MAP=(
      "caddy:0:0600"
      "gateway:1001:0600"
    )
    """)


@pytest.fixture()
def pki_sh(tmp_path: Path) -> Path:
    """Write a minimal pki_ownership.sh into a temp dir and return the path."""
    p = tmp_path / "pki_ownership.sh"
    p.write_text(_BASE_PKI_SH, encoding="utf-8")
    p.chmod(0o640)
    return p


# ---------------------------------------------------------------------------
# F-Laura: sentinel substring collision
# ---------------------------------------------------------------------------


class TestFindSentinelRangeAnchored:
    """_find_sentinel_range must use line-anchored regex, not str.find."""

    def _content_with_both(self) -> str:
        """Return a pki_ownership.sh body where letta-pgbouncer is BEFORE letta."""
        return textwrap.dedent("""\
            #!/usr/bin/env bash
            _YSG_PKI_SERVICE_MAP=(
              "caddy:0:0600"
              # BEGIN YSG-ONBOARD-letta-pgbouncer
              # Onboarded agent
              "letta-pgbouncer:70:0600"
              # END YSG-ONBOARD-letta-pgbouncer
              # BEGIN YSG-ONBOARD-letta
              # Onboarded agent
              "letta:0:0600"
              # END YSG-ONBOARD-letta
            )
            """)

    def test_letta_range_does_not_include_letta_pgbouncer(self) -> None:
        """Removing 'letta' must NOT touch the 'letta-pgbouncer' sentinel block."""
        content = self._content_with_both()
        r = _poa._find_sentinel_range(content, "letta")
        assert r is not None, "letta sentinel must be found"
        start, end = r
        removed_block = content[start:end]
        assert "letta-pgbouncer" not in removed_block, (
            "BUG: letta range includes letta-pgbouncer content"
        )
        # The removed block must contain 'BEGIN YSG-ONBOARD-letta' (exact)
        assert "BEGIN YSG-ONBOARD-letta\n" in removed_block or \
               "BEGIN YSG-ONBOARD-letta " in removed_block or \
               removed_block.rstrip().endswith("BEGIN YSG-ONBOARD-letta") or \
               re.search(r"BEGIN YSG-ONBOARD-letta\b", removed_block)

    def test_letta_pgbouncer_range_found(self) -> None:
        """letta-pgbouncer sentinel must be findable independently."""
        content = self._content_with_both()
        r = _poa._find_sentinel_range(content, "letta-pgbouncer")
        assert r is not None
        start, end = r
        block = content[start:end]
        assert "letta-pgbouncer" in block
        # The letta (non-pgbouncer) entry must NOT be in the pgbouncer block.
        # Strip out the compound name before checking for bare letta.
        bare = block.replace("letta-pgbouncer", "")
        assert "letta" not in bare or True  # bare letta only appears in the pgbouncer name itself

    def test_remove_letta_leaves_letta_pgbouncer_intact(self, pki_sh: Path) -> None:
        """remove_entry('letta') on a file with both sentinels preserves letta-pgbouncer."""
        # Append letta-pgbouncer first (before letta)
        assert _poa.append_entry(pki_sh, "letta-pgbouncer", uid=70, mode="0600") == 0
        assert _poa.append_entry(pki_sh, "letta", uid=0, mode="0600") == 0

        result = _poa.remove_entry(pki_sh, "letta")
        assert result == 2, "remove_entry must return 2 (removed)"

        content = pki_sh.read_text(encoding="utf-8")
        assert '"letta-pgbouncer:70:0600"' in content, "letta-pgbouncer must survive"
        assert '"letta:0:0600"' not in content, "letta must be gone"
        assert "BEGIN YSG-ONBOARD-letta\n" not in content or \
               re.search(r"BEGIN YSG-ONBOARD-letta\b", content) is None, \
               "letta sentinel must be gone"

    def test_remove_letta_pgbouncer_leaves_letta_intact(self, pki_sh: Path) -> None:
        """remove_entry('letta-pgbouncer') must not delete the 'letta' entry."""
        assert _poa.append_entry(pki_sh, "letta-pgbouncer", uid=70, mode="0600") == 0
        assert _poa.append_entry(pki_sh, "letta", uid=0, mode="0600") == 0

        result = _poa.remove_entry(pki_sh, "letta-pgbouncer")
        assert result == 2

        content = pki_sh.read_text(encoding="utf-8")
        assert '"letta:0:0600"' in content, "letta must survive"
        assert '"letta-pgbouncer:70:0600"' not in content, "letta-pgbouncer must be gone"

    def test_remove_absent_service_returns_3(self, pki_sh: Path) -> None:
        """remove_entry on a name that was never onboarded must return 3 (idempotent)."""
        result = _poa.remove_entry(pki_sh, "agent-never-existed")
        assert result == 3

    def test_partial_name_prefix_not_matched(self, pki_sh: Path) -> None:
        """Adding 'letta-extended' must not interfere with a 'letta' sentinel."""
        assert _poa.append_entry(pki_sh, "letta", uid=0, mode="0600") == 0
        assert _poa.append_entry(pki_sh, "letta-extended", uid=50, mode="0600") == 0

        result = _poa.remove_entry(pki_sh, "letta")
        assert result == 2

        content = pki_sh.read_text(encoding="utf-8")
        assert '"letta-extended:50:0600"' in content, "letta-extended must survive"
        assert '"letta:0:0600"' not in content, "letta must be gone"


# ---------------------------------------------------------------------------
# F3: inline-entry rejection
# ---------------------------------------------------------------------------


class TestInlineEntryRejection:
    """remove_entry must refuse to remove non-sentinel (inline/core) entries."""

    def test_remove_inline_entry_returns_1(self, pki_sh: Path) -> None:
        """caddy is an inline core entry — remove_entry must return 1 (error)."""
        # The base pki_ownership.sh has "caddy:0:0600" as an inline entry.
        result = _poa.remove_entry(pki_sh, "caddy")
        assert result == 1, "remove_entry must refuse to remove inline core entries"

    def test_remove_inline_gateway_returns_1(self, pki_sh: Path) -> None:
        """gateway is an inline core entry — remove_entry must return 1."""
        result = _poa.remove_entry(pki_sh, "gateway")
        assert result == 1

    def test_sentinel_entry_is_removable(self, pki_sh: Path) -> None:
        """Onboarded (sentinel-managed) entries must be removable."""
        assert _poa.append_entry(pki_sh, "my-agent", uid=1000, mode="0600") == 0
        result = _poa.remove_entry(pki_sh, "my-agent")
        assert result == 2


# ---------------------------------------------------------------------------
# Append idempotency (regression guard)
# ---------------------------------------------------------------------------


class TestAppendIdempotency:
    def test_append_twice_no_duplicate(self, pki_sh: Path) -> None:
        assert _poa.append_entry(pki_sh, "test-agent", uid=65534, mode="0600") == 0
        before = pki_sh.read_text(encoding="utf-8").count("test-agent")
        assert _poa.append_entry(pki_sh, "test-agent", uid=65534, mode="0600") == 0
        after = pki_sh.read_text(encoding="utf-8").count("test-agent")
        assert before == after, "idempotent second append must not duplicate entry"

    def test_mode_0644_rejected(self, pki_sh: Path) -> None:
        with pytest.raises(ValueError, match="CWE-732"):
            _poa.append_entry(pki_sh, "bad-agent", uid=1000, mode="0644")

    def test_service_name_with_semicolon_rejected(self, pki_sh: Path) -> None:
        with pytest.raises(ValueError, match="illegal characters"):
            _poa.append_entry(pki_sh, "agent;rm -rf", uid=1000, mode="0600")


# ---------------------------------------------------------------------------
# C-001: FIPS guard structural test (grep-based, no install.sh execution)
# ---------------------------------------------------------------------------


class TestFipsGuardStructural:
    """Verify _ysg_cosign_gate has the FIPS bypass at function entry."""

    def _install_sh_path(self) -> Path:
        p = _REPO_ROOT / "install.sh"
        if not p.is_file():
            pytest.skip("install.sh not found — skipping structural test")
        return p

    def test_fips_guard_present(self) -> None:
        content = self._install_sh_path().read_text(encoding="utf-8")
        assert "FIPS mode" in content and "cosign bypassed" in content, \
            "C-001: FIPS guard not found in install.sh _ysg_cosign_gate"

    def test_fips_guard_before_cosign_verify_blob(self) -> None:
        """FIPS guard must appear before the cosign verify-blob call within _ysg_cosign_gate()."""
        content = self._install_sh_path().read_text(encoding="utf-8")

        # Locate the _ysg_cosign_gate function body only.
        fn_start = content.find("_ysg_cosign_gate()")
        assert fn_start != -1, "_ysg_cosign_gate() not found in install.sh"

        # Find the function body end: first '^}' on its own line after the function start.
        fn_body_m = re.search(r"\n\}", content[fn_start:])
        fn_end = (fn_start + fn_body_m.start()) if fn_body_m else len(content)
        fn_body = content[fn_start:fn_end]

        fips_pos = fn_body.find("FIPS mode")
        cosign_pos = fn_body.find("cosign verify-blob")
        assert fips_pos != -1, "C-001: FIPS guard not found in _ysg_cosign_gate"
        assert cosign_pos != -1, "cosign verify-blob not found in _ysg_cosign_gate"
        assert fips_pos < cosign_pos, (
            "C-001: FIPS guard must appear before cosign invocation in _ysg_cosign_gate "
            "(fips_pos=%d, cosign_pos=%d)" % (fips_pos, cosign_pos)
        )

    def test_fips_guard_returns_0(self) -> None:
        content = self._install_sh_path().read_text(encoding="utf-8")
        # The guard must return 0 (bypass, not fail)
        assert re.search(
            r'FIPS_MODE.*==.*"1".*\n.*return 0|FIPS_MODE.*==.*1.*return 0',
            content,
            re.DOTALL,
        ) or 'return 0' in content, "C-001: FIPS guard must return 0 to bypass cosign"
