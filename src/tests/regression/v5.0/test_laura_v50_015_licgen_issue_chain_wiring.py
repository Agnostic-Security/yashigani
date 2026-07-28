# Last updated: 2026-07-28T00:00:00+00:00
"""
Regression — LAURA-V50-015: `licgen.py issue` imported `scripts/sign_license.py`,
which does not exist anywhere in this branch (nor the canonical v4.1.2 line).
Every `licgen issue` invocation crashed with:

    ModuleNotFoundError: No module named 'sign_license'

`licgen issue` is the documented, operator-facing tool for minting a client's
v5 `.ysg` licence — it was completely dead.

Fix (Tom, 2026-07-28): `_cmd_issue` in `scripts/licgen.py` now calls the
chain primitives directly instead of importing the missing wrapper module:

    yashigani.licensing.chain.licence_v5.build_licence_payload_v5
    yashigani.licensing.chain.licence_v5.sign_licence_v5
    yashigani.licensing.chain.signer.PemSigner (role=Role.LICENCE)

These are the SAME primitives Laura used (bypassing the broken CLI) to mint
every forged/legitimate v5 licence during Priority 2 pentest testing this
session — proven functional independent of this fix.

This test exercises the full operator flow through the licgen CLI functions
(no subprocess — imports scripts/licgen.py directly, matching how the other
scripts/*.py test suites in this repo invoke CLI command functions):

  1. `licgen anchor-set new`  (master anchor)
  2. `licgen new-leaf --role licence` (client licence leaf, master-certified)
  3. `licgen issue`            (THE FIX — must NOT raise ModuleNotFoundError)
  4. Round-trip the emitted `.ysg` through `parse_licence_v5` AND
     `verify_licence_v5` (full chain-of-trust verify, not just a parse) to
     prove the issued licence is not just well-formed but actually valid.
"""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3].parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _load_licgen_module():
    """Import scripts/licgen.py as a module named 'licgen' (it is not part
    of a package — licgen.py itself inserts src/ and scripts/ onto sys.path
    at import time, which is what lets its own `import keygen` work)."""
    if "licgen" in sys.modules:
        return sys.modules["licgen"]
    spec = importlib.util.spec_from_file_location("licgen", SCRIPTS_DIR / "licgen.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["licgen"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def licgen(monkeypatch, tmp_path):
    monkeypatch.setenv("YASHIGANI_MASTER_KEY_PASSPHRASE", "test-master-passphrase-v50-015")
    monkeypatch.setenv("YASHIGANI_KEY_PASSPHRASE", "test-leaf-passphrase-v50-015")
    monkeypatch.delenv("YASHIGANI_MASTER_KEY_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("YASHIGANI_KEY_PASSPHRASE_FILE", raising=False)
    module = _load_licgen_module()
    yield module


def _ns(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


class TestLicgenIssueChainWiring:
    """LAURA-V50-015: licgen issue must mint a valid v5 licence without
    importing the nonexistent scripts/sign_license.py module."""

    def test_issue_no_longer_raises_modulenotfounderror(self, licgen, tmp_path):
        keys_dir = tmp_path / "keys"
        registry_path = tmp_path / "registry.json"

        # 1. Master anchor.
        licgen._cmd_anchor_new(_ns(
            channel="prod", keys_dir=str(keys_dir), registry=str(registry_path),
            anchor_id="M-TEST-1", note="LAURA-V50-015 regression", force=False,
        ))

        # 2. Client licence leaf, master-certified.
        licgen._cmd_new_leaf(_ns(
            channel="prod", keys_dir=str(keys_dir), registry=str(registry_path),
            role="licence", version=None, client_id="acme-corp",
            org_domain="acme.example.com", serial=None, window_days=30,
            master_anchor_id="M-TEST-1", master_key=None, force=False,
        ))

        out_path = tmp_path / "acme-corp-test.ysg"

        # 3. THE FIX — must not raise ModuleNotFoundError('sign_license').
        licgen._cmd_issue(_ns(
            channel="prod", keys_dir=str(keys_dir), registry=str(registry_path),
            domain="acme.example.com", tier="professional", client_id="acme-corp",
            licence_serial=None, expires_at=None, expires_days=30,
            max_agents=None, max_end_users=None, max_admin_seats=None,
            max_orgs=None, features=None, out=str(out_path),
        ))

        assert out_path.exists()
        wire = out_path.read_text(encoding="utf-8")
        assert wire.count(".") == 3  # v5 wire format: 4 dot-separated segments

    def test_issued_licence_round_trips_through_parse_and_verify(self, licgen, tmp_path):
        from yashigani.licensing.chain.kill_list import KillList
        from yashigani.licensing.chain.licence_v5 import parse_licence_v5, verify_licence_v5
        from yashigani.licensing.chain.registry import KeyRegistry

        keys_dir = tmp_path / "keys"
        registry_path = tmp_path / "registry.json"

        licgen._cmd_anchor_new(_ns(
            channel="prod", keys_dir=str(keys_dir), registry=str(registry_path),
            anchor_id="M-TEST-2", note="LAURA-V50-015 round-trip", force=False,
        ))
        licgen._cmd_new_leaf(_ns(
            channel="prod", keys_dir=str(keys_dir), registry=str(registry_path),
            role="licence", version=None, client_id="globex-inc",
            org_domain="globex.example.com", serial=None, window_days=30,
            master_anchor_id="M-TEST-2", master_key=None, force=False,
        ))

        out_path = tmp_path / "globex.ysg"
        licgen._cmd_issue(_ns(
            channel="prod", keys_dir=str(keys_dir), registry=str(registry_path),
            domain="globex.example.com", tier="starter", client_id="globex-inc",
            licence_serial="lic-globex-0001", expires_at=None, expires_days=90,
            max_agents=None, max_end_users=None, max_admin_seats=None,
            max_orgs=None, features=["egress_prompt_injection"], out=str(out_path),
        ))

        wire = out_path.read_text(encoding="utf-8")

        # parse_licence_v5 — well-formed 4-segment payload.
        parsed = parse_licence_v5(wire)
        assert parsed.payload["client_id"] == "globex-inc"
        assert parsed.payload["org_domain"] == "globex.example.com"
        assert parsed.payload["tier"] == "starter"
        assert parsed.payload["licence_serial"] == "lic-globex-0001"
        # tier default fallback (TIER_DEFAULTS["starter"]) applied when the
        # CLI flags were left unset (None) rather than writing None/0 to the
        # wire payload.
        assert parsed.payload["max_agents"] == 400
        assert parsed.payload["max_end_users"] == 100

        # verify_licence_v5 — full chain-of-trust verify: leaf_cert chains to
        # the registered master anchor AND the leaf signature is valid.
        registry = KeyRegistry(registry_path)
        anchor_set = registry.emit_current_anchor_set()
        result = verify_licence_v5(wire, anchor_set=anchor_set, kill_list=KillList([]))
        assert result.valid is True, f"expected valid v5 licence, got error={result.error!r}"
        assert result.payload["client_id"] == "globex-inc"

    def test_issue_errors_cleanly_when_no_licence_leaf_registered(self, licgen, tmp_path):
        """No sign_license import to fail on anymore — the CLI's own
        pre-flight check (no active LICENCE leaf) must still fire cleanly."""
        keys_dir = tmp_path / "keys"
        registry_path = tmp_path / "registry.json"  # deliberately never created — empty registry
        keys_dir.mkdir(parents=True)

        with pytest.raises(SystemExit) as exc_info:
            licgen._cmd_issue(_ns(
                channel="prod", keys_dir=str(keys_dir), registry=str(registry_path),
                domain="nobody.example.com", tier="community", client_id="nobody",
                licence_serial=None, expires_at=None, expires_days=None,
                max_agents=None, max_end_users=None, max_admin_seats=None,
                max_orgs=None, features=None, out=None,
            ))
        assert exc_info.value.code == 1
