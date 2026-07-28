"""
Regression test — passphrase env-var unification between keygen.py's
ENCRYPT side and sign_license.py/licgen.py's DECRYPT side (2026-07-15).

Real footgun found by Maxine's team: keygen.py encrypts the licence leaf
using YASHIGANI_KEY_PASSPHRASE, but sign_license.py / licgen.py's `issue`
command previously only read YASHIGANI_LICENCE_KEY_PASSPHRASE to decrypt it
— same secret, two different env-var names, so issuing a licence failed
with "Password was not given but private key is encrypted" unless the
caller happened to know to set BOTH vars to the same value.

Fixed: sign_license._resolve_passphrase() now checks YASHIGANI_KEY_PASSPHRASE
(PRIMARY, matches keygen.py's _resolve_leaf_passphrase()) first, falling
back to YASHIGANI_LICENCE_KEY_PASSPHRASE for back-compat. licgen.py's
_cmd_issue() now calls that shared resolver instead of duplicating its own
env lookup (the duplication is exactly how the two sites drifted apart).

This test round-trips: mint + encrypt a licence-leaf key the way
keygen.py's `leaf new` does, then decrypt + sign a licence via
sign_license.sign_licence_file() with ONLY YASHIGANI_KEY_PASSPHRASE set
(the OLD var name deliberately absent) — proving a single passphrase now
carries end-to-end.
"""
from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


def _import_script(name: str):
    """Import a scripts/*.py module by inserting scripts/ on sys.path,
    mirroring the pattern already used by
    test_license_integrity.py::TestSignLicenseV5Roundtrip."""
    scripts_dir = Path(__file__).parents[4] / "scripts"
    sys.path.insert(0, str(scripts_dir))
    try:
        import importlib
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pytest.skip(f"scripts/{name}.py not available in this checkout — internal tool is gitignored")
    finally:
        if str(scripts_dir) in sys.path:
            sys.path.remove(str(scripts_dir))


class TestPassphraseVarUnification:
    def test_keygen_primary_var_alone_decrypts_via_sign_license(self, monkeypatch, tmp_path):
        keygen = _import_script("keygen")
        sign_license = _import_script("sign_license")

        from cryptography.hazmat.primitives.asymmetric import ec

        from yashigani.licensing.chain import Alg, LeafCert, Role
        from yashigani.licensing.chain.algorithms import sign_message
        from yashigani.licensing.chain.canonical import leaf_cert_signing_digest

        # Mint + master-certify a licence leaf, exactly the shape keygen.py
        # produces (master signs the leaf_cert; the leaf's OWN private key
        # is encrypted with the LEAF passphrase — YASHIGANI_KEY_PASSPHRASE).
        master_key = ec.generate_private_key(ec.SECP384R1())
        licence_key = keygen._generate_p384_keypair()

        now = datetime.now(timezone.utc)
        leaf_cert = LeafCert(
            role=Role.LICENCE, client_id="roundtrip-corp",
            leaf_pubkey_pem=keygen._pubkey_pem(licence_key),
            not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
            serial="licence-roundtrip-0001", signed_at=now, alg=Alg.ECDSA_P384_SHA384,
        )
        leaf_cert_sig = sign_message(
            Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(leaf_cert.to_canonical_dict())
        )

        # Encrypt exactly as keygen.py's `leaf new` does — one passphrase,
        # the PRIMARY var.
        only_passphrase = b"round-trip-test-passphrase-2026-07-15"
        key_path = tmp_path / "licence_private.pem"
        keygen._write_private_key_encrypted(key_path, licence_key, only_passphrase)

        leaf_cert_path = tmp_path / "leaf_cert.json"
        leaf_cert_path.write_text(json.dumps(leaf_cert.to_canonical_dict()))

        # DECRYPT side: set ONLY the primary var — the OLD var name must be
        # absent, proving this is not accidentally passing via the alias.
        monkeypatch.setenv("YASHIGANI_KEY_PASSPHRASE", only_passphrase.decode("utf-8"))
        monkeypatch.delenv("YASHIGANI_LICENCE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("YASHIGANI_KEY_PASSPHRASE_FILE", raising=False)
        monkeypatch.delenv("YASHIGANI_LICENCE_KEY_PASSPHRASE_FILE", raising=False)

        resolved = sign_license._resolve_passphrase()
        assert resolved == only_passphrase

        payload = sign_license.build_payload_v5(
            tier="starter", org_domain="roundtrip.example.com", client_id="roundtrip-corp",
            licence_serial="lic-roundtrip-0001", expires_at="2099-01-01T00:00:00Z",
        )
        wire = sign_license.sign_licence_file(
            payload=payload,
            licence_key_pem_path=str(key_path),
            leaf_cert_json_path=str(leaf_cert_path),
            leaf_cert_sig_b64=base64.b64encode(leaf_cert_sig).decode(),
            licence_key_passphrase=resolved,
        )
        assert wire.count(".") == 3, "v5 licence must have exactly 3 dots (4 segments)"

    def test_old_var_still_works_as_fallback_alias(self, monkeypatch, tmp_path):
        """Back-compat: existing callers using the OLD var name alone must
        keep working — this is an additive fix, not a breaking rename."""
        keygen = _import_script("keygen")
        sign_license = _import_script("sign_license")

        passphrase = b"back-compat-alias-test-passphrase"
        licence_key = keygen._generate_p384_keypair()
        key_path = tmp_path / "licence_private.pem"
        keygen._write_private_key_encrypted(key_path, licence_key, passphrase)

        monkeypatch.delenv("YASHIGANI_KEY_PASSPHRASE", raising=False)
        monkeypatch.setenv("YASHIGANI_LICENCE_KEY_PASSPHRASE", passphrase.decode("utf-8"))
        monkeypatch.delenv("YASHIGANI_KEY_PASSPHRASE_FILE", raising=False)
        monkeypatch.delenv("YASHIGANI_LICENCE_KEY_PASSPHRASE_FILE", raising=False)

        resolved = sign_license._resolve_passphrase()
        assert resolved == passphrase

    def test_primary_var_takes_precedence_over_alias(self, monkeypatch):
        sign_license = _import_script("sign_license")

        monkeypatch.setenv("YASHIGANI_KEY_PASSPHRASE", "primary-value")
        monkeypatch.setenv("YASHIGANI_LICENCE_KEY_PASSPHRASE", "alias-value")

        resolved = sign_license._resolve_passphrase()
        assert resolved == b"primary-value"

    def test_licgen_cmd_issue_uses_shared_resolver_not_duplicated_lookup(self):
        """Guards against re-introducing the drift: licgen.py's _cmd_issue()
        must call sign_license._resolve_passphrase(), never read
        YASHIGANI_LICENCE_KEY_PASSPHRASE (or any passphrase env var) itself —
        duplicating the lookup is exactly how the two sites diverged onto
        different var names originally."""
        licgen_path = Path(__file__).parents[4] / "scripts" / "licgen.py"
        if not licgen_path.exists():
            pytest.skip("scripts/licgen.py not available in this checkout")
        source = licgen_path.read_text(encoding="utf-8")

        assert "sign_license._resolve_passphrase()" in source, (
            "_cmd_issue() must resolve the passphrase via sign_license's "
            "shared resolver, not its own os.environ.get(...) call"
        )
        assert 'os.environ.get("YASHIGANI_LICENCE_KEY_PASSPHRASE")' not in source
        assert 'os.environ.get("YASHIGANI_KEY_PASSPHRASE")' not in source


class TestDemoDefaultDirResolution:
    """LAURA-V2-DEMO-DIR (Ava's finding, 2026-07-15): licgen.py's
    DEMO_DEFAULT_DIR previously resolved one directory short
    (`YSG/testing_runs/...` instead of `Claude/testing_runs/...`)."""

    def test_demo_default_dir_resolves_under_claude_workspace_root(self):
        licgen = _import_script("licgen")

        resolved = licgen.DEMO_DEFAULT_DIR
        assert resolved.parts[-4:] == ("Claude", "testing_runs", "yashigani", "demo-license-system"), (
            f"DEMO_DEFAULT_DIR resolved to {resolved} — expected it to end in "
            "Claude/testing_runs/yashigani/demo-license-system"
        )
        # Must NOT resolve to the buggy one-level-short YSG/testing_runs/... path.
        assert "YSG/testing_runs" not in str(resolved)
