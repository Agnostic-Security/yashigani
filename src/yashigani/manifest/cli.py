"""
Yashigani Manifest CLI — ``yashigani validate``.

Usage:
    yashigani validate <manifest.yaml> [--verify-digests] [--fips-pubkey <pem-path>]
    python -m yashigani.manifest.cli validate <manifest.yaml> [--verify-digests]

Error messages are human-quality (K3 — Nora launch gate):
  Every error includes what failed, why it matters, and how to fix it.

F3 (Laura MED): ``--fips-pubkey <pem-path>`` threads the RSA-3072 public key
into verify_manifest_signature() so that FIPS-signed manifests can be
validated via the CLI.  Without this flag, rsa-pss-3072-sha384 manifests
always failed with "fips_public_key_pem required".

Last updated: 2026-05-28T00:00:00+00:00
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yashigani validate",
        description=(
            "Validate a Yashigani ring-fence onboarding manifest (yashigani.io/v1alpha1).\n\n"
            "Checks: safe-parse (M1), tenant_id regex (M2), shell-injection guard (M3), "
            "inbound_ports allowlist (M5), image-digest pins (M6), signature gate (M7), "
            "JSON-Schema (M8), SPIFFE prefix (N1), egress_allow private-IP guard (C1)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "manifest",
        type=Path,
        help="Path to the agent manifest YAML file to validate.",
    )
    parser.add_argument(
        "--verify-digests",
        action="store_true",
        default=False,
        help=(
            "Perform live registry digest inspection (M6 live path). "
            "Requires docker/skopeo and network access. "
            "Skip for air-gap deployments."
        ),
    )
    parser.add_argument(
        "--fips-pubkey",
        metavar="PEM_PATH",
        default=None,
        help=(
            "Path to a PEM-encoded RSA-3072 public key used to verify "
            "rsa-pss-3072-sha384 (FIPS) signatures.  Required when the "
            "manifest spec.signature.algorithm is rsa-pss-3072-sha384. "
            "Without this flag, FIPS-signed manifests cannot be verified."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit validation results as JSON (for CI integration).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point for ``yashigani validate``.

    Returns:
        0 on success, 1 on validation failure, 2 on internal error.
    """
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    manifest_path: Path = args.manifest

    # 1. Parse
    from yashigani.manifest.parser import parse_manifest, ManifestParseError  # noqa: PLC0415
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        _emit_error("Cannot read manifest file: %s\n  Fix: ensure the file exists and is readable." % exc, args.json)
        return 2

    try:
        parsed = parse_manifest(manifest_bytes)
    except ManifestParseError as exc:
        _emit_error(
            "Manifest parse error [%s]: %s\n  Fix: %s" % (
                exc.rule,
                exc.detail,
                _parse_fix_hint(exc.rule),
            ),
            args.json,
        )
        return 1

    # 2. Lint
    from yashigani.manifest.linter import validate_manifest, LintResult  # noqa: PLC0415
    result: LintResult = validate_manifest(
        parsed,
        manifest_bytes=manifest_bytes,
        verify_digests=args.verify_digests,
    )

    # 3. Signature verification (crypto — after structural lint)
    # F3: load FIPS public key if --fips-pubkey was supplied.
    fips_public_key_pem: bytes | None = None
    if args.fips_pubkey is not None:
        fips_pubkey_path = Path(args.fips_pubkey)
        try:
            fips_public_key_pem = fips_pubkey_path.read_bytes()
        except OSError as exc:
            _emit_error(
                "Cannot read FIPS public key file: %s\n"
                "  Fix: ensure %s exists and is a PEM-encoded RSA-3072 public key."
                % (exc, args.fips_pubkey),
                args.json,
            )
            return 2

    from yashigani.manifest.signatures import verify_manifest_signature, ManifestSignatureError  # noqa: PLC0415
    try:
        verify_manifest_signature(manifest_bytes, parsed, fips_public_key_pem=fips_public_key_pem)
    except ManifestSignatureError as exc:
        from yashigani.manifest.linter import LintError  # noqa: PLC0415
        result.errors.append(LintError(
            "M7_crypto_failure",
            "Signature cryptographic verification failed: %s" % exc.detail,
            field="spec.signature",
            fix=(
                "Re-sign the manifest with the correct key, or set "
                "YSG_REQUIRE_SIGNED_MANIFEST=warn to demote to a warning in development."
            ),
        ))
        result.passed = False

    # 4. Emit results
    if args.json:
        import json  # noqa: PLC0415
        output = {
            "passed": result.passed,
            "errors": [
                {"rule": e.rule, "field": e.field, "message": e.message, "fix": e.fix}
                for e in result.errors
            ],
            "warnings": [
                {"rule": w.rule, "field": w.field, "message": w.message, "fix": w.fix}
                for w in result.warnings
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print(result.format_report())

    return 0 if result.passed else 1


def _emit_error(message: str, as_json: bool) -> None:
    if as_json:
        import json  # noqa: PLC0415
        print(json.dumps({"passed": False, "error": message, "errors": [], "warnings": []}))
    else:
        print("ERROR: %s" % message, file=sys.stderr)


def _parse_fix_hint(rule: str) -> str:
    """Return a human-quality fix hint for a parse rule code (K3)."""
    hints = {
        "M1_size_cap": "Reduce the manifest file size to under 512 KB.",
        "M1_yaml_syntax": "Fix the YAML syntax error — check for incorrect indentation, missing colons, or unclosed quotes.",
        "M1_not_mapping": "The manifest root must be a YAML mapping (key: value).  Check the file starts with apiVersion:.",
        "M1_anchor_alias_cap": "The manifest uses too many YAML anchors (&) and aliases (*).  Flatten the structure.",
        "M1_nesting_depth": "The manifest is too deeply nested.  Flatten the YAML structure.",
        "M1_sandbox_timeout": "The manifest parser timed out — likely a complex anchor/alias bomb.  Simplify the YAML.",
        "M1_sandbox_crash": "The manifest parser crashed unexpectedly.  Check for malformed YAML or oversized content.",
        "M1_encoding": "The manifest file must be UTF-8 encoded.  Re-save the file as UTF-8.",
        "M2_tenant_id_regex": "tenant_id must match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$.  Use lowercase letters, digits, and hyphens; at least 3 chars.",
        "M2_kms_prefix": "All spec.secrets[].kms_path values must start with /tenant/<your-tenant-id>/.  Check the kms_path values.",
        "M3_nul_byte": "Remove any NUL bytes (\\x00) from the manifest file.",
        "M3_multiline_shell_field": "The flagged field must be a single line (no newlines).  Shell codegen requires single-line values.",
        "M3_injection_pattern": "The flagged field value contains a pattern that looks like a shell injection (e.g. ; $(cmd)).  Correct the value.",
        "M1_not_file": "The manifest path does not exist or is not a regular file.",
    }
    return hints.get(rule, "Review the manifest against the yashigani.io/v1alpha1 schema.")


if __name__ == "__main__":
    sys.exit(main())
