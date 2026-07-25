"""
Regression tests — F2/F3/F4 from FINDING-V412-DOCKER-CLEANROUND-BATCH.md
(Laura, docker clean-round, 2026-07-22).  All 3 are CONFIRMED code-level
bypasses that affect every runtime (docker/podman/k8s); F2 and F3 bypass the
codescan fixes already landed this release (db20ff30 SSRF, #1900 ReDoS).

  F2 (CRITICAL) — SSRF C1 bypass via octal/hex dotted IPv4 literals.
                  manifest/linter.py _is_private_address(),
                  manifest/codegen.py _assert_not_private().
  F3 (HIGH)     — ReDoS heuristic bypass via unparenthesized adjacent
                  wildcard-quantifier chains.
                  backoffice/routes/sensitivity.py _validate_regex_safety().
  F4 (CRITICAL) — PII/DLP REDACT defeated by zero-width Unicode + false
                  "redacted" audit claim.
                  pii/detector.py PiiDetector.

Each test pins the exploit vector as a red -> green case: it re-fails this
file if the fix is reverted.
"""
from __future__ import annotations

import multiprocessing as mp
import time

import pytest
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# F2 — SSRF C1 bypass via octal/hex/decimal IPv4 literal encodings
# ---------------------------------------------------------------------------

class TestF2SSRFOctalHexIPv4Bypass:
    """
    _is_private_address() previously handed non-standard IPv4 literal
    encodings to ipaddress.ip_address(), which raises ValueError on them —
    causing the OLD code to treat them as "genuine hostnames" and pass them
    straight through.  socket.getaddrinfo() DOES resolve them, so the guard
    was bypassable for every consumer (linter C1 + codegen._assert_not_private).
    """

    # --- direct _is_private_address unit tests: confirmed bypass vectors ---

    @pytest.mark.parametrize("host,desc", [
        ("0251.0376.0251.0376", "F2-A octal-dotted IMDS (169.254.169.254)"),
        ("0xA9.0xFE.0xA9.0xFE", "F2-B hex-dotted IMDS (169.254.169.254)"),
        ("2852039166", "F2-C 32-bit decimal-int IMDS (already covered pre-fix)"),
        ("0xA9FEA9FE", "F2-D whole-string hex IMDS (already covered pre-fix)"),
        ("012.034.056.078", "F2-E ambiguous leading-zero octet (resolvers disagree) -> fail closed"),
        ("0192.0168.0001.0001", "F2-F ambiguous leading-zero RFC1918-shaped -> fail closed"),
    ])
    def test_is_private_address_blocks_octal_hex_dotted_vectors(self, host: str, desc: str) -> None:
        from yashigani.manifest.linter import _is_private_address
        assert _is_private_address(host), (
            "_is_private_address(%r) returned False — F2 SSRF bypass NOT blocked (%s)" % (host, desc)
        )

    @pytest.mark.parametrize("host,desc", [
        ("8.8.8.8", "public dotted-decimal — must not regress"),
        ("1.1.1.1", "public dotted-decimal — must not regress"),
        ("api.openai.com", "genuine public hostname — must not regress"),
        ("my-model-server.example.com", "private-sounding but genuine hostname — must not regress"),
    ])
    def test_is_private_address_still_passes_legitimate_hosts(self, host: str, desc: str) -> None:
        from yashigani.manifest.linter import _is_private_address
        assert not _is_private_address(host), (
            "_is_private_address(%r) returned True — legitimate host incorrectly blocked (%s)" % (host, desc)
        )

    def test_fold_ipv4_numeric_literal_computes_correct_imds_address(self) -> None:
        """The octal/hex dotted forms fold to the EXACT concrete address a
        real resolver returns (ground-truthed live via socket.getaddrinfo
        during fix development — both encodings resolve to 169.254.169.254
        on Linux/BSD/macOS)."""
        import ipaddress
        from yashigani.manifest.linter import _fold_ipv4_numeric_literal

        imds = ipaddress.IPv4Address("169.254.169.254")
        assert _fold_ipv4_numeric_literal("0251.0376.0251.0376") == imds
        assert _fold_ipv4_numeric_literal("0xA9.0xFE.0xA9.0xFE") == imds

    # --- linter path (C1_model_egress_private_url / C1_private_egress_host) ---

    @pytest.mark.parametrize("url,desc", [
        ("http://0251.0376.0251.0376/v1", "F2-A octal-dotted IMDS base_url"),
        ("http://0xA9.0xFE.0xA9.0xFE/v1", "F2-B hex-dotted IMDS base_url"),
    ])
    def test_linter_blocks_octal_hex_bypass_urls(self, url: str, desc: str) -> None:
        from yashigani.manifest import validate_manifest
        import copy
        import os

        parsed = _base_manifest()
        parsed["spec"]["model_egress"]["base_url"] = url
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            result = validate_manifest(parsed)
        finally:
            os.environ.pop("YSG_REQUIRE_SIGNED_MANIFEST", None)
        rules = [e.rule for e in result.errors]
        assert "C1_model_egress_private_url" in rules, (
            "Linter did not reject %r (%s); errors: %s" % (url, desc, rules)
        )

    @pytest.mark.parametrize("host,desc", [
        ("0251.0376.0251.0376", "F2-A octal-dotted IMDS in egress_allow"),
        ("0xA9.0xFE.0xA9.0xFE", "F2-B hex-dotted IMDS in egress_allow"),
    ])
    def test_linter_blocks_octal_hex_bypass_egress_allow(self, host: str, desc: str) -> None:
        from yashigani.manifest import validate_manifest
        import os

        parsed = _base_manifest()
        parsed["spec"]["network"] = {"egress_allow": [{"host": host, "ports": [443]}]}
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            result = validate_manifest(parsed)
        finally:
            os.environ.pop("YSG_REQUIRE_SIGNED_MANIFEST", None)
        rules = [e.rule for e in result.errors]
        assert "C1_private_egress_host" in rules, (
            "Linter did not reject egress_allow host %r (%s); errors: %s" % (host, desc, rules)
        )

    # --- codegen path (_validate_upstreams -> C1_private_upstream) ---

    @pytest.mark.parametrize("url,desc", [
        ("http://0251.0376.0251.0376/v1", "F2-A octal-dotted IMDS base_url"),
        ("http://0xA9.0xFE.0xA9.0xFE/v1", "F2-B hex-dotted IMDS base_url"),
    ])
    def test_codegen_blocks_octal_hex_bypass_base_url(self, url: str, desc: str) -> None:
        from yashigani.manifest.codegen import CodegenEngine, CodegenError, reset_codegen_registry

        reset_codegen_registry()
        parsed = _base_manifest()
        parsed["spec"]["model_egress"]["base_url"] = url
        engine = CodegenEngine(parsed, "docker")
        with pytest.raises(CodegenError) as exc_info:
            engine.render(dry_run=True)
        assert exc_info.value.code == "C1_private_upstream", (
            "Codegen did not abort for %r (%s); code=%s" % (url, desc, exc_info.value.code)
        )

    @pytest.mark.parametrize("host,desc", [
        ("0251.0376.0251.0376", "F2-A octal-dotted IMDS in egress_allow"),
        ("0xA9.0xFE.0xA9.0xFE", "F2-B hex-dotted IMDS in egress_allow"),
    ])
    def test_codegen_blocks_octal_hex_bypass_egress_allow(self, host: str, desc: str) -> None:
        from yashigani.manifest.codegen import CodegenEngine, CodegenError, reset_codegen_registry

        reset_codegen_registry()
        parsed = _base_manifest()
        parsed["spec"]["network"] = {"egress_allow": [{"host": host, "ports": [443]}]}
        engine = CodegenEngine(parsed, "docker")
        with pytest.raises(CodegenError) as exc_info:
            engine.render(dry_run=True)
        assert exc_info.value.code == "C1_private_upstream", (
            "Codegen did not abort for egress host %r (%s); code=%s" % (host, desc, exc_info.value.code)
        )


def _base_manifest() -> dict:
    import copy

    digest = "a" * 64
    return copy.deepcopy({
        "apiVersion": "yashigani.io/v1alpha1",
        "kind": "AgentIntegration",
        "metadata": {"name": "hermes-agent", "tenant_id": "acme-corp"},
        "spec": {
            "image": {
                "repository": "ghcr.io/acme/hermes",
                "tag": "2.0.0",
                "digest": "sha256:" + digest,
            },
            "model_egress": {"provider": "openai", "base_url": "https://api.openai.com/v1"},
            "network": {"egress_allow": [{"host": "api.openai.com", "ports": [443]}]},
        },
    })


# ---------------------------------------------------------------------------
# F3 — ReDoS heuristic bypass via unparenthesized adjacent-wildcard chain
# ---------------------------------------------------------------------------

class TestF3ReDoSUnparenthesizedWildcardChain:
    """
    _validate_regex_safety() previously only caught PARENTHESIZED nested
    quantifiers (e.g. "(a+)+").  An unparenthesized chain of adjacent
    broad-wildcard quantifiers (".*.*.*.*.*.*x") passed unchanged and, if
    ever executed against attacker-controlled text, hangs the regex engine
    (Laura measured >120s on a 30-char adversarial string; independently
    reproduced here at n=100/120 chars taking ~24s/~74s on stdlib re —
    same vulnerability class, input-length-dependent blowup).
    """

    _EVIL_PATTERN = ".*.*.*.*.*.*x"

    def test_unparenthesized_wildcard_chain_rejected(self) -> None:
        from yashigani.backoffice.routes.sensitivity import _validate_regex_safety

        with pytest.raises(HTTPException) as exc_info:
            _validate_regex_safety(self._EVIL_PATTERN)
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["error"] == "redos_risk_adjacent_wildcard"

    def test_rejection_completes_well_under_one_second(self) -> None:
        """The validator itself must never execute the dangerous pattern
        against attacker text — it only compiles + heuristically inspects
        the pattern SOURCE, so rejection must be near-instant regardless
        of how catastrophic the pattern would be if actually matched."""
        from yashigani.backoffice.routes.sensitivity import _validate_regex_safety

        t0 = time.monotonic()
        with pytest.raises(HTTPException):
            _validate_regex_safety(self._EVIL_PATTERN)
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, (
            "F3: _validate_regex_safety took %.3fs to reject the evil pattern — "
            "expected near-instant rejection (no unsafe execution)." % elapsed
        )

    @pytest.mark.parametrize("pattern,desc", [
        (r"\b(?:\d[ -]*?){13,19}\b", "seeded credit-card pattern"),
        (r"\b(?:sk-|sk-ant-)[A-Za-z0-9_-]{20,}\b", "seeded API-key pattern"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "seeded SSN pattern"),
        (r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b", "seeded phone pattern"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "seeded email pattern"),
        (r"a.*b", "single wildcard quantifier — must not false-positive"),
    ])
    def test_normal_patterns_still_allowed(self, pattern: str, desc: str) -> None:
        from yashigani.backoffice.routes.sensitivity import _validate_regex_safety

        _validate_regex_safety(pattern)  # must not raise

    def test_existing_parenthesized_nested_quantifier_still_rejected(self) -> None:
        """Regression guard: the ORIGINAL (a+)+ heuristic must still fire —
        the new adjacent-wildcard check is additive, not a replacement."""
        from yashigani.backoffice.routes.sensitivity import _validate_regex_safety

        with pytest.raises(HTTPException) as exc_info:
            _validate_regex_safety("(a+)+")
        assert exc_info.value.detail["error"] == "redos_risk"

    def test_unparenthesized_wildcard_chain_would_genuinely_hang_if_unblocked(self) -> None:
        """
        Proves the danger is real (not a theoretical heuristic-only concern):
        bypassing the fixed validator and executing the raw evil pattern
        against a modest adversarial string blows well past a bounded
        timeout.  Run in a subprocess with a hard join-timeout + terminate
        so this test itself never actually hangs CI.
        """
        proc = mp.Process(target=_redos_worker, args=(self._EVIL_PATTERN, "a" * 100))
        t0 = time.monotonic()
        proc.start()
        proc.join(timeout=5.0)
        elapsed = time.monotonic() - t0
        still_running = proc.is_alive()
        if still_running:
            proc.terminate()
            proc.join()
        assert still_running, (
            "Expected the raw (unvalidated) evil pattern to still be running "
            "after a 5s bound on a 100-char adversarial string (elapsed=%.2fs) — "
            "if it completed quickly, the danger this fix closes may no longer "
            "be reproducible on this interpreter; re-verify F3 is still real "
            "before assuming this control is unnecessary." % elapsed
        )


def _redos_worker(pattern: str, text: str) -> None:
    import re

    re.compile(pattern).search(text)


# ---------------------------------------------------------------------------
# F4 — PII/DLP REDACT defeated by zero-width Unicode + false audit claim
# ---------------------------------------------------------------------------

class TestF4ZeroWidthPiiEvasionAndAuditTruthfulness:
    """
    Inserting a zero-width Unicode format character (category Cf) inside an
    SSN/credit-card token previously made every pattern in patterns.py find
    ZERO matches (plain \\d-based regexes require contiguous digits), so the
    value passed through completely UNREDACTED — yet action_taken still
    reported "redacted" (false compliance).  Both bugs are closed:
      1. PiiDetector normalizes (strip Cf + per-char NFKC) before matching.
      2. action_taken only claims "redacted"/"pseudonymized" when a finding
         was ACTUALLY spliced out of the payload.
    """

    ZWSP = "​"    # ZERO WIDTH SPACE
    ZWNJ = "‌"    # ZERO WIDTH NON-JOINER
    ZWJ = "‍"     # ZERO WIDTH JOINER
    BOM = "﻿"     # ZERO WIDTH NO-BREAK SPACE / BOM

    def _detector(self):
        from yashigani.pii.detector import PiiDetector, PiiMode
        return PiiDetector(mode=PiiMode.REDACT)

    @pytest.mark.parametrize("zw_char,desc", [
        ("​", "U+200B ZERO WIDTH SPACE"),
        ("‌", "U+200C ZERO WIDTH NON-JOINER"),
        ("‍", "U+200D ZERO WIDTH JOINER"),
        ("﻿", "U+FEFF ZERO WIDTH NO-BREAK SPACE / BOM"),
    ])
    def test_zero_width_char_inside_ssn_is_detected_and_redacted(self, zw_char: str, desc: str) -> None:
        text = "123" + zw_char + "-45-6789"
        detector = self._detector()
        redacted, result = detector.process(text)

        assert result.detected is True, "F4: zero-width evasion (%s) NOT detected" % desc
        assert "[REDACTED:SSN]" in redacted, "F4: SSN not actually redacted (%s)" % desc
        assert "45-6789" not in redacted, "F4: raw SSN digits leaked into output (%s)" % desc
        assert result.action_taken == "redacted"

    def test_zero_width_char_inside_credit_card_is_detected_and_redacted(self) -> None:
        # 4111111111111111 is a Luhn-valid Visa test number.
        text = "4111" + self.ZWSP + " 1111 1111 1111"
        detector = self._detector()
        redacted, result = detector.process(text)

        assert result.detected is True, "F4: zero-width evasion in credit card NOT detected"
        assert "[REDACTED:CREDIT_CARD]" in redacted
        assert "1111 1111" not in redacted
        assert result.action_taken == "redacted"

    def test_multiple_zero_width_chars_interspersed_still_detected(self) -> None:
        """Defence-in-depth: several zero-width chars scattered through the
        same token (not just one split point) must still be fully stripped
        and detected."""
        text = "1" + self.ZWSP + "2" + self.ZWNJ + "3-4" + self.ZWJ + "5-6789"
        detector = self._detector()
        redacted, result = detector.process(text)
        assert result.detected is True
        assert "[REDACTED:SSN]" in redacted

    def test_clean_payload_reports_zero_matches_and_truthful_audit(self) -> None:
        """F4 audit-truthfulness: a genuinely clean payload must report
        detected=False AND action_taken must NOT falsely claim "redacted"."""
        text = "Just a normal message with no sensitive data at all."
        detector = self._detector()
        redacted, result = detector.process(text)

        assert result.detected is False
        assert len(result.findings) == 0
        assert redacted == text
        assert result.action_taken != "redacted", (
            "F4: action_taken falsely claims 'redacted' on a payload with zero findings "
            "(action_taken=%r) — false compliance." % result.action_taken
        )
        assert result.action_taken == "logged"

    def test_pseudonymize_mode_same_truthfulness_guarantee(self) -> None:
        from yashigani.pii.detector import PiiDetector, PiiMode

        detector = PiiDetector(mode=PiiMode.PSEUDONYMIZE)
        clean_text = "Nothing sensitive here."
        pseudo, result = detector.process(clean_text)
        assert result.detected is False
        assert pseudo == clean_text
        assert result.action_taken == "logged"

        detector2 = PiiDetector(mode=PiiMode.PSEUDONYMIZE)
        dirty_text = "SSN 123" + self.ZWSP + "-45-6789"
        pseudo2, result2 = detector2.process(dirty_text)
        assert result2.detected is True
        assert "[PSEUDONYMIZED:SSN]" in pseudo2
        assert result2.action_taken == "pseudonymized"

    def test_redaction_span_maps_back_to_original_text_not_normalized_copy(self) -> None:
        """The finding span must cover the FULL original span (including the
        embedded zero-width char) so _apply_redactions splices the correct
        region out of the real payload, not a normalized copy with different
        offsets."""
        text = "prefix 123" + self.ZWSP + "-45-6789 suffix"
        detector = self._detector()
        redacted, result = detector.process(text)

        assert redacted == "prefix [REDACTED:SSN] suffix"
        assert len(result.findings) == 1
        f = result.findings[0]
        # The original span must include the embedded zero-width char.
        assert text[f.start:f.end] == "123" + self.ZWSP + "-45-6789"
