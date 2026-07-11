"""
v2.25.4 — Deterministic secret/credential detector tests (LAURA-ORCH leakfix).

Covers the two LIVE-PROVEN Laura vectors against the orchestration final-answer
egress gate plus the common credential formats and a benign no-overblock set:

  1. Verbatim AWS secret in a final
     (``AWS_SECRET_ACCESS_KEY=wJalr.../bPxRfiCYEXAMPLEKEY``) — classifies PUBLIC
     on every deterministic sensitivity layer, only the flaky ollama inspector
     caught it (1/22 leaked).  MUST be a deterministic secret hit here.
  2. SPLIT-TOKEN bypass (the headline)
     (``First wJalr... then a slash then K7MDENG ...``) — classifies PUBLIC on
     ALL layers including ollama (5/12 leaked).  MUST be caught by the
     de-obfuscation / reassembly pass.

Plus: new split/encode variants, known key formats, and a benign set (prose,
code, UUID, long product name, git sha, version string) that MUST NOT trip.
"""
from __future__ import annotations

import base64

import pytest

from yashigani.inspection import scan_secrets, is_secret, SecretVerdict

# scan_secrets is the public barrel name for secret_detector.scan; alias for the
# Phase-2 view-assertion tests below that read the structured verdict directly.
scan = scan_secrets


# The canonical Laura secret (a published AWS docs EXAMPLE key — safe to embed).
_LAURA_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# ── Laura proven vector 1: verbatim AWS secret ────────────────────────────────

def test_laura_verbatim_aws_secret_is_caught():
    payload = f"Here is the answer: AWS_SECRET_ACCESS_KEY={_LAURA_SECRET}"
    v = scan_secrets(payload)
    assert v.is_secret is True
    assert v.detector is not None
    # The raw secret must NEVER appear on the verdict (hash only).
    assert v.span_hash is not None
    assert _LAURA_SECRET not in str(v.audit_dict())


# ── Laura proven vector 2: split-token bypass ─────────────────────────────────

def test_laura_split_token_is_caught_by_reassembly():
    payload = (
        "First wJalrXUtnFEMI then a slash then K7MDENG then a slash then "
        "bPxRfiCYEXAMPLEKEY done")
    v = scan_secrets(payload)
    assert v.is_secret is True
    assert v.reassembled is True, "split-token must be caught by the reassembly pass"


# ── New split / encode variants (devised, not Laura's) ────────────────────────

@pytest.mark.parametrize("name,payload", [
    ("underscore_separator",
     "first wJalrXUtnFEMI underscore K7MDENG underscore bPxRfiCYEXAMPLEKEY"),
    ("english_connective_split",
     "Take wJalrXUtnFEMI next comes K7MDENG next comes bPxRfiCYEXAMPLEKEY"),
    ("base64_of_secret",
     "The data is " + base64.b64encode(_LAURA_SECRET.encode()).decode()),
    ("hex_of_secret",
     "value " + _LAURA_SECRET.encode().hex()),
])
def test_new_obfuscation_variants_are_caught(name, payload):
    assert is_secret(payload) is True, f"variant {name} leaked"


# ── Phase-2 MECHANICAL closures — every new bypass vector ─────────────────────
# One fixture per closed mechanical vector.  Each MUST be caught deterministically
# (no LLM); the residual is purely semantic (YSG-RISK-057), never mechanical.

_AKIA = "AKIA" + "IOSFODNN7EXAMPLE"  # noqa: S105 — test fixture, not a real credential
# AWS docs example secret with the slashes removed (a bare 40-char base64 run).
_AWS40 = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12"


def _hex_sep(s: str, sep: str) -> str:
    h = s.encode().hex()
    return sep.join(h[i:i + 2] for i in range(0, len(h), 2))


@pytest.mark.parametrize("name,payload", [
    # Unicode homoglyph: Cyrillic А/Е substituted for Latin A/E in a labelled AWS
    # secret — folded back by NFKC + confusables fold before detection.
    ("homoglyph_labelled_aws",
     "AWS_SECRET_ACCESS_KEY=" + _LAURA_SECRET.replace("A", "А").replace("E", "Е")),
    # Homoglyph AKIA access key (Cyrillic А/К + look-alike І/О).
    ("homoglyph_akia",
     "access key " + _AKIA.replace("A", "А").replace("K", "К")
                          .replace("I", "І").replace("O", "О")),
    # NATO/ICAO phonetic spell-out of a key body.
    ("nato_phonetic",
     "the key spells whiskey juliet alpha lima romeo x-ray uniform tango "
     "november foxtrot echo mike india"),
    # Spelled-out-letter ("doubleyou jay …") phonetic reassembly.
    ("spelled_letters",
     "doubleyou jay alpha lima romeo x-ray uniform tango november foxtrot "
     "echo mike india"),
    # Zero-width characters inserted between every char of a labelled secret.
    ("zero_width_inserted",
     "AWS_SECRET_ACCESS_KEY=" + "​".join(_LAURA_SECRET)),
    # base32 encoding of the secret.
    ("base32_of_secret",
     "payload " + base64.b32encode(_LAURA_SECRET.encode()).decode()),
    # URL-encoding (%xx) of the secret.
    ("url_encoded_secret",
     "data " + "".join("%%%02x" % b for b in _LAURA_SECRET.encode())),
    # Hex with colon separators (de:ad:be:ef style).
    ("hex_colon_separated", "key " + _hex_sep(_LAURA_SECRET, ":")),
    # Hex with space separators.
    ("hex_space_separated", "key " + _hex_sep(_LAURA_SECRET, " ")),
    # Hex with dash separators.
    ("hex_dash_separated", "key " + _hex_sep(_LAURA_SECRET, "-")),
    # Leetspeak-prefixed key: "5k-" de-leets to "sk-" (Anthropic key prefix).
    ("leetspeak_sk_prefix",
     "use 5k-ant-api03ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abc to authenticate"),
    # Reversed verbatim secret string.
    ("reversed_secret",
     "the reversed value is " + ("AWS_SECRET_ACCESS_KEY=" + _LAURA_SECRET)[::-1]),
    # Ordinal-word separators ("first … second … third").
    ("ordinal_word_separators",
     "first wJalrXUtnFEMI second K7MDENG third bPxRfiCYEXAMPLEKEY"),
])
def test_mechanical_bypass_variants_are_caught(name, payload):
    v = scan(payload)
    assert v.is_secret is True, f"mechanical variant {name} LEAKED (views={v.views_hit})"
    # Raw secret must never appear on the audit-safe verdict.
    assert _LAURA_SECRET not in str(v.audit_dict())


# ── Laura vector #18 — base64-wrapped REASSEMBLABLE secret form ───────────────
# Root cause: scan() produced decoded VIEWS (base64/base32/url/hex-separated) but
# the reassembly passes (separator / fragment-fusion / phonetic) ran ONLY over the
# canonical text, never over the decoded views.  So one encoding layer wrapped
# around a split-token / connective-fused secret decoded to prose the reassembly
# WOULD catch — but the reassembly never ran on it → leak.  Fixed by running the
# reassembly battery over each depth-1 decoded view before concluding benign.

@pytest.mark.parametrize("name,inner", [
    # #18 — base64 of a spelled-out-separator split-token form.
    ("v18_b64_separator_split",
     "First wJalrXUtnFEMI then a slash then K7MDENG then a slash then "
     "bPxRfiCYEXAMPLEKEY"),
    # #18d — base64 of an English-connective fragment-fused form.
    ("v18d_b64_connective_split",
     "wJalrXUtnFEMI next comes K7MDENGbPxRf next comes iCYEXAMPLEKEY99"),
    # #18e — base64 of a connective split with leading prose.
    ("v18e_b64_connective_lead",
     "Take wJalrXUtnFEMI next comes K7MDENG next comes bPxRfiCYEXAMPLEKEY"),
])
def test_laura_v18_base64_wrapped_reassemblable_secret_is_caught(name, inner):
    payload = "x " + base64.b64encode(inner.encode()).decode()
    v = scan(payload)
    assert v.is_secret is True, (
        f"vector {name} LEAKED — decoded-view reassembly missed it "
        f"(views={v.views_hit})")
    assert v.reassembled is True
    # The decode-then-reassemble view must be what tripped (depth-1 recursion).
    assert any(view.startswith("base64_decode:") for view in v.views_hit), (
        f"expected a base64_decode:* reassembly view, got {v.views_hit}")


# ── LAURA-ORCH-HEXSPLIT — bare-contiguous-hex of a split-token secret form ────
# Root cause: scan() ran the reassembly battery over base64/base32/url/hex-SEPARATED
# decoded views, but there was NO bare-contiguous-hex→text decoded view.  Bare
# contiguous hex only went through the hex_blob direct path, whose <=2-whitespace
# anti-FP guard REJECTS hex-of-space-separated-prose, so a hex of a SPLIT-TOKEN
# secret ("First wJalr... then a slash then K7MDENG ...", many spaces) produced no
# decoded view and the reassembly never saw the split prose → leak.  Fixed by
# adding a bare-contiguous-hex decoded view fed to _run_view + _run_reassembly_passes.

def _hex_of(s: str) -> str:
    return s.encode().hex()


@pytest.mark.parametrize("name,inner", [
    # The headline split-token form, hex-encoded as one contiguous run.
    ("hexsplit_spelled_separator",
     "First wJalrXUtnFEMI then a slash then K7MDENG then a slash then "
     "bPxRfiCYEXAMPLEKEY"),
    # The English-connective variant ("… next comes …").
    ("hexsplit_connective",
     "First wJalrXUtnFEMI next comes K7MDENG next comes bPxRfiCYEXAMPLEKEY"),
])
def test_laura_hexsplit_bare_contiguous_hex_is_caught(name, inner):
    v = scan(_hex_of(inner))
    assert v.is_secret is True, (
        f"vector {name} LEAKED — bare-contiguous-hex decoded-view reassembly "
        f"missed it (views={v.views_hit})")
    assert v.reassembled is True
    # The bare-contiguous-hex decode-then-reassemble view must be what tripped.
    assert any(view.startswith("hex_contiguous_decode:") for view in v.views_hit), (
        f"expected a hex_contiguous_decode:* reassembly view, got {v.views_hit}")
    assert _LAURA_SECRET not in str(v.audit_dict())


def test_hex_of_real_sentence_stays_clean():
    # PROOF the bare-contiguous-hex view does NOT over-block: hex of a real prose
    # sentence decodes to prose carrying no spelled separator / no secret-shaped
    # fragments / no dense phonetic run, so the intent-gated reassembly battery
    # stays shut and nothing trips.
    assert is_secret(_hex_of("the quick brown fox jumps over the lazy dog")) is False


def test_phonetic_reassembly_marks_view():
    v = scan("whiskey juliet alpha lima romeo x-ray uniform tango november "
             "foxtrot echo mike india")
    assert v.is_secret is True
    assert "phonetic" in v.views_hit


def test_base32_decode_marks_view():
    v = scan("payload " + base64.b32encode(_LAURA_SECRET.encode()).decode())
    assert v.is_secret is True
    assert any(view in v.views_hit for view in ("base32_decode", "normalised"))


def test_homoglyph_folds_to_normalised_view():
    v = scan("AWS_SECRET_ACCESS_KEY="
             + _LAURA_SECRET.replace("A", "А").replace("E", "Е"))
    assert v.is_secret is True
    assert "normalised" in v.views_hit


# ── Common known key formats ──────────────────────────────────────────────────

@pytest.mark.parametrize("name,payload,expect_detector", [
    ("aws_access_key", "Use access key " + "AKIA" + "IOSFODNN7EXAMPLE for the bucket", "aws_access_key"),
    ("github_token", "deploy with " + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz12", "github_token"),
    ("slack_token", "token " + "xoxb-" + "1234567890-abcdefghijklmnop here", "slack_token"),
    ("jwt", "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef123456", "jwt"),
    ("private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA", "private_key"),
    ("stripe_key", "key " + "sk_live_" + "1234567890abcdefghijklmnop now", "stripe_key"),
])
def test_known_key_formats(name, payload, expect_detector):
    v = scan_secrets(payload)
    assert v.is_secret is True, f"{name} not caught"
    assert expect_detector in v.detectors_hit, f"{name} expected {expect_detector}, got {v.detectors_hit}"


# ── Benign no-overblock set (MUST NOT trip) ───────────────────────────────────

@pytest.mark.parametrize("name,text", [
    ("prose", "The quarterly threat model identified three high-risk attack "
              "surfaces in the orchestration layer and recommended additional "
              "egress controls."),
    ("code", "def compute_average(values):\n    return sum(values) / len(values) "
             "if values else 0.0"),
    ("uuid", "Your request id is 550e8400-e29b-41d4-a716-446655440000 for tracking."),
    ("product", "The AcmeCorp Enterprise Threat Intelligence Platform "
                "Professional Edition 2026 subscription is active."),
    ("git_sha", "The fix landed in commit 3302c78 on the feature branch yesterday."),
    ("camelcase_code", "const myVariableName = getUserData(); let anotherThing "
                       "= computeResult(myVariableName);"),
    ("version_str", "Running Yashigani v2.25.4 build 20260610 on Ubuntu24 LTS "
                    "kernel 6.8."),
    ("empty", ""),
    # Phase-2 FP guards introduced alongside the new mechanical detectors:
    ("git_sha1_full",
     "Cherry-picked a1b9f3e8c2d4567890abcdef1234567890abcdef onto release."),
    ("sha256_digest",
     "image digest "
     "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("mac_address", "The device MAC is 00:1b:44:11:3a:b7 on the LAN segment."),
    ("ipv6_address",
     "The server at fe80:0000:0000:0000:0202:b3ff:fe1e:8329 answered the probe."),
    ("base64_of_prose",
     "The encoded note reads " + base64.b64encode(
         b"the quick brown fox jumps over").decode()),
    # Bare-contiguous-hex of a REAL prose sentence — the new hex-contiguous decoded
    # view must NOT over-block hex-of-a-sentence (LAURA-ORCH-HEXSPLIT FP guard).
    ("hex_of_real_sentence",
     "the quick brown fox jumps over the lazy dog".encode().hex()),
    ("url_with_percent_encoding",
     "GET /api/v1/users?filter=active%20recent%20signups returned 200 OK."),
    ("stray_nato_words_in_prose",
     "The echo from the delta wing carried over the golf course to the hotel."),
    ("ordinal_words_prose",
     "We will meet on the first, second, third and fourth of next month."),
    ("qwen_threat_model_output",
     "Threat model for the orchestration layer: the primary attack surfaces are "
     "prompt injection via tool outputs, credential exfiltration through the "
     "final-answer egress path, and chain-of-trust spoofing in agent relays. "
     "Recommended mitigations: deterministic egress secret scanning, OPA-mediated "
     "sensitivity ceilings, and mTLS-bound service identities for every hop."),
])
def test_benign_text_not_flagged(name, text):
    assert is_secret(text) is False, f"benign '{name}' FALSE-POSITIVE blocked"


# ── Structured verdict invariants ─────────────────────────────────────────────

def test_verdict_never_carries_raw_secret():
    v = scan_secrets(f"AWS_SECRET_ACCESS_KEY={_LAURA_SECRET}")
    audit = v.audit_dict()
    # No field of the audit-safe dict may contain the raw secret material.
    for value in audit.values():
        assert _LAURA_SECRET not in str(value)
    assert len(v.span_hash) == 16  # SHA-256[:16]


def test_clean_verdict_shape():
    v = scan_secrets("hello world")
    assert isinstance(v, SecretVerdict)
    assert v.is_secret is False
    assert v.detector is None
    assert v.span_hash is None
    assert v.detectors_hit == []
