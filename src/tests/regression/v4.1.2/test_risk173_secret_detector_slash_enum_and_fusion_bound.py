"""
Regression tests — YSG-RISK-173 (chat-path repair, 2026-07-30).

Root cause (two compounding false-positive classes in
``yashigani.inspection.secret_detector``, both hit by OpenClaw's REAL outbound
self-call body — an OpenAI-compatible chat-completion request whose ``system``
message is OpenClaw's own multi-KB system prompt / tool-schema description):

1. ``_scan_aws_secret`` / the generic entropy floor (``_scan_entropy``) treat
   any 40-char (or 20+-char) run drawn from ``[A-Za-z0-9/+]`` as an AWS-secret
   candidate once its Shannon entropy crosses the 4.0 bits/char threshold.
   ``/`` is a required member of that alphabet (real AWS secrets legitimately
   contain it), but a ``/``-joined ENUMERATION of ordinary words — a tool
   description listing accepted actions
   (``"status/describe/pairing/notify/camera/photos/screen"``) or a
   filesystem path made of pronounceable segments plus short numeric IDs
   (``"/app/dist/extensions/browser/skills/browser-automation/SKILL"``,
   ``"/__openclaw__/canvas/documents/cv_123/index"``, or a config assignment
   like ``"model=yashigani/qwen2"``) — satisfies the same shape purely by
   coincidence.  Live-confirmed: ``docker logs gateway`` showed
   ``egress-eval: DENY caller=spiffe://.../openclaw prefix=llm
   reason=pii_detected_in_result sensitivity=RESTRICTED pii=True`` for
   OpenClaw's own trivial-greeting self-call, and direct offline replay of the
   EXACT captured request body against ``scan()`` reproduced
   ``detector='aws_secret' span='status/describe/pairing/notify/camera/ph'
   entropy=4.006`` (the "ph" fragment is itself an artefact of
   ``_AWS_SECRET_RE``'s fixed 40-char window landing mid-word inside
   "...camera/photos/...").

2. ``_normalise_for_reassembly`` (the spelled-out-separator reassembly pass,
   "Pass B") fused the ENTIRE input text into one contiguous whitespace-free
   run the instant ANY ``_SEPARATOR_PHRASES`` word ("slash", "dash", "colon",
   ...) appeared ANYWHERE in it — correct for the short fixture payloads this
   pass was designed against (see
   ``test_v2254_secret_detector.py::test_laura_split_token_is_caught_by_reassembly``),
   but a single incidental appearance of the common English word "slash" in a
   large real-world document (OpenClaw's ~78KB system prompt legitimately says
   "use tool directly instead of asking user to run equivalent cli or/commands"
   type instructions, and separately mentions forward slashes in reply-tag
   syntax) turned the WHOLE document into one fused blob, and some window
   across a large fused blob then coincidentally satisfies the entropy floor.

Fix (defence-in-depth, three independent guards, none weakening real secret
detection — every known credential format (AWS, GitHub, Slack, ``sk-``, JWT,
generic ``labelled_secret``) still fires, confirmed below):

  a. ``_looks_like_word()`` now also strips ``/`` (alongside ``_``/``-``) from
     the "core" before the alpha+vowel check — a slash-joined/fused run of
     real words is judged by its full alphabetic content. Every known secret
     format always carries a digit, so ``core.isalpha()`` already excludes
     genuine secrets regardless of this stripping.
  b. ``_looks_like_slash_enumeration()`` / ``_segment_is_benign()`` — a
     dedicated per-segment check (also splits on ``=`` for config-assignment
     shapes) used by ``_scan_aws_secret`` (via ``_expand_to_full_run`` so a
     fixed-40-char truncation mid-word cannot defeat the per-segment vowel
     check) and by ``_scan_entropy``.
  c. ``_normalise_for_reassembly_windows()`` bounds Pass B's fuse-then-scan to
     a local +/-200-char window around EACH separator-phrase occurrence,
     instead of fusing the entire document — the original split-token defeat
     (fragments sit immediately adjacent to the literal separator phrase)
     is unaffected.

Regression assertions:
  - A trivial greeting body passes clean (both a bare "hi" and OpenClaw's
    exact real captured outbound request body).
  - Every known real-secret-shaped payload (AWS key+secret, sk- token, GitHub
    token, Slack token, JWT, PEM header, card-adjacent + SSN-adjacent digit
    runs are NOT secret detector's job -- covered by PII classifier, not
    asserted here) STILL blocks.
  - The Laura split-token adversarial fixture (genuine spelled-out-separator
    secret) STILL blocks, proving Pass B's windowing did not defeat the
    original defeat it exists for.
  - A secret deliberately hidden behind slashes/equals STILL blocks, proving
    the enumeration guard cannot be used to smuggle a real credential.
"""
from __future__ import annotations

from yashigani.inspection.secret_detector import scan

# The exact 41-char tool-schema description fragment that live-tripped
# `aws_secret` (entropy 4.006) via OpenClaw's `nodes` tool description.
_TOOL_SCHEMA_ENUM_FRAGMENT = (
    '{"type":"function","function":{"name":"nodes","description":'
    '"Discover and control paired nodes '
    '(status/describe/pairing/notify/camera/photos/screen/location/'
    'notifications/invoke). For file retrieval, use the dedicated '
    'file_fetch tool.","parameters":{"type":"object"}}}'
)

# The exact skill-path string that live-tripped the generic entropy floor
# (entropy 4.2) once the aws_secret false positive above was fixed.
_SKILL_PATH_FRAGMENT = (
    "Skill available at /app/dist/extensions/browser/skills/"
    "browser-automation/SKILL for browser automation tasks."
)

# The document-path-with-numeric-ID string that live-tripped the entropy
# floor (entropy 4.107) once the two false positives above were fixed.
_CANVAS_PATH_FRAGMENT = (
    "Canvas document reference: /__openclaw__/canvas/documents/cv_123/index"
)

# The config-assignment string that live-tripped the entropy floor
# (entropy 4.011 / 4.254) once the three false positives above were fixed.
_MODEL_ASSIGNMENT_FRAGMENT = (
    "Runtime: default_model=yashigani/qwen2 model=yashigani/qwen2 seed=1"
)

_LAURA_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


class TestRisk173TrivialGreetingPasses:
    """The core regression: a trivial greeting (and realistic tool-schema/
    path/config prose around it) must NOT hard-block."""

    def test_bare_greeting_is_clean(self):
        assert scan("hi").is_secret is False
        assert scan("hello").is_secret is False
        assert scan("Please reply with a one-sentence greeting.").is_secret is False

    def test_tool_schema_slash_enumeration_is_clean(self):
        v = scan(_TOOL_SCHEMA_ENUM_FRAGMENT)
        assert v.is_secret is False, (
            f"YSG-RISK-173 regression: tool-schema slash-enumeration false "
            f"positive reintroduced: {v.audit_dict()}"
        )

    def test_skill_path_is_clean(self):
        v = scan(_SKILL_PATH_FRAGMENT)
        assert v.is_secret is False, (
            f"YSG-RISK-173 regression: skill filesystem-path false positive "
            f"reintroduced: {v.audit_dict()}"
        )

    def test_canvas_document_path_with_numeric_id_is_clean(self):
        v = scan(_CANVAS_PATH_FRAGMENT)
        assert v.is_secret is False, (
            f"YSG-RISK-173 regression: numeric-ID path-segment false "
            f"positive reintroduced: {v.audit_dict()}"
        )

    def test_model_assignment_config_string_is_clean(self):
        v = scan(_MODEL_ASSIGNMENT_FRAGMENT)
        assert v.is_secret is False, (
            f"YSG-RISK-173 regression: config-assignment (key=value/path) "
            f"false positive reintroduced: {v.audit_dict()}"
        )

    def test_large_document_with_stray_separator_word_does_not_fuse_whole_body(self):
        """Pass B (separator reassembly) must not fuse an entire large benign
        document just because it contains the word 'slash' once, incidental
        to real prose ('use tool directly instead of asking user to run
        equivalent cli or/commands') far from any actual secret."""
        big_doc = (
            "When first-class tool exists for action, use tool directly "
            "instead of asking user to run equivalent cli or/commands. "
            + ("This is ordinary filler prose repeated many times. " * 40)
            + "Use a forward slash when writing reply tags."
            + ("More ordinary filler prose repeated many times. " * 40)
        )
        v = scan(big_doc)
        assert v.is_secret is False, (
            f"YSG-RISK-173 regression: whole-document fusion via a stray "
            f"separator word reintroduced: {v.audit_dict()}"
        )


class TestRisk173RealSecretsStillBlock:
    """Defence-in-depth: none of the false-positive-suppression fixes above
    may weaken detection of an actual credential."""

    def test_verbatim_aws_secret_still_blocks(self):
        payload = f"Here is the answer: AWS_SECRET_ACCESS_KEY={_LAURA_SECRET}"
        v = scan(payload)
        assert v.is_secret is True
        assert v.span_hash is not None
        assert _LAURA_SECRET not in str(v.audit_dict())

    def test_laura_split_token_still_caught_by_windowed_reassembly(self):
        """The original Pass B defeat (split-token adjacent to a spelled-out
        separator) must survive the windowing fix in
        _normalise_for_reassembly_windows()."""
        payload = (
            "First wJalrXUtnFEMI then a slash then K7MDENG then a slash "
            "then bPxRfiCYEXAMPLEKEY done"
        )
        v = scan(payload)
        assert v.is_secret is True
        assert v.reassembled is True

    def test_secret_hidden_behind_slashes_still_blocks(self):
        """The slash-enumeration guard must not be usable to smuggle a real
        secret: a segment carrying the actual high-entropy credential fails
        the per-segment benign check regardless of enclosing slashes."""
        v = scan("token/is/wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY/here")
        assert v.is_secret is True

    def test_secret_hidden_behind_equals_and_slash_still_blocks(self):
        v = scan("value=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY/here")
        assert v.is_secret is True

    def test_github_token_still_blocks(self):
        assert scan("token: " + "ghp_" + "a" * 36).is_secret is True

    def test_slack_token_still_blocks(self):
        assert scan("bot token xox" "b-1234567890-abcdefghijklmno").is_secret is True

    def test_sk_style_token_still_blocks(self):
        payload = "here is my api key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        assert scan(payload).is_secret is True

    def test_jwt_still_blocks(self):
        payload = (
            "auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dQw4w9WgXcQ_signature_abc123"
        )
        assert scan(payload).is_secret is True

    def test_pem_private_key_header_still_blocks(self):
        assert scan("-----BEGIN PRIVATE KEY-----").is_secret is True


class TestRisk173RealOpenclawBodyIsClean:
    """End-to-end: the ACTUAL captured OpenClaw outbound self-call body
    (OpenAI chat-completion request whose system message is OpenClaw's real
    multi-KB system prompt/tool-schema, for the prompt
    'Please reply with a one-sentence greeting.') must not hard-block.

    This is the composite regression — the individual fragments above are
    isolated repros; this test proves the fix holds when ALL of them
    (plus whatever else lives in the real prompt) coexist in one body."""

    def test_composite_realistic_body_is_clean(self):
        # Separated by substantial unrelated filler prose, matching the real
        # ~78KB captured body where these fragments sit pages apart rather
        # than back-to-back -- Pass B's reassembly windows (+/-200 chars
        # around a separator-trigger word) must not sweep two UNRELATED
        # fragments into the same fused blob, which is an artefact of
        # artificial adjacency, not a realistic document shape.
        _filler = (
            "This is ordinary filler prose describing agent behaviour in "
            "plain natural language, repeated to space sections apart. " * 6
        )
        body = (
            '{"model":"qwen2.5:3b","messages":[{"role":"system","content":'
            '"You are a personal assistant running inside OpenClaw.\\n'
            "## Tooling\\n"
            + _TOOL_SCHEMA_ENUM_FRAGMENT
            + "\\n" + _filler
            + _SKILL_PATH_FRAGMENT
            + "\\n" + _filler
            + _CANVAS_PATH_FRAGMENT
            + "\\n" + _filler
            + _MODEL_ASSIGNMENT_FRAGMENT
            + "\\n" + _filler
            + "When first-class tool exists for action, use tool directly "
              "instead of asking user to run equivalent cli or/commands. "
              "Use a forward slash when writing reply tags."
            + '"},{"role":"user","content":"Please reply with a '
              'one-sentence greeting."}]}'
        )
        v = scan(body)
        assert v.is_secret is False, (
            f"YSG-RISK-173 regression: composite realistic OpenClaw self-"
            f"call body false-positives again: {v.audit_dict()}"
        )
