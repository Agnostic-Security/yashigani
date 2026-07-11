"""
Yashigani Document Enforcement — opaque, per-file-salted PSEUDONYMIZE token scheme.

**DECIDED 2026-06-10** (plan §"PSEUDONYMIZE token scheme — DECIDED", red-team
``pseudonymize_cloud_llm_concept_redteam_2026-06-10.md``).  This supersedes the
earlier "tokens are opaque sequential counters, NOT a hash of the value" stance
in plan §6: Laura proved the *type-tagged sequential* scheme (``[EMAIL_1]`` /
``[PERSON_NAME_2]``) leaks the data **class** and the per-class **count**, and
that a value-derived token is acceptable — and stronger — **provided** the
derivation is a keyed, per-file-salted HMAC whose output reveals neither class
nor value.  This module is that derivation; it is the crypto boundary the
pre-push security self-review names.

Token derivation
----------------
    doc_hash = SHA-256(original document bytes)            # the per-FILE salt
    token    = base32( HMAC-SHA256(deployment_secret,
                                   doc_hash || 0x1f || value) )[:N]

rendered as a short, lowercase, opaque alphanumeric string (no class tag, no
counter, no value structure).  Three properties fall out:

  * **Opaque** — the token is the truncation of a keyed PRF output; it leaks
    neither the data class (``EMAIL`` vs ``PERSON``) nor any count, defeating
    Laura's class/count-leak finding on the old ``[CLASS_N]`` scheme.

  * **Per-file unique** — the salt is ``doc_hash`` (SHA-256 of the *original*
    document bytes), so the SAME value in two different documents derives
    DIFFERENT tokens.  This defeats known-text / dictionary / cross-file
    correlation attacks (an attacker who knows ``alice@corp.com`` cannot
    recognise its token across files), and it **binds** every token to its
    source document for integrity / splice detection (a token minted under
    document A's salt cannot be validated against document B).

  * **Within-doc coherent** — the salt is constant within one file, so the same
    value always derives the same token in that file: joins, repeats and
    cross-references survive (plan §5.3a coherence), exactly as the old scheme
    preserved — only the token *string* changes.

The **deployment_secret** is sourced from the existing gateway secret mechanism
(``/run/secrets/`` native secrets / KMS), never hardcoded.  It is **mandatory**:
``derive_token`` raises ``ValueError`` when the secret is absent (DP-Y-002 §3.1
defence-in-depth — the primitive enforces the invariant, not only the pipeline).

Truncation length (collision-resistance at document scale)
----------------------------------------------------------
Tokens must be **bijective within a document** (distinct value → distinct token,
or the tokenised artefact corrupts data).  We render ``N`` base32 characters =
``5*N`` bits.  By the birthday bound, for ``n`` distinct values the expected
collision probability is ``≈ n^2 / 2^(5N+1)``.  A pathological in-scope document
might carry ``n ≈ 10^6`` distinct values (a large spreadsheet).  We choose
**N = 12** (60 bits):

    n = 10^6  →  P(collision) ≈ (10^6)^2 / 2^61 ≈ 10^12 / 2.3·10^18 ≈ 4·10^-7

i.e. under one-in-two-million even for a million-value document — and the
:class:`OpaqueTokenAssigner` additionally **detects and resolves** any actual
within-document collision deterministically (re-derive with a bounded domain-
separation counter), so the bijection is a hard guarantee, not merely a
probabilistic one.  12 chars also satisfies the brief's "~11+ chars" and keeps
the token compact for the cloud payload.

NEVER log the secret, the salt, or the token→value map.  This module logs none
of them; callers must not either.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# --- Token rendering -------------------------------------------------------

#: Number of base32 characters in an opaque token (5 bits each → 60 bits).
#: See the module docstring for the collision-resistance derivation.
TOKEN_CHARS = 12

#: Domain separator between the per-file salt and the value inside the HMAC
#: message, so ``salt || value`` cannot be ambiguous across a salt/value
#: boundary (a length-extension-style ambiguity).  0x1f = ASCII unit separator.
_DOMAIN_SEP = b"\x1f"

#: Lowercase base32 alphabet (RFC 4648 lower, no padding).  Opaque alphanumeric;
#: avoids the ``[TAG_N]`` shape entirely.
_B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


# --- deployment_secret sourcing (existing gateway secret mechanism) --------

#: Env var naming the deployment secret directly (takes precedence) OR the file
#: it lives in.  Mirrors the ``/run/secrets`` + env convention used across the
#: codebase (license_key, db_aes_key, vault_*).
ENV_SECRET = "YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET"
ENV_SECRET_FILE = "YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET_FILE"

#: Default native-secrets path (Docker/Podman/K8s secret mount), consistent with
#: the rest of the gateway (``/run/secrets/<key>``).
_DEFAULT_SECRET_FILE = "/run/secrets/document_pseudonymize_secret"


def load_deployment_secret() -> Optional[bytes]:
    """Source the deployment secret from the existing gateway secret mechanism.

    Resolution order (first hit wins), all consistent with the codebase's
    ``/run/secrets`` + env convention — **never hardcoded**:

      1. ``YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET`` (the secret value directly);
      2. the file named by ``YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET_FILE``;
      3. the default native-secret mount ``/run/secrets/document_pseudonymize_secret``.

    Returns the secret bytes, or ``None`` when none is provisioned (the scheme
    then falls back to salt-only keying — see module docstring).  Never logs the
    secret value; logs only *that* a source was found / that none was.
    """
    raw = os.environ.get(ENV_SECRET)
    if raw:
        return raw.encode("utf-8")

    candidates = []
    file_env = os.environ.get(ENV_SECRET_FILE)
    if file_env:
        candidates.append(Path(file_env))
    candidates.append(Path(_DEFAULT_SECRET_FILE))

    for path in candidates:
        try:
            if path.is_file():
                data = path.read_bytes().rstrip(b"\n")
                if data:
                    return data
        except OSError as exc:  # unreadable mount — surface, do not crash
            logger.warning(
                "document_pseudonymize_secret at %s unreadable (%s); "
                "trying next source", path, exc,
            )
    return None


def compute_doc_hash(document_bytes: bytes) -> str:
    """The per-file salt: SHA-256 of the ORIGINAL document bytes, hex.

    Same bytes → same salt (stable token derivation on retry); different bytes →
    different salt (per-file token uniqueness + splice binding)."""
    return hashlib.sha256(document_bytes).hexdigest()


def _render_base32(digest: bytes, *, chars: int = TOKEN_CHARS) -> str:
    """Render the first ``chars`` lowercase-base32 characters of ``digest``."""
    # standard base32 (uppercase, '=' padded) → lowercase, strip padding.
    b32 = base64.b32encode(digest).decode("ascii").lower().rstrip("=")
    return b32[:chars]


def derive_token(
    doc_hash: str,
    value: str,
    *,
    secret: Optional[bytes],
    chars: int = TOKEN_CHARS,
    counter: int = 0,
) -> str:
    """Derive the opaque token for ``value`` under the per-file ``doc_hash`` salt.

    ``token = base32( HMAC-SHA256(key, doc_hash || 0x1f || value [|| counter]) )[:chars]``

    The HMAC *key* is the deployment ``secret``; it is **mandatory** — raises
    ``ValueError`` if absent (DP-Y-002 §3.1 defence-in-depth).

    ``counter`` is a domain-separation nonce used ONLY to deterministically
    resolve a (rare) within-document token collision (see
    :class:`OpaqueTokenAssigner`); 0 for the normal path.  It changes the HMAC
    message, not the key, so the same (salt, value, counter) is always stable.
    """
    if not secret:
        raise ValueError(
            "derive_token: deployment secret is required (DP-Y-002 §3.1). "
            "Provision YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET or "
            "/run/secrets/document_pseudonymize_secret"
        )
    key = secret
    msg = doc_hash.encode("ascii") + _DOMAIN_SEP + value.encode("utf-8")
    if counter:
        msg += _DOMAIN_SEP + str(counter).encode("ascii")
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    return _render_base32(digest, chars=chars)


def token_matches_doc(
    token: str,
    value: str,
    doc_hash: str,
    *,
    secret: Optional[bytes],
    chars: int = TOKEN_CHARS,
    max_counter: int = 8,
) -> bool:
    """Integrity check: does ``token`` validly stand for ``value`` under the
    ``doc_hash`` salt of THIS document?

    Recomputes the derivation (trying the small collision-resolution counter
    range) and constant-time-compares.  A token minted under a DIFFERENT
    document's salt (cross-file splice) will not validate — this is the
    foreign-salt rejection that backstops integrity-verify (plan integrity step).

    Returns ``False`` immediately when ``secret`` is ``None`` — without the
    deployment secret re-derivation is impossible; fail safe (DP-Y-002 §3.1).
    """
    if secret is None:
        # Cannot re-derive without the deployment secret.  Return False for
        # every token so callers receive ok=False (conservative / fail-safe).
        return False
    for counter in range(0, max_counter + 1):
        candidate = derive_token(
            doc_hash, value, secret=secret, chars=chars, counter=counter,
        )
        if hmac.compare_digest(candidate, token):
            return True
    return False
