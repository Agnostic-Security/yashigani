"""
MCP Broker — ES384 JWT issuance and verification.

Implements Nico's locked crypto spec (mcp-identity-jwt-spec-20260529.md):
  - Algorithm: ES384 (ECDSA P-384 / SHA-384). NO SUBSTITUTES.
  - kid in every JWT header (upstream verifiers use kid for JWKS key selection).
  - chain is an ordered array of SPIFFE URI strings (append-only per hop).
  - jti is UUIDv4, checked against nonce store before accepting relay JWTs.
  - exp = iat + 60 (configurable via mcp_jwt_ttl_seconds).
  - Clock-skew tolerance: ±5 seconds (per RFC 7519 §4.1.4).
  - Gateway pre-validates chain depth before signing (belt-and-suspenders).
  - JWKS Cache-Control: max-age=300 (see _jwks.py).
  - KMS-backed key in production; PEM file at /run/secrets/mcp_identity_signing_key
    (mounted by install.sh from docker/secrets/, overridable via
    YASHIGANI_MCP_SIGNING_KEY_PATH env var).

Startup self-test:
  At import time, McpJwtIssuer performs a startup self-test:
  1. Signs a test payload → verifies algorithm header is "ES384".
  2. Fires a known-bad object chain at the JWT builder → asserts it is
     rejected before the token is issued (per Nico FIPS checklist §7).

v2.25.0 / P1 W3 Phase 2b-ii / Nico NICO-004.

v1 limitation (token binding):
  The JWT does not cryptographically bind to the TLS session (no cnf/DPoP).
  Binding is attestation-based: posture is gateway-asserted from physical
  channel observation, not self-declared by the caller. Full token-binding
  (DPoP or cnf with TLS export keying material) is deferred to v2.
  A compromised upstream that knows a valid JWT can replay it within the
  TTL window (60s), subject to jti nonce dedup at the gateway.
"""
from __future__ import annotations

import base64
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP384R1,
)

import jwt as pyjwt

logger = logging.getLogger(__name__)

# Locked constants (Nico spec §1 / §3)
_ALGORITHM = "ES384"
_AUDIENCE = "yashigani-mcp-upstream"
_JWT_TTL_SECONDS = int(os.environ.get("YASHIGANI_MCP_JWT_TTL_SECONDS", "60"))
_CLOCK_SKEW_SECONDS = 5
_DEFAULT_CHAIN_MAX_DEPTH = 3
_DEFAULT_SIGNING_KEY_PATH = "/run/secrets/mcp_identity_signing_key"


def _get_signing_key_path() -> Path:
    """Return the MCP signing key path, reading YASHIGANI_MCP_SIGNING_KEY_PATH at call time.

    Deliberately NOT evaluated at module import so that tests can monkeypatch
    YASHIGANI_MCP_SIGNING_KEY_PATH without requiring importlib.reload().
    Laura SB-1 fix.
    """
    return Path(
        os.environ.get("YASHIGANI_MCP_SIGNING_KEY_PATH", _DEFAULT_SIGNING_KEY_PATH)
    )


def _b64url_no_pad(data: bytes) -> str:
    """Base64-URL encode without padding (JWK format)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class ChainValidationError(ValueError):
    """Raised when the identity chain fails validation rules."""


class ChainDepthExceeded(ChainValidationError):
    """Raised when the outgoing chain would exceed mcp_chain_max_depth."""


class McpJwtIssuer:
    """
    Issues ES384-signed MCP identity JWTs per Nico spec §1-§5.

    Key loading order:
      1. YASHIGANI_MCP_SIGNING_KEY_PEM env var (base64-encoded PEM, for testing)
      2. PEM file at the path in YASHIGANI_MCP_SIGNING_KEY_PATH
         (default /run/secrets/mcp_identity_signing_key — docker secret bind-mount;
         install.sh writes docker/secrets/mcp_identity_signing_key which appears
         at that path inside the gateway container, 0600).
      3. Generates a new ephemeral key (WARN: not persisted, for unit tests only;
         REFUSED in production/staging — Fix-5).

    Production: key is KMS-backed (Vault Transit, AWS KMS, etc.).
    The KMS abstraction is a drop-in replacement for this class that implements
    the same sign() interface delegating to the KMS API.

    Startup self-test:
      Issues a test token and verifies:
      1. Header alg == "ES384" (Nico FIPS checklist §7)
      2. Known-bad object chain is rejected before token issuance
    """

    def __init__(
        self,
        tenant_id: str,
        private_key: Optional[EllipticCurvePrivateKey] = None,
        key_generated_at: Optional[int] = None,
        chain_max_depth: int = _DEFAULT_CHAIN_MAX_DEPTH,
        jwt_ttl_seconds: int = _JWT_TTL_SECONDS,
    ) -> None:
        self._tenant_id = tenant_id
        self._chain_max_depth = chain_max_depth
        self._ttl = jwt_ttl_seconds

        # Nico ship-blocker: FIPS provider assertion.
        # If FIPS_MODE=1, verify that the OpenSSL FIPS provider is actually
        # loaded before accepting any crypto work.  Fail loudly if absent —
        # never silently degrade to a non-FIPS OpenSSL configuration.
        # Mirrors the shell guard _fips_assert_provider_loaded in
        # lib/yashigani-fips.sh:60.
        self._assert_fips_provider_if_required()

        if private_key is not None:
            self._key = private_key
            # When key is injected directly (tests / KMS wrapper), use the
            # caller-supplied key_generated_at or fall back to now().
            stable_generated_at: Optional[int] = None
        else:
            self._key, stable_generated_at = self._load_or_generate_key()

        # Nico kid-stability fix: prefer (in order):
        #   1. caller-supplied key_generated_at (explicit override / tests)
        #   2. stable_generated_at from _load_or_generate_key() (file mtime for path #2)
        #   3. int(time.time()) fallback (env-var PEM path #1, ephemeral path #3)
        self._generated_at = key_generated_at or stable_generated_at or int(time.time())
        self._kid = f"mcp-{tenant_id}-{self._generated_at}"

        # Derive the JWK for JWKS publication
        self._public_key: EllipticCurvePublicKey = self._key.public_key()

        # Startup self-test (Nico FIPS checklist §7)
        self._startup_self_test()

    @staticmethod
    def _assert_fips_provider_if_required() -> None:
        """
        Nico ship-blocker: FIPS provider assertion.

        If FIPS_MODE=1, check that the OpenSSL FIPS provider is loaded via
        `openssl list -providers`.  Raises RuntimeError immediately if the
        FIPS provider is absent — never silently degrades to non-FIPS crypto.

        Mirrors the shell guard `_fips_assert_provider_loaded` in
        lib/yashigani-fips.sh:60.

        In non-FIPS deployments (FIPS_MODE unset or not "1") this is a no-op.
        """
        fips_mode = os.environ.get("FIPS_MODE", "").strip()
        if fips_mode != "1":
            return  # Non-FIPS deployment — skip assertion

        try:
            import subprocess as _subprocess
            result = _subprocess.run(
                ["openssl", "list", "-providers"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            output = result.stdout + result.stderr
        except FileNotFoundError:
            raise RuntimeError(
                "McpJwtIssuer: FIPS_MODE=1 but 'openssl' binary not found. "
                "Cannot verify FIPS provider status. "
                "Install openssl or disable FIPS_MODE."
            )
        except Exception as exc:
            raise RuntimeError(
                f"McpJwtIssuer: FIPS_MODE=1 but 'openssl list -providers' failed: {exc}. "
                "Cannot verify FIPS provider status."
            ) from exc

        # The FIPS provider shows as "fips" in the providers list.
        # We check for the case-insensitive string "fips" in the output.
        if "fips" not in output.lower():
            raise RuntimeError(
                "McpJwtIssuer: FIPS_MODE=1 but the OpenSSL FIPS provider is NOT loaded. "
                "Output of 'openssl list -providers':\n"
                f"{output.strip()}\n"
                "Ensure the FIPS provider is installed and configured in openssl.cnf. "
                "The gateway MUST NOT operate in FIPS mode without a validated FIPS "
                "provider. Failing startup to prevent non-compliant operation. "
                "See lib/yashigani-fips.sh:60 for the install procedure."
            )

        logger.info(
            "mcp-broker: FIPS_MODE=1 — OpenSSL FIPS provider confirmed loaded"
        )

    def _load_or_generate_key(self) -> tuple[EllipticCurvePrivateKey, Optional[int]]:
        """
        Load the signing key from env, secrets file, or generate ephemeral.

        Returns (key, stable_generated_at) where stable_generated_at is:
          - None  for path #1 (env-var PEM; caller uses int(time.time()) fallback)
          - int   derived from the file's mtime for path #2 — ensures all replicas
                  holding the SAME file produce the SAME kid (Nico kid-stability fix)
          - None  for path #3 (ephemeral; kid will differ per process — dev only)

        WARNING: ephemeral key generation means the JWKS changes on restart —
        downstream verifiers caching the JWKS will reject tokens after restart.
        Only acceptable for unit tests.

        Laura SB-1: YASHIGANI_MCP_SIGNING_KEY_PATH is read HERE (at call time),
        not at module import, so monkeypatching the env var takes effect without
        importlib.reload().
        """
        # 1. Env var (base64-encoded PEM — for test injection)
        pem_b64 = os.environ.get("YASHIGANI_MCP_SIGNING_KEY_PEM", "")
        if pem_b64:
            try:
                pem = base64.b64decode(pem_b64)
                key = serialization.load_pem_private_key(pem, password=None)
                if not isinstance(key, EllipticCurvePrivateKey):
                    raise ValueError("MCP signing key must be an EC private key")
                if not isinstance(key.curve, SECP384R1):
                    raise ValueError(
                        f"MCP signing key must use P-384 curve; got {type(key.curve).__name__}. "
                        "Nico spec §1: ES384 only."
                    )
                logger.info("mcp-broker: loaded MCP signing key from env var")
                # Path #1: no stable file mtime — return None so __init__ uses its
                # key_generated_at parameter (or falls back to int(time.time())).
                return key, None
            except Exception as exc:
                raise RuntimeError(
                    f"YASHIGANI_MCP_SIGNING_KEY_PEM is set but invalid: {exc}"
                ) from exc

        # 2. PEM file (docker secret bind-mount in prod; arbitrary path in dev)
        # Read YASHIGANI_MCP_SIGNING_KEY_PATH at call time (Laura SB-1 fix).
        signing_key_path = _get_signing_key_path()
        if signing_key_path.exists():
            try:
                pem = signing_key_path.read_bytes()
                key = serialization.load_pem_private_key(pem, password=None)
                if not isinstance(key, EllipticCurvePrivateKey):
                    raise ValueError("MCP signing key must be an EC private key")
                if not isinstance(key.curve, SECP384R1):
                    raise ValueError(
                        f"MCP signing key must use P-384 curve; got {type(key.curve).__name__}. "
                        "Nico spec §1: ES384 only."
                    )
                logger.info(
                    "mcp-broker: loaded MCP signing key from %s (DEV MODE — not KMS-backed)",
                    signing_key_path,
                )
                # Path #2 (Nico kid-stability fix): derive stable_generated_at from
                # the file's mtime so that all replicas mounting the SAME file produce
                # the SAME kid, regardless of when they start.
                file_mtime = int(signing_key_path.stat().st_mtime)
                return key, file_mtime
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to load MCP signing key from {signing_key_path}: {exc}"
                ) from exc

        # 3. Ephemeral key (unit tests only) — FAIL-CLOSED in production/staging.
        #
        # Fix-5 (HA-correctness): an ephemeral key is NOT acceptable in production
        # or staging because:
        #   - Each gateway replica generates a DIFFERENT key → JWTs from replica A
        #     are rejected by replica B's verifier (mismatched public key in JWKS).
        #   - A gateway restart rotates the key → upstream verifiers caching the
        #     JWKS will reject tokens until the JWKS cache expires (up to 60s).
        #
        # If YASHIGANI_ENV is "production" or "staging", REFUSE to start.
        # Point the operator at the correct setup (secrets file or env var).
        # dev/test environments continue to allow ephemeral keys (unchanged).
        _env = os.environ.get("YASHIGANI_ENV", "").strip().lower()
        signing_key_path_str = str(_get_signing_key_path())
        if _env in {"production", "staging"}:
            raise RuntimeError(
                f"McpJwtIssuer: YASHIGANI_ENV={_env!r} but no persistent MCP signing key "
                "was found. An ephemeral key is NOT acceptable in production/staging "
                "(multi-replica JWKS mismatch + restart key rotation risk). "
                f"Set YASHIGANI_MCP_SIGNING_KEY_PEM (base64 PEM) or mount the key at "
                f"{signing_key_path_str} (0600, PEM format). "
                "See install.sh for key generation. "
                "Nico spec §2: KMS-backed persistent key required in production."
            )

        logger.warning(
            "mcp-broker: generating EPHEMERAL MCP signing key "
            "(NOT PERSISTED — dev/test mode only). "
            "Set YASHIGANI_MCP_SIGNING_KEY_PEM or provide %s for persistent key. "
            "Nico spec §2: KMS-backed key required in production.",
            signing_key_path_str,
        )
        # Path #3: ephemeral — no stable generated_at; kid will differ per process.
        return ec.generate_private_key(SECP384R1()), None

    def _startup_self_test(self) -> None:
        """
        Nico FIPS checklist §7: verify algorithm header and chain validation
        at startup before the broker accepts any calls.
        """
        # Test 1: verify algorithm header == "ES384"
        test_payload = {"sub": "_selftest", "iss": "selftest", "aud": _AUDIENCE,
                        "iat": int(time.time()), "exp": int(time.time()) + 10,
                        "jti": str(uuid.uuid4())}
        test_token = pyjwt.encode(test_payload, self._key, algorithm=_ALGORITHM,
                                   headers={"kid": self._kid, "alg": _ALGORITHM})
        header = pyjwt.get_unverified_header(test_token)
        assert header.get("alg") == "ES384", (
            f"MCP JWT startup self-test FAILED: header alg={header.get('alg')!r}, "
            f"expected 'ES384'. Nico FIPS checklist §7. "
            f"This is a critical configuration error — broker will not start."
        )

        # Test 2: known-bad object chain must be rejected before token issuance
        # (Nico spec §7: chain format validation must reject non-string elements)
        bad_chain: list = [{"spiffe": "bad-object-not-a-string"}]  # type: ignore[list-item]
        try:
            self._validate_chain(bad_chain, extend_with=None)
            raise AssertionError(
                "MCP JWT startup self-test FAILED: known-bad object chain was NOT "
                "rejected. Nico spec §7 / Nico spec §4 binding requirement. "
                "OPA guard will deny object chains — the broker must reject them "
                "before issuing a token."
            )
        except ChainValidationError:
            pass  # expected — chain validation correctly rejected the bad chain

        logger.info(
            "mcp-broker: JWT issuer startup self-test PASSED (ES384 alg + chain validation)"
        )

    def _validate_chain(
        self, chain: list, extend_with: Optional[str]
    ) -> list[str]:
        """
        Validate and optionally extend the identity chain.

        Rules (Nico spec §4 + §9):
        1. chain must be a list (is_array).
        2. Every element must be a string (every is_string).
        3. chain.length + (1 if extend_with else 0) <= chain_max_depth.
        4. extend_with (if provided) is appended (never prepended).

        Returns the validated (and optionally extended) chain.
        Raises ChainValidationError or ChainDepthExceeded.
        """
        if not isinstance(chain, list):
            raise ChainValidationError(
                f"identity.chain must be a list; got {type(chain).__name__}. "
                "Nico spec §4 binding requirement / OPA guard."
            )
        for i, element in enumerate(chain):
            if not isinstance(element, str):
                raise ChainValidationError(
                    f"identity.chain[{i}] must be a string; "
                    f"got {type(element).__name__}: {element!r}. "
                    "Nico spec §4 / OPA guard: is_array AND every is_string."
                )

        resulting_depth = len(chain) + (1 if extend_with is not None else 0)
        if resulting_depth > self._chain_max_depth:
            raise ChainDepthExceeded(
                f"Chain depth would be {resulting_depth} which exceeds "
                f"mcp_chain_max_depth={self._chain_max_depth}. "
                "Nico spec §4 / §9.7: gateway MUST NOT issue JWT with chain "
                "length > mcp_chain_max_depth. Rejecting before signing."
            )

        result = list(chain)
        if extend_with is not None:
            result.append(extend_with)
        return result

    def issue(
        self,
        *,
        user_id: str,
        agent_name: str,
        posture: str,
        posture_binding: dict,
        action: str,
        call_id: str,
        upstream_chain: Optional[list[str]] = None,
    ) -> str:
        """
        Issue a gateway-signed ES384 JWT per Nico spec §4.

        Parameters
        ----------
        user_id:
            Opaque internal user_id for the sub claim.
            Must NOT contain email, real name, or PII.

        agent_name:
            Agent name (used in SPIFFE URI and agent claim).

        posture:
            One of "mcp-a", "mcp-b", "mcp-c". MUST be derived from the
            physical channel before calling issue().

        posture_binding:
            PostureBinding.to_dict() — evidence of how posture was derived.

        action:
            MCP action string (e.g. "mcp.tools.call").

        call_id:
            UUIDv4 call identifier for end-to-end tracing.

        upstream_chain:
            For mcp-c: the upstream identity.chain from the relay caller's
            verified JWT. This hop's SPIFFE URI is appended to form the
            outgoing chain. Must be None for mcp-a / mcp-b (first hop).

        Returns
        -------
        str: The signed JWT.

        Raises
        ------
        ChainDepthExceeded: If the outgoing chain would exceed max depth.
        ChainValidationError: If chain elements are not all strings.
        """
        iat = int(time.time())
        exp = iat + self._ttl
        jti = str(uuid.uuid4())

        spiffe_uri = (
            f"spiffe://yashigani.internal/agents/{self._tenant_id}/{agent_name}"
        )
        iss = f"https://gateway.yashigani.internal/{self._tenant_id}"

        # Build chain: for mcp-a / mcp-b (first hop), chain = [this hop's SPIFFE].
        # For mcp-c (relay), chain = upstream_chain + [this hop's SPIFFE].
        incoming_chain = upstream_chain or []
        outgoing_chain = self._validate_chain(incoming_chain, extend_with=spiffe_uri)

        payload: dict[str, Any] = {
            "iss": iss,
            "aud": _AUDIENCE,
            "iat": iat,
            "exp": exp,
            "jti": jti,
            "sub": user_id,
            "identity": {
                "spiffe": spiffe_uri,
                "chain": outgoing_chain,
            },
            "tenant": self._tenant_id,
            "agent": agent_name,
            "call_id": call_id,
            "posture": posture,
            "posture_binding": posture_binding,
        }

        token = pyjwt.encode(
            payload,
            self._key,
            algorithm=_ALGORITHM,
            headers={"kid": self._kid, "alg": _ALGORITHM},
        )
        logger.debug(
            "mcp-broker: issued JWT jti=%s agent=%s posture=%s chain_depth=%d",
            jti, agent_name, posture, len(outgoing_chain),
        )
        return token

    def public_key_jwk(self) -> dict:
        """
        Return the public key as a JWK entry per Nico spec §5.

        Format:
          {"kty": "EC", "crv": "P-384", "use": "sig", "alg": "ES384",
           "kid": "mcp-{tenant_id}-{epoch}", "x": "...", "y": "...",
           "nbf": <epoch>, "exp": <epoch>}

        exp is nbf + 90 days (default rotation cadence).
        """
        pub = self._public_key
        numbers = pub.public_numbers()
        key_size_bytes = (pub.key_size + 7) // 8

        def _to_b64(n: int) -> str:
            return _b64url_no_pad(n.to_bytes(key_size_bytes, "big"))

        nbf = self._generated_at
        exp_ts = nbf + 90 * 24 * 3600  # 90-day rotation cadence

        return {
            "kty": "EC",
            "crv": "P-384",
            "use": "sig",
            "alg": _ALGORITHM,
            "kid": self._kid,
            "x": _to_b64(numbers.x),
            "y": _to_b64(numbers.y),
            "nbf": nbf,
            "exp": exp_ts,
        }

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def tenant_id(self) -> str:
        return self._tenant_id


class McpJwtVerifier:
    """
    Verifies ES384 MCP identity JWTs issued by a gateway.

    Used to verify upstream relay JWTs (mcp-c posture) before extending
    the identity chain.

    JWKS is provided at construction time (or fetched from the JWKS endpoint
    for cross-installation relay — that path is implemented in the HTTP transport).

    Clock-skew tolerance: ±5 seconds per Nico spec §3.
    """

    def __init__(
        self,
        jwks_keys: list[EllipticCurvePublicKey],
        kid_to_key: Optional[dict[str, EllipticCurvePublicKey]] = None,
        expected_issuer_prefix: str = "https://gateway.yashigani.internal/",
        expected_audience: str = _AUDIENCE,
        skew_tolerance: float = _CLOCK_SKEW_SECONDS,
    ) -> None:
        """
        Parameters
        ----------
        jwks_keys:
            List of public keys (for kid-less fallback).

        kid_to_key:
            Mapping of kid → public key (preferred — fast key selection).

        expected_issuer_prefix:
            JWT iss must start with this prefix (tenant_id follows).

        expected_audience:
            JWT aud must equal this value.
        """
        self._keys = jwks_keys
        self._kid_map = kid_to_key or {}
        self._iss_prefix = expected_issuer_prefix
        self._audience = expected_audience
        self._skew = skew_tolerance

    @classmethod
    def from_issuer(cls, issuer: "McpJwtIssuer") -> "McpJwtVerifier":
        """Create a verifier from a co-located issuer (same-installation relay).

        CAVEAT (Nico-F1 / point-in-time snapshot):
        This captures the issuer's public key at construction time.  If the
        issuer rotates its key after this verifier is built (key_generated_at
        changes), the verifier will NOT see the new key and will reject JWTs
        signed with it.

        For rotation-safe verification, rebuild the verifier from a JwksStore
        that is updated atomically during key rotation (see _jwks.py ::rotate()).
        Cross-installation relay verification must use the JWKS endpoint
        (/.well-known/yashigani-mcp-jwks.json) with cache-busting on kid miss,
        not from_issuer().

        Safe use: unit tests, single-issuer same-process scenarios where key
        rotation does not occur during the verifier's lifetime.
        """
        kid_to_key = {issuer.kid: issuer._public_key}
        return cls(
            jwks_keys=[issuer._public_key],
            kid_to_key=kid_to_key,
            expected_issuer_prefix=f"https://gateway.yashigani.internal/{issuer.tenant_id}",
        )

    def verify(self, token: str) -> dict:
        """
        Verify an ES384 JWT.

        Returns the decoded payload dict on success.
        Raises jwt.exceptions.* on failure (caller must treat as deny).

        Notes:
        - Uses kid from header to select the correct JWKS entry.
        - Falls back to trying all known keys if kid is not found (rotation overlap).
        - Applies ±skew_tolerance leeway per Nico spec §3.
        """
        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.DecodeError as exc:
            raise pyjwt.DecodeError(f"Invalid JWT header: {exc}") from exc

        if header.get("alg") != _ALGORITHM:
            raise pyjwt.InvalidAlgorithmError(
                f"JWT algorithm must be {_ALGORITHM}; got {header.get('alg')!r}. "
                "Nico spec §1: ES384 only."
            )

        kid = header.get("kid")
        keys_to_try: list[EllipticCurvePublicKey] = []

        if kid and kid in self._kid_map:
            keys_to_try = [self._kid_map[kid]]
        else:
            # Rotation overlap: try all known keys
            keys_to_try = self._keys

        last_exc: Exception = pyjwt.DecodeError("No keys available")
        for pubkey in keys_to_try:
            try:
                payload = pyjwt.decode(
                    token,
                    pubkey,
                    algorithms=[_ALGORITHM],
                    audience=self._audience,
                    leeway=self._skew,
                )
                # Validate issuer prefix
                iss = payload.get("iss", "")
                if not iss.startswith(self._iss_prefix):
                    raise pyjwt.InvalidIssuerError(
                        f"JWT iss={iss!r} does not start with expected prefix "
                        f"{self._iss_prefix!r}"
                    )
                # Validate chain format (belt-and-suspenders — OPA also checks)
                identity = payload.get("identity", {})
                chain = identity.get("chain", [])
                if not isinstance(chain, list):
                    raise pyjwt.DecodeError(
                        f"identity.chain must be a list; got {type(chain).__name__}. "
                        "Nico spec §4 binding requirement."
                    )
                for element in chain:
                    if not isinstance(element, str):
                        raise pyjwt.DecodeError(
                            f"identity.chain element must be a string; "
                            f"got {type(element).__name__}: {element!r}."
                        )
                return payload
            except (pyjwt.DecodeError, pyjwt.InvalidSignatureError,
                    pyjwt.ExpiredSignatureError, pyjwt.InvalidIssuerError,
                    pyjwt.InvalidAudienceError) as exc:
                last_exc = exc
                continue

        raise last_exc
