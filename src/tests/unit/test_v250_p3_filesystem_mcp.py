"""
v2.25.0 P3 — Shape-C filesystem bundle gate findings
======================================================

Pytest regression suite covering the four findings fixed in this branch:

  FIX-P3-001  (LAURA-P3-001, MED) — encoded path traversal bypass
              Broker normalises args before OPA; OPA rejects residual %2e/%2f.
  FIX-P3-002  (LAURA-P3-002, MED) — read_multiple_files paths-array gap
              _fs_paths_array_safe checks every element of args.paths.
              Also covers move_file args.source / args.destination.
  FIX-P3-ENFORCE (Iris F2, pivotal) — filesystem tool-gating was inert
              McpBroker.enforce() now queries query_filesystem_tool_allowed()
              for agents with is_filesystem_agent=True.
  FIX-NICO-001 (NICO-001, MED-HIGH) — placeholder digest accepted by linter
              _is_placeholder_digest() rejects all-identical-char sha256.
  FIX-IRIS-F1  (Iris F1, MED) — codegen ignores mounts[0].name
              _gen_compose_override_shape_c() reads mounts[0].name when set.
  NICO-002 (contract) — CertMount(spiffe_identity=resolve_spiffe_uri(fs_manifest))
              must not raise — SPIFFE URI from filesystem bundle matches prefix.

Coverage groups:
  A. _normalize_path_arg / _normalize_tool_args (unit)
  B. query_filesystem_tool_allowed (unit — mocked OPA)
  C. McpBroker.enforce() second gate (unit — mocked OPA both gates)
  D. Linter M6 placeholder digest (unit)
  E. Codegen mounts[0].name (unit)
  F. Nico-002 CertMount + resolve_spiffe_uri contract

v2.25.0 / P3 filesystem bundle / LAURA-P3-001 / LAURA-P3-002 / Iris-F2 / Nico-001 / Iris-F1.
"""
from __future__ import annotations

import logging
import copy
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1


# ===========================================================================
# A. Path normalisation (unit — no I/O)
# ===========================================================================

class TestNormalizePathArg:
    """Unit tests for _normalize_path_arg and _normalize_tool_args."""

    def test_plain_path_unchanged(self) -> None:
        from yashigani.mcp._opa import _normalize_path_arg
        assert _normalize_path_arg("workspace/data.txt") == "workspace/data.txt"

    def test_single_encoded_slash(self) -> None:
        """..%2f decoded to ../"""
        from yashigani.mcp._opa import _normalize_path_arg
        result = _normalize_path_arg("..%2fetc%2fshadow")
        assert "../" in result, f"Expected ../ in result, got: {result!r}"

    def test_double_encoded_slash(self) -> None:
        """%252f → %2f → / (two decode passes)"""
        from yashigani.mcp._opa import _normalize_path_arg
        result = _normalize_path_arg("..%252fetc%252fshadow")
        assert "../" in result or "../" in result, (
            f"Expected decoded traversal in: {result!r}"
        )

    def test_double_encoded_dot(self) -> None:
        """%252e%252e decoded twice → ..."""
        from yashigani.mcp._opa import _normalize_path_arg
        result = _normalize_path_arg("%252e%252e%252fetc%252fshadow")
        # After two rounds of decoding: %2e%2e%2fetc%2fshadow → ../etc/shadow
        assert "../" in result, f"Expected ../ in: {result!r}"

    def test_nfkc_normalisation_applied(self) -> None:
        """NFKC collapse of unicode lookalikes (U+FF0E is the fullwidth period)."""
        from yashigani.mcp._opa import _normalize_path_arg
        # U+FF0E FULLWIDTH FULL STOP + U+FF0E + U+FF0F FULLWIDTH SOLIDUS
        result = _normalize_path_arg("．．／")
        # NFKC maps these to ASCII equivalents
        assert result == "../", f"Expected ../, got: {result!r}"

    def test_idempotent_on_clean_path(self) -> None:
        from yashigani.mcp._opa import _normalize_path_arg
        clean = "reports/q1-2026.csv"
        assert _normalize_path_arg(clean) == clean

    def test_normalize_tool_args_path_key(self) -> None:
        from yashigani.mcp._opa import _normalize_tool_args
        args = {"path": "..%2fetc%2fshadow", "other": "unchanged"}
        result = _normalize_tool_args(args)
        assert result is not None
        assert "../" in result["path"]
        assert result["other"] == "unchanged"

    def test_normalize_tool_args_paths_array(self) -> None:
        """FIX-P3-002: paths array is normalised element-by-element."""
        from yashigani.mcp._opa import _normalize_tool_args
        args = {"paths": ["workspace/ok.txt", "..%2fetc%2fshadow"]}
        result = _normalize_tool_args(args)
        assert result is not None
        assert result["paths"][0] == "workspace/ok.txt"
        assert "../" in result["paths"][1]

    def test_normalize_tool_args_source_destination(self) -> None:
        """move_file: source and destination are normalised."""
        from yashigani.mcp._opa import _normalize_tool_args
        args = {"source": "..%2fsecret", "destination": "workspace%2fdst"}
        result = _normalize_tool_args(args)
        assert result is not None
        assert "../" in result["source"]

    def test_normalize_tool_args_none_passthrough(self) -> None:
        """None args returns None."""
        from yashigani.mcp._opa import _normalize_tool_args
        assert _normalize_tool_args(None) is None

    def test_normalize_tool_args_non_dict_passthrough(self) -> None:
        """Non-dict input returns as-is."""
        from yashigani.mcp._opa import _normalize_tool_args
        assert _normalize_tool_args("not-a-dict") == "not-a-dict"  # type: ignore[arg-type]

    def test_normalize_tool_args_does_not_mutate_original(self) -> None:
        """The original args dict is not mutated."""
        from yashigani.mcp._opa import _normalize_tool_args
        original = {"path": "..%2fetc"}
        _ = _normalize_tool_args(original)
        assert original["path"] == "..%2fetc", "original dict must not be mutated"


# ===========================================================================
# B. query_filesystem_tool_allowed (unit — mocked OPA)
# ===========================================================================

class TestQueryFilesystemToolAllowed:
    """Unit tests for query_filesystem_tool_allowed (FIX-P3-ENFORCE)."""

    async def test_opa_returns_true_allowed(self) -> None:
        """OPA result=true → allowed=True."""
        from yashigani.mcp._opa import query_filesystem_tool_allowed
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": True}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        result = await query_filesystem_tool_allowed(
            opa_url="http://localhost:8181",
            tool_name="read_file",
            tool_args={"path": "workspace/notes.txt"},
            http_client=mock_client,
        )
        assert result.allowed is True
        assert result.deny_reason == "ok"
        assert result.error is None

    async def test_opa_returns_false_denied(self) -> None:
        """OPA result=false → allowed=False."""
        from yashigani.mcp._opa import query_filesystem_tool_allowed
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": False}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        result = await query_filesystem_tool_allowed(
            opa_url="http://localhost:8181",
            tool_name="write_file",
            tool_args={"path": "workspace/secret.txt", "content": "bad"},
            http_client=mock_client,
        )
        assert result.allowed is False
        assert result.deny_reason == "fs_tool_not_permitted"
        assert result.error is None

    async def test_opa_returns_null_denied_fail_closed(self) -> None:
        """OPA result=null (undefined rule) → allowed=False, fail-closed."""
        from yashigani.mcp._opa import query_filesystem_tool_allowed
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": None}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        result = await query_filesystem_tool_allowed(
            opa_url="http://localhost:8181",
            tool_name="read_file",
            tool_args={"path": "workspace/ok.txt"},
            http_client=mock_client,
        )
        assert result.allowed is False, "Undefined OPA result must be fail-closed"

    async def test_opa_timeout_fail_closed(self) -> None:
        """OPA timeout → allowed=False, deny_reason=fs_opa_timeout."""
        import httpx
        from yashigani.mcp._opa import query_filesystem_tool_allowed

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        result = await query_filesystem_tool_allowed(
            opa_url="http://localhost:8181",
            tool_name="read_file",
            tool_args={"path": "workspace/ok.txt"},
            http_client=mock_client,
        )
        assert result.allowed is False
        assert result.deny_reason == "fs_opa_timeout"
        assert result.error is not None

    async def test_opa_unreachable_fail_closed(self) -> None:
        """OPA connection error → allowed=False, deny_reason=fs_opa_unreachable."""
        import httpx
        from yashigani.mcp._opa import query_filesystem_tool_allowed

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("connection refused")
        )

        result = await query_filesystem_tool_allowed(
            opa_url="http://localhost:8181",
            tool_name="read_file",
            tool_args={"path": "workspace/ok.txt"},
            http_client=mock_client,
        )
        assert result.allowed is False
        assert result.deny_reason == "fs_opa_unreachable"

    async def test_path_normalisation_before_opa(self) -> None:
        """
        FIX-P3-001: encoded path traversal is decoded before the OPA call.
        The OPA request body should contain the decoded path, not the encoded one.
        """
        from yashigani.mcp._opa import query_filesystem_tool_allowed
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": False}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        await query_filesystem_tool_allowed(
            opa_url="http://localhost:8181",
            tool_name="read_file",
            tool_args={"path": "..%2fetc%2fshadow"},
            http_client=mock_client,
        )

        # Inspect the JSON payload sent to OPA
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs.args[1]
        sent_path = payload["input"]["tool"]["args"]["path"]
        assert "%" not in sent_path or "%2" not in sent_path.lower(), (
            f"Encoded traversal must be decoded before OPA query; got path={sent_path!r}"
        )
        assert "../" in sent_path, (
            f"Decoded traversal must appear in normalised path; got: {sent_path!r}"
        )


# ===========================================================================
# C. McpBroker.enforce() second gate (FIX-P3-ENFORCE)
# ===========================================================================

def _make_p384_key():
    return ec.generate_private_key(SECP384R1())


def _make_opa_allow():
    from yashigani.mcp._opa import OpaDecisionResult
    return OpaDecisionResult(
        allow=True,
        deny_reason="ok",
        redact_args=set(),
        audit_capture=True,
        rate_limit_key=None,
        elapsed_ms=5,
    )


def _make_opa_deny(reason: str = "tool_not_in_exposed_allowlist"):
    from yashigani.mcp._opa import OpaDecisionResult
    return OpaDecisionResult(
        allow=False,
        deny_reason=reason,
        redact_args=set(),
        audit_capture=True,
        rate_limit_key=None,
        elapsed_ms=5,
    )


def _make_fs_allow():
    from yashigani.mcp._opa import FsToolDecisionResult
    return FsToolDecisionResult(allowed=True, deny_reason="ok", elapsed_ms=3)


def _make_fs_deny(reason: str = "fs_tool_not_permitted"):
    from yashigani.mcp._opa import FsToolDecisionResult
    return FsToolDecisionResult(allowed=False, deny_reason=reason, elapsed_ms=3)


def _make_broker(is_filesystem_agent: bool = False):
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp._jwt import McpJwtIssuer, McpJwtVerifier
    from yashigani.mcp._nonce import InMemoryNonceStore
    key = _make_p384_key()
    issuer = McpJwtIssuer(tenant_id="tenant1", private_key=key, chain_max_depth=3)
    verifier = McpJwtVerifier.from_issuer(issuer)
    with patch.object(logging.getLogger("yashigani.mcp._nonce"), "warning"):
        nonce_store = InMemoryNonceStore()
    config = McpBrokerConfig(
        opa_url="http://localhost:8181",
        tenant_id="tenant1",
        issuer=issuer,
        verifier=verifier,
        nonce_store=nonce_store,
        audit_writer=None,
        is_filesystem_agent=is_filesystem_agent,
    )
    return McpBroker(config)


def _make_fs_call_context(tool_name: str = "read_file", args: Optional[dict] = None):
    from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
    posture = McpPosture("mcp-b")
    binding = PostureBinding.for_posture(posture)
    return McpCallContext(
        tenant_id="tenant1",
        posture=posture,
        posture_binding=binding,
        action="mcp.tools.call",
        tool_name=tool_name,
        tool_args_redacted=args or {"path": "workspace/data.txt"},
        agent_name="filesystem",
        user_id="user1",
        upstream_chain=[],
        upstream_jwt=None,
    )


class TestBrokerFilesystemGate:
    """FIX-P3-ENFORCE: broker second OPA gate for is_filesystem_agent=True."""

    async def test_non_fs_broker_does_not_query_second_gate(self) -> None:
        """
        A broker with is_filesystem_agent=False never calls
        query_filesystem_tool_allowed, even when OPA approves.
        """
        broker = _make_broker(is_filesystem_agent=False)
        ctx = _make_fs_call_context()

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_make_opa_allow()),
        ), patch(
            "yashigani.mcp.broker.query_filesystem_tool_allowed",
            new=AsyncMock(return_value=_make_fs_deny()),
        ) as mock_fs:
            decision = await broker.enforce(ctx)

        mock_fs.assert_not_called()
        # Non-FS broker should allow since OPA allows
        assert decision.allow is True, (
            "Non-filesystem broker must not apply the second gate"
        )

    async def test_fs_broker_second_gate_queried_on_opa_allow(self) -> None:
        """
        A broker with is_filesystem_agent=True calls query_filesystem_tool_allowed
        after query_mcp_decision returns allow=True.
        """
        broker = _make_broker(is_filesystem_agent=True)
        ctx = _make_fs_call_context()

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_make_opa_allow()),
        ), patch(
            "yashigani.mcp.broker.query_filesystem_tool_allowed",
            new=AsyncMock(return_value=_make_fs_allow()),
        ) as mock_fs:
            decision = await broker.enforce(ctx)

        mock_fs.assert_called_once()
        assert decision.allow is True

    async def test_fs_broker_second_gate_deny_blocks_tool(self) -> None:
        """
        FIX-P3-ENFORCE (pivotal): when second gate denies, call is blocked
        even though mcp_decision said allow.
        """
        broker = _make_broker(is_filesystem_agent=True)
        ctx = _make_fs_call_context(tool_name="write_file", args={"path": "workspace/x.txt"})

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_make_opa_allow()),
        ), patch(
            "yashigani.mcp.broker.query_filesystem_tool_allowed",
            new=AsyncMock(return_value=_make_fs_deny("fs_tool_not_permitted")),
        ):
            decision = await broker.enforce(ctx)

        assert decision.allow is False, (
            "Filesystem second gate deny MUST block the call (Iris F2)"
        )
        assert decision.deny_reason == "fs_tool_not_permitted"
        assert decision.issued_jwt is None

    async def test_fs_broker_first_gate_deny_skips_second_gate(self) -> None:
        """
        When mcp_decision denies, the second gate is NOT queried
        (early-exit on first deny).
        """
        broker = _make_broker(is_filesystem_agent=True)
        ctx = _make_fs_call_context()

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_make_opa_deny()),
        ), patch(
            "yashigani.mcp.broker.query_filesystem_tool_allowed",
            new=AsyncMock(return_value=_make_fs_allow()),
        ) as mock_fs:
            decision = await broker.enforce(ctx)

        mock_fs.assert_not_called()
        assert decision.allow is False
        assert decision.deny_reason == "tool_not_in_exposed_allowlist"

    async def test_fs_broker_second_gate_traversal_denied(self) -> None:
        """
        FIX-P3-001 + FIX-P3-ENFORCE: encoded traversal in path is denied by
        second gate (deny_reason starts with fs_).
        """
        broker = _make_broker(is_filesystem_agent=True)
        ctx = _make_fs_call_context(
            tool_name="read_file",
            args={"path": "..%2fetc%2fshadow"},  # encoded traversal
        )

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_make_opa_allow()),
        ), patch(
            "yashigani.mcp.broker.query_filesystem_tool_allowed",
            new=AsyncMock(
                return_value=_make_fs_deny("fs_path_traversal_encoded_attempt")
            ),
        ):
            decision = await broker.enforce(ctx)

        assert decision.allow is False
        assert "fs_" in decision.deny_reason

    async def test_fs_broker_paths_array_traversal_denied(self) -> None:
        """
        FIX-P3-002 + FIX-P3-ENFORCE: traversal in paths array blocked.
        """
        broker = _make_broker(is_filesystem_agent=True)
        ctx = _make_fs_call_context(
            tool_name="read_multiple_files",
            args={"paths": ["workspace/ok.txt", "../../../etc/shadow"]},
        )

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_make_opa_allow()),
        ), patch(
            "yashigani.mcp.broker.query_filesystem_tool_allowed",
            new=AsyncMock(
                return_value=_make_fs_deny("fs_paths_array_traversal_attempt")
            ),
        ):
            decision = await broker.enforce(ctx)

        assert decision.allow is False
        assert decision.deny_reason == "fs_paths_array_traversal_attempt"

    async def test_is_filesystem_agent_false_is_default(self) -> None:
        """is_filesystem_agent defaults to False — no second gate for regular agents."""
        from yashigani.mcp.broker import McpBrokerConfig
        from yashigani.mcp._jwt import McpJwtIssuer
        key = _make_p384_key()
        with patch.object(logging.getLogger("yashigani.mcp._nonce"), "warning"):
            from yashigani.mcp._nonce import InMemoryNonceStore
            nonce = InMemoryNonceStore()
        issuer = McpJwtIssuer(tenant_id="t1", private_key=key, chain_max_depth=3)
        config = McpBrokerConfig(
            opa_url="http://localhost:8181",
            tenant_id="t1",
            issuer=issuer,
            nonce_store=nonce,
            audit_writer=None,
        )
        assert config.is_filesystem_agent is False, (
            "is_filesystem_agent must default to False"
        )


# ===========================================================================
# D. Linter M6 placeholder digest (FIX-NICO-001)
# ===========================================================================

_ZEROS_DIGEST = "sha256:" + "0" * 64
_AAAA_DIGEST = "sha256:" + "a" * 64
_VALID_REAL_DIGEST = "sha256:" + "a3b4c5d6" * 8  # 64 hex chars, not all-same

_FS_BASE_PARSED = {
    "apiVersion": "yashigani.io/v1alpha1",
    "kind": "AgentIntegration",
    "metadata": {
        "name": "filesystem",
        "tenant_id": "acme-corp",
    },
    "spec": {
        "image": {
            "repository": "registry.yashigani.internal/bundles/mcp-filesystem",
            "tag": "latest",
            "digest": _VALID_REAL_DIGEST,
        },
    },
}


def _fs_parsed(**image_overrides) -> dict:
    p = copy.deepcopy(_FS_BASE_PARSED)
    p["spec"]["image"].update(image_overrides)
    return p


class TestM6PlaceholderDigest:
    """FIX-NICO-001: linter rejects all-identical-char sha256 digest."""

    def test_zeros_digest_rejected(self) -> None:
        """sha256:000...0 is a placeholder and must be rejected."""
        from yashigani.manifest.linter import validate_manifest
        parsed = _fs_parsed(digest=_ZEROS_DIGEST)
        result = validate_manifest(parsed)
        rules = [e.rule for e in result.errors]
        assert any("M6_image_digest_placeholder" in r for r in rules), (
            f"All-zeros digest must trigger M6_image_digest_placeholder; got: {rules}"
        )

    def test_all_same_hex_digit_rejected(self) -> None:
        """sha256:aaa...a is also a placeholder pattern."""
        from yashigani.manifest.linter import validate_manifest
        parsed = _fs_parsed(digest=_AAAA_DIGEST)
        result = validate_manifest(parsed)
        rules = [e.rule for e in result.errors]
        assert any("M6_image_digest_placeholder" in r for r in rules), (
            f"All-same-hex digest must trigger M6_image_digest_placeholder; got: {rules}"
        )

    def test_real_digest_passes(self) -> None:
        """A real mixed-hex digest does not trigger the placeholder rule."""
        from yashigani.manifest.linter import validate_manifest
        parsed = _fs_parsed(digest=_VALID_REAL_DIGEST)
        result = validate_manifest(parsed)
        placeholder_errors = [
            e for e in result.errors if "M6_image_digest_placeholder" in e.rule
        ]
        assert not placeholder_errors, (
            f"Real digest triggered false-positive: {placeholder_errors}"
        )

    def test_invalid_digest_format_not_placeholder(self) -> None:
        """A digest with invalid format should fire format rule, not placeholder rule."""
        from yashigani.manifest.linter import validate_manifest
        parsed = _fs_parsed(digest="sha256:notvalidhex")
        result = validate_manifest(parsed)
        rules = [e.rule for e in result.errors]
        # Either M6 or M8 fires; must NOT be the placeholder rule
        assert not any("M6_image_digest_placeholder" in r for r in rules), (
            "Invalid-format digest should not trigger placeholder rule"
        )
        assert any("M6" in r or "M8" in r for r in rules), (
            "Invalid digest format should trigger M6 or M8 rule"
        )

    def test_sidecar_placeholder_digest_rejected(self) -> None:
        """Placeholder digest in a sidecar image is also rejected."""
        from yashigani.manifest.linter import validate_manifest
        parsed = copy.deepcopy(_FS_BASE_PARSED)
        parsed["spec"]["sidecars"] = [
            {
                "name": "spiffe-proxy",
                "image": {
                    "repository": "registry.yashigani.internal/spiffe-helper",
                    "tag": "1.0.0",
                    "digest": _ZEROS_DIGEST,
                },
            }
        ]
        result = validate_manifest(parsed)
        rules = [e.rule for e in result.errors]
        assert any("M6_image_digest_placeholder" in r for r in rules), (
            f"Sidecar all-zeros digest must trigger M6_image_digest_placeholder; got: {rules}"
        )

    def test_is_placeholder_digest_function_unit(self) -> None:
        """Unit test _is_placeholder_digest directly."""
        from yashigani.manifest.linter import _is_placeholder_digest
        # Placeholders
        assert _is_placeholder_digest("sha256:" + "0" * 64) is True
        assert _is_placeholder_digest("sha256:" + "a" * 64) is True
        assert _is_placeholder_digest("sha256:" + "f" * 64) is True
        # Non-placeholders
        assert _is_placeholder_digest(_VALID_REAL_DIGEST) is False
        # Invalid format → False (not a placeholder)
        assert _is_placeholder_digest("sha256:notvalidhex") is False
        assert _is_placeholder_digest("not-a-sha256") is False


# ===========================================================================
# E. Codegen: _gen_compose_override_shape_c reads mounts[0].name (FIX-IRIS-F1)
# ===========================================================================

_SC_PARSED_BASE = {
    "apiVersion": "yashigani.io/v1alpha1",
    "kind": "AgentIntegration",
    "metadata": {
        "name": "filesystem",
        "tenant_id": "acme",
    },
    "spec": {
        "image": {
            "repository": "registry.yashigani.internal/bundles/mcp-filesystem",
            "tag": "latest",
            "digest": _VALID_REAL_DIGEST,
        },
        "mcp": {
            "posture": "mcp-b",
            "transport": "stdio",
            "session_mode": "persistent",
            "identity_propagation": "gateway-enforced-only",
            "exposes": {
                "listen_port": None,
            },
        },
        "subprocess": {
            "command": ["node", "index.js"],
            "args": ["/workspace"],
        },
        "network": {"egress_allow": []},
        "secrets": [],
        "storage": {
            "mounts": [
                {
                    "name": "ysg_fs_acme_filesystem_workspace",
                    "type": "volume",
                    "container_path": "/workspace",
                    "read_only": False,
                }
            ],
            "tmpfs": [{"path": "/tmp", "size_limit": "64m"}],
        },
        "lifecycle": {"mode": "persistent"},
        "audit": {
            "capture": ["mcp_call"],
            "sensitivity_ceiling": "INTERNAL",
        },
    },
}


def _sc_engine(parsed=None, runtime="docker"):
    from yashigani.manifest.codegen import CodegenEngineShapeC, reset_codegen_registry
    reset_codegen_registry()
    p = copy.deepcopy(_SC_PARSED_BASE if parsed is None else parsed)
    return CodegenEngineShapeC(p, runtime=runtime)


class TestCodegenShapeCMountName:
    """FIX-IRIS-F1: codegen reads mounts[0].name when provided."""

    def test_declared_vol_name_used_in_compose(self) -> None:
        """When mounts[0].name is set, compose output uses that exact name."""
        artifacts = _sc_engine().render(dry_run=True)
        compose_key = [k for k in artifacts if "compose.override" in k]
        assert compose_key, f"No compose override artifact found; keys: {list(artifacts)}"
        compose = artifacts[compose_key[0]]
        assert "ysg_fs_acme_filesystem_workspace" in compose, (
            "Compose override must use the declared volume name from mounts[0].name"
        )

    def test_declared_vol_name_used_in_volumes_section(self) -> None:
        """The volumes: section at the bottom also uses the declared name."""
        artifacts = _sc_engine().render(dry_run=True)
        compose_key = [k for k in artifacts if "compose.override" in k]
        compose = artifacts[compose_key[0]]
        # The volumes: section should list the declared name
        lines = compose.splitlines()
        volumes_section_lines = []
        in_volumes = False
        for line in lines:
            if line.strip() == "volumes:":
                in_volumes = True
            elif in_volumes:
                volumes_section_lines.append(line)
        volumes_text = "\n".join(volumes_section_lines)
        assert "ysg_fs_acme_filesystem_workspace" in volumes_text, (
            f"volumes: section must reference declared name; got:\n{volumes_text}"
        )

    def test_fallback_when_name_absent(self) -> None:
        """When mounts[0].name is absent, falls back to _sc_volume_name() auto-gen."""
        parsed = copy.deepcopy(_SC_PARSED_BASE)
        # Remove name from mount
        del parsed["spec"]["storage"]["mounts"][0]["name"]

        artifacts = _sc_engine(parsed=parsed).render(dry_run=True)
        compose_key = [k for k in artifacts if "compose.override" in k]
        compose = artifacts[compose_key[0]]
        # Fallback name: ysg_fs_{tenant_id}_{agent_name}_workspace
        assert "ysg_fs_acme_filesystem_workspace" in compose, (
            "Fallback auto-generated name must still match linter tenant-namespace pattern"
        )

    def test_empty_name_falls_back(self) -> None:
        """An empty string for name falls back to auto-gen."""
        parsed = copy.deepcopy(_SC_PARSED_BASE)
        parsed["spec"]["storage"]["mounts"][0]["name"] = ""

        artifacts = _sc_engine(parsed=parsed).render(dry_run=True)
        compose_key = [k for k in artifacts if "compose.override" in k]
        compose = artifacts[compose_key[0]]
        # Auto-gen name should appear (empty string is falsy → fallback)
        assert "ysg_fs_acme_filesystem_workspace" in compose, (
            "Empty mount name must fall back to auto-generated name"
        )

    def test_declared_name_differs_from_autogen(self) -> None:
        """When declared name differs from auto-gen, codegen uses declared name."""
        parsed = copy.deepcopy(_SC_PARSED_BASE)
        # Use a custom name (still satisfies linter prefix pattern)
        custom_name = "ysg_fs_acme_custom_volume_name"
        parsed["spec"]["storage"]["mounts"][0]["name"] = custom_name

        artifacts = _sc_engine(parsed=parsed).render(dry_run=True)
        compose_key = [k for k in artifacts if "compose.override" in k]
        compose = artifacts[compose_key[0]]
        assert custom_name in compose, (
            f"Declared custom volume name {custom_name!r} must appear in compose output"
        )
        # The auto-generated name should NOT appear
        assert "ysg_fs_acme_filesystem_workspace" not in compose, (
            "Auto-generated name must NOT appear when a declared name is provided"
        )


# ===========================================================================
# F. Nico-002: CertMount(spiffe_identity=resolve_spiffe_uri(fs_manifest))
# ===========================================================================

class TestNico002CertMountSpiffeUri:
    """
    NICO-002 contract: CertMount(spiffe_identity=resolve_spiffe_uri(filesystem_manifest))
    must not raise ValueError — the resolved SPIFFE URI matches the required prefix.
    """

    def test_fs_manifest_spiffe_uri_matches_cert_mount_prefix(self) -> None:
        """
        resolve_spiffe_uri(filesystem_manifest) produces a URI that satisfies
        CertMount's prefix validation (spiffe://yashigani.internal/agents/).
        """
        from yashigani.manifest import resolve_spiffe_uri
        from yashigani.pool.manager import CertMount

        parsed = copy.deepcopy(_FS_BASE_PARSED)
        parsed["metadata"]["name"] = "filesystem"
        parsed["metadata"]["tenant_id"] = "acme-corp"

        spiffe_id = resolve_spiffe_uri(parsed)
        assert spiffe_id.startswith("spiffe://yashigani.internal/agents/"), (
            f"Filesystem manifest SPIFFE URI must start with required prefix; got: {spiffe_id!r}"
        )

        # CertMount.__post_init__ validates the prefix — must not raise
        try:
            cm = CertMount(
                host_cert_path="/run/secrets/client.crt",
                host_key_path="/run/secrets/client.key",
                host_ca_path="/run/secrets/ca.crt",
                spiffe_identity=spiffe_id,
            )
        except ValueError as exc:
            pytest.fail(
                f"CertMount raised ValueError with filesystem SPIFFE URI {spiffe_id!r}: {exc}"
            )
        assert cm.spiffe_identity == spiffe_id

    def test_spiffe_uri_contains_tenant_and_agent_name(self) -> None:
        """Resolved URI encodes tenant_id and name in the path."""
        from yashigani.manifest import resolve_spiffe_uri

        parsed = copy.deepcopy(_FS_BASE_PARSED)
        parsed["metadata"]["name"] = "filesystem"
        parsed["metadata"]["tenant_id"] = "acme-corp"

        spiffe_id = resolve_spiffe_uri(parsed)
        assert "acme-corp" in spiffe_id or "acme_corp" in spiffe_id, (
            f"tenant_id must appear in SPIFFE URI; got: {spiffe_id!r}"
        )
        assert "filesystem" in spiffe_id, (
            f"agent name must appear in SPIFFE URI; got: {spiffe_id!r}"
        )

    def test_cert_mount_empty_spiffe_allowed(self) -> None:
        """CertMount with empty spiffe_identity is still valid (non-agent pool containers)."""
        from yashigani.pool.manager import CertMount
        cm = CertMount(
            host_cert_path="/tmp/client.crt",
            host_key_path="/tmp/client.key",
            host_ca_path="/tmp/ca.crt",
            spiffe_identity="",
        )
        assert cm.spiffe_identity == ""

    def test_cert_mount_wrong_prefix_raises(self) -> None:
        """CertMount rejects SPIFFE URI that does not match the agents/ prefix."""
        from yashigani.pool.manager import CertMount
        with pytest.raises(ValueError, match="spiffe://yashigani.internal/agents/"):
            CertMount(
                host_cert_path="/tmp/client.crt",
                host_key_path="/tmp/client.key",
                host_ca_path="/tmp/ca.crt",
                spiffe_identity="spiffe://yashigani.internal/services/fake",
            )
