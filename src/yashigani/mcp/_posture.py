"""
MCP Broker — channel-derived posture enforcement.

YSG-RISK-055 / LAURA-MCP-003 BINDING REQUIREMENT:
  - posture MUST be derived from the physical channel.
  - posture MUST NOT be taken from the request body.
  - mcp-a is assignable ONLY when the transport is a verified local OS pipe.
  - Any network-arriving request is mcp-b or mcp-c.

This module implements posture derivation. The broker calls
derive_posture_from_channel() with the physical transport descriptor;
the JWT claim is then set from the returned PostureBinding.

The skipped OPA policy test test_TRANSPORT_REQUIREMENT_mcp_a_must_be_local_only
is satisfied here — the test in the broker suite verifies this invariant
at the Python broker layer (the invariant cannot be expressed as a pure Rego
assertion because it is a transport-layer property).

v2.25.0 / P1 W3 Phase 2b-ii
"""
from __future__ import annotations

import logging
from typing import Optional

from yashigani.mcp._types import McpPosture, McpTransportKind, PostureBinding

logger = logging.getLogger(__name__)


class PostureDerivationError(ValueError):
    """Raised when posture cannot be safely derived from the channel."""


def derive_posture_from_channel(
    transport_kind: McpTransportKind,
    upstream_chain: Optional[list[str]] = None,
    upstream_jwt_verified: bool = False,
    peer_pid: Optional[int] = None,
    is_local_pipe: bool = False,
) -> tuple[McpPosture, PostureBinding]:
    """
    Derive MCP posture from the physical channel descriptor.

    Parameters
    ----------
    transport_kind:
        The physical transport type. This MUST be set by the transport layer
        from direct observation (socket type, fd type), NEVER from a client
        request body or header claim.

    upstream_chain:
        For mcp-c only: the validated upstream JWT identity.chain (list of
        SPIFFE URI strings). Must be non-empty for mcp-c to be assigned.

    upstream_jwt_verified:
        For mcp-c only: True if the upstream JWT signature has been verified
        against the JWKS of the issuing gateway. mcp-c requires this.

    peer_pid:
        For mcp-a only: the OS-verified peer PID (from /proc or SO_PEERCRED).
        When provided, confirms the channel is a local process.
        When None on a stdio channel, mcp-a is still assigned (the transport
        layer guarantees locality by the fd pair's existence).

    is_local_pipe:
        For mcp-a: True when the transport has confirmed the channel is an OS
        pipe fd pair (isatty(fd)==False and the fd is a pipe). Required to
        assign mcp-a; if False on LOCAL_STDIO transport the call is degraded
        to mcp-b.

    Returns
    -------
    (McpPosture, PostureBinding)

    Raises
    ------
    PostureDerivationError
        If the transport_kind is CHAINED_RELAY but the upstream chain is
        empty or the upstream JWT was not verified.

    Security notes
    --------------
    - mcp-a is only returned when transport_kind==LOCAL_STDIO AND
      is_local_pipe==True. A network-arriving request that somehow has
      transport_kind==LOCAL_STDIO with is_local_pipe==False is downgraded
      to mcp-b (belt-and-suspenders).
    - The caller MUST NOT allow the client to influence transport_kind,
      is_local_pipe, peer_pid, or upstream_chain.
    - Forwarded headers (X-Forwarded-For, X-Forwarded-Proto) MUST be
      stripped by the broker before calling this function.
    """
    if transport_kind == McpTransportKind.CHAINED_RELAY:
        # mcp-c: upstream JWT must be present and verified with a non-empty chain
        if not upstream_jwt_verified:
            raise PostureDerivationError(
                "mcp-c requires upstream JWT signature verification; "
                "upstream_jwt_verified=False. "
                "Falling back to mcp-b. "
                "YSG-RISK-055 / LAURA-MCP-003."
            )
        if not upstream_chain:
            raise PostureDerivationError(
                "mcp-c requires a non-empty upstream identity chain "
                "(identity.chain in the upstream JWT). "
                "YSG-RISK-055 / LAURA-MCP-003."
            )
        # Validate chain elements are all strings (per Nico spec §4 + OPA guard)
        for element in upstream_chain:
            if not isinstance(element, str):
                raise PostureDerivationError(
                    f"identity.chain must be an array of strings; "
                    f"element {element!r} is {type(element).__name__}. "
                    "OPA guard will deny — rejecting before JWT issuance."
                )
        posture = McpPosture.MCP_C
        binding = PostureBinding.for_posture(posture)
        logger.debug(
            "mcp-broker: posture=mcp-c derived from chained relay, chain_depth=%d",
            len(upstream_chain),
        )
        return posture, binding

    if transport_kind == McpTransportKind.LOCAL_STDIO:
        if is_local_pipe:
            posture = McpPosture.MCP_A
            binding = PostureBinding.for_posture(posture)
            logger.debug(
                "mcp-broker: posture=mcp-a derived from local stdio pipe (peer_pid=%s)",
                peer_pid,
            )
            return posture, binding
        else:
            # LOCAL_STDIO transport but is_local_pipe=False → downgrade to mcp-b
            # (defensive: transport layer reported LOCAL_STDIO but couldn't confirm
            # the fd is a pipe — treat as network to avoid mcp-a privilege escalation)
            logger.warning(
                "mcp-broker: LOCAL_STDIO transport but is_local_pipe=False — "
                "downgrading to mcp-b. YSG-RISK-055 defence."
            )
            posture = McpPosture.MCP_B
            binding = PostureBinding.for_posture(posture)
            return posture, binding

    if transport_kind == McpTransportKind.NETWORK_STREAMABLE_HTTP:
        posture = McpPosture.MCP_B
        binding = PostureBinding.for_posture(posture)
        logger.debug("mcp-broker: posture=mcp-b derived from network Streamable-HTTP")
        return posture, binding

    # Unknown transport kind → fail closed to mcp-b
    logger.error(
        "mcp-broker: unknown transport_kind=%r — failing closed to mcp-b. "
        "YSG-RISK-055 defence.",
        transport_kind,
    )
    posture = McpPosture.MCP_B
    binding = PostureBinding.for_posture(posture)
    return posture, binding
