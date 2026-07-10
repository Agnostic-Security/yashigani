"""
OPA Policy Assistant — Rego module compile validator.

Validates a generated Rego module by doing a trial PUT to OPA's policy REST API
in a uniquely-named sandbox slot, then checks the response:

  HTTP 200/204 → compiled successfully  → (True, None)
  HTTP 400     → compile error          → (False, error_message)
  Exception    → OPA unreachable        → (False, error_message)

The sandbox slot is always deleted in the finally block (best-effort cleanup).

Uses internal_httpx_client (mTLS) because OPA lives behind the service mesh.

Last updated: 2026-07-01
"""
from __future__ import annotations

import logging
import os
import uuid
from typing import Optional

logger = logging.getLogger(__name__)


def _opa_base() -> str:
    return os.getenv("YASHIGANI_OPA_URL", "https://policy:8181").rstrip("/")


async def validate_rego_module(
    rego_text: str,
    opa_url: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """
    Validate a Rego module by compiling it against OPA's policy API.

    Args:
        rego_text: The Rego source to validate.
        opa_url:   Override the OPA base URL (defaults to YASHIGANI_OPA_URL env var).

    Returns:
        (is_valid, error_message_or_None)
    """
    # Lazy import: keeps module importable without httpx/pki installed (unit tests)
    from yashigani.pki.client import internal_httpx_client  # noqa: PLC0415

    base = (opa_url or _opa_base()).rstrip("/")
    slot_id = f"clients/_oa_validate_{uuid.uuid4().hex[:12]}"
    put_url = f"{base}/v1/policies/{slot_id}"

    put_resp = None
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            put_resp = await client.put(
                put_url,
                content=rego_text.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
            )
    except Exception as exc:
        logger.error("RegoValidator: OPA PUT failed for slot %s: %s", slot_id, exc)
    finally:
        # Always attempt to clean up the sandbox slot
        try:
            async with internal_httpx_client(timeout=5.0) as client:
                await client.delete(put_url)
        except Exception as exc_cleanup:
            logger.warning(
                "RegoValidator: sandbox cleanup failed for slot %s: %s",
                slot_id, exc_cleanup,
            )

    if put_resp is None:
        return False, "opa_unreachable: could not reach OPA policy API for compile check"

    if put_resp.status_code == 400:
        # OPA returns compile errors as JSON with an "errors" list
        err_msg = "Rego compile error"
        try:
            body = put_resp.json()
            errors = body.get("errors", [])
            if errors:
                # Surface the first error's location + message
                e0 = errors[0]
                loc = e0.get("location", {})
                loc_str = f" (line {loc.get('row', '?')}, col {loc.get('col', '?')})" if loc else ""
                err_msg = f"{e0.get('message', 'compile error')}{loc_str}"
            elif body.get("message"):
                err_msg = body["message"]
        except Exception:
            pass
        logger.warning("RegoValidator: compile error for slot %s: %s", slot_id, err_msg)
        return False, err_msg

    if put_resp.status_code not in (200, 204):
        logger.error(
            "RegoValidator: unexpected OPA status %d for slot %s",
            put_resp.status_code, slot_id,
        )
        return False, f"opa_unexpected_status:{put_resp.status_code}"

    return True, None
