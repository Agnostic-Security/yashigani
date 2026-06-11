"""
Langflow adapter for the Yashigani gateway.

Langflow is a visual workflow builder. It requires:
1. Auto-login to get a bearer token
2. Create an API key for subsequent calls
3. Create a default chat flow (or use an existing one)
4. Route messages via POST /api/v1/run/{flow_id}
5. Convert Langflow response to OpenAI ChatCompletionResponse
"""

import json
import logging
import os
import uuid

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal service-mesh Bearer token
#
# YASHIGANI_INTERNAL_BEARER is a per-install-rotated secret injected into
# the Langflow flow template so it can call back through the Yashigani
# gateway as an internal service. It MUST be set by the installer
# (docker/secrets/yashigani_internal_bearer).  A missing or empty value
# fails closed at import time.
# ---------------------------------------------------------------------------

def _load_internal_bearer() -> str:
    """Read YASHIGANI_INTERNAL_BEARER from env; raise RuntimeError if absent."""
    _val = os.environ.get("YASHIGANI_INTERNAL_BEARER", "")
    if not _val:
        raise RuntimeError(
            "YASHIGANI_INTERNAL_BEARER is not set. "
            "The gateway cannot start without a per-install internal service token. "
            "See docker/secrets/yashigani_internal_bearer."
        )
    return _val


# Cached at module load — fails fast if env-var is absent.
_INTERNAL_BEARER: str = _load_internal_bearer()

# ---------------------------------------------------------------------------
# LLM routing for the default "Yashigani Chat" flow
#
# Langflow runs on the `langflow_isolated` compose network and CANNOT reach the
# Ollama container directly (ollama lives on `data`/`edge`; they share no
# network — see YSG-RISK-055 UA-10, which moved langflow off `data`).  The only
# LLM surface langflow can reach is the Yashigani gateway's internal mesh port
# (gateway:8081/v1), which the gateway also joins on `langflow_isolated`.
#
# That mesh port speaks the OpenAI-compatible protocol (/v1/chat/completions)
# and is authed with the per-install internal bearer, which the langflow
# container's entrypoint exports as OPENAI_API_KEY (and OPENAI_API_BASE points
# at the same gateway mesh endpoint).
#
# Therefore the default flow MUST use langflow's OpenAIModel component pointing
# at the gateway mesh endpoint — NOT the LanguageModelComponent with the Ollama
# provider, which has no reachable upstream and which (with no provider set)
# fails at run time with HTTP 500 "Unknown API key is required when using
# Unknown provider".  Verified end-to-end against langflow 1.9.2 (2026-06-10):
# OpenAIModel(model_name=qwen2.5:3b, openai_api_base=gateway:8081/v1,
# api_key=OPENAI_API_KEY) returns a real chat completion.
# ---------------------------------------------------------------------------

# Gateway internal mesh endpoint (plain HTTP, OpenAI-compatible, reachable from
# langflow_isolated). Overridable for non-compose topologies.
_GATEWAY_MESH_BASE_URL: str = os.environ.get(
    "YASHIGANI_LANGFLOW_LLM_BASE_URL", "http://gateway:8081/v1"
)
# Default model served by the gateway mesh endpoint.
_DEFAULT_MODEL: str = os.environ.get("YASHIGANI_LANGFLOW_MODEL", "qwen2.5:3b")
# SecretStrInput sentinel: langflow resolves this env-var name at run time to
# the internal bearer (exported as OPENAI_API_KEY by langflow's entrypoint).
_API_KEY_ENV_REF: str = "OPENAI_API_KEY"

# The component "type" the runnable default flow must use.
_TARGET_NODE_TYPE: str = "OpenAIModel"
# The (broken) component type shipped by the "Basic Prompting" starter template.
_STARTER_NODE_TYPE: str = "LanguageModelComponent"

# Cached state after first initialization
_api_key: str | None = None
_flow_id: str | None = None
_initialized = False
# Cached OpenAIModel component template fetched from langflow /api/v1/all.
_openai_component: dict | None = None


async def _fetch_openai_component(
    client: httpx.AsyncClient, base_url: str, api_headers: dict
) -> dict:
    """Fetch and cache langflow's OpenAIModel component node template.

    The node template (template + outputs + metadata) is needed to convert a
    LanguageModelComponent node into a runnable OpenAIModel node.  Cached for
    the process lifetime — langflow's component catalogue is static per image.
    """
    global _openai_component
    if _openai_component is not None:
        return _openai_component

    resp = await client.get(f"{base_url}/api/v1/all", headers=api_headers)
    if resp.status_code != 200:
        raise RuntimeError(
            f"Langflow /api/v1/all failed: {resp.status_code}"
        )

    def _find(node: object, target: str) -> dict | None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == target and isinstance(value, dict):
                    return value
                found = _find(value, target)
                if found is not None:
                    return found
        return None

    component = _find(resp.json(), _TARGET_NODE_TYPE)
    if not component or "template" not in component:
        raise RuntimeError(
            f"Langflow component catalogue has no usable {_TARGET_NODE_TYPE} node"
        )
    # Deep copy so per-flow value mutations never poison the cache.
    _openai_component = json.loads(json.dumps(component))
    return _openai_component


def _configure_openai_component(component: dict) -> dict:
    """Return a copy of the OpenAIModel component configured for the gateway."""
    component = json.loads(json.dumps(component))
    template = component.get("template", {})

    def _set(field: str, value: object) -> None:
        slot = template.get(field)
        if isinstance(slot, dict):
            slot["value"] = value

    _set("model_name", _DEFAULT_MODEL)
    _set("openai_api_base", _GATEWAY_MESH_BASE_URL)
    _set("api_key", _API_KEY_ENV_REF)
    _set("stream", False)
    return component


def _lm_node_is_healthy(node_data: dict) -> bool:
    """True if the flow's model node is already a gateway-pointed OpenAIModel.

    Used by the self-heal path to decide, idempotently, whether an
    already-persisted flow needs repair.
    """
    if node_data.get("type") != _TARGET_NODE_TYPE:
        return False
    template = node_data.get("node", {}).get("template", {})
    base = template.get("openai_api_base", {})
    base_val = base.get("value") if isinstance(base, dict) else base
    return base_val == _GATEWAY_MESH_BASE_URL


async def _repair_flow_data(
    client: httpx.AsyncClient, base_url: str, api_headers: dict, flow_data: dict
) -> bool:
    """Convert the flow's model node to a gateway-pointed OpenAIModel in place.

    Finds the model node (either the broken LanguageModelComponent from the
    starter template, or an already-present OpenAIModel) and rewrites it to a
    runnable OpenAIModel pointing at the gateway mesh endpoint.  Edge handles
    that embed the old component type string are rewritten too — the relevant
    field names (input_value, system_message, text_output) are identical
    between the two components, so connectivity is preserved.

    Returns True if a change was made, False if the flow was already healthy.
    Idempotent and safe to call repeatedly.
    """
    nodes = flow_data.get("nodes", [])
    model_node = None
    old_type = None
    for node in nodes:
        node_data = node.get("data", {})
        node_type = node_data.get("type")
        if node_type in (_STARTER_NODE_TYPE, _TARGET_NODE_TYPE):
            model_node = node_data
            old_type = node_type
            break

    if model_node is None:
        # No model node we recognise — nothing safe to do.
        return False

    if old_type == _TARGET_NODE_TYPE and _lm_node_is_healthy(model_node):
        return False  # already healthy — idempotent no-op

    component = await _fetch_openai_component(client, base_url, api_headers)
    model_node["type"] = _TARGET_NODE_TYPE
    model_node["node"] = _configure_openai_component(component)

    if old_type and old_type != _TARGET_NODE_TYPE:
        # Rewrite ONLY the structural reference fields that embed the old
        # component-type string (node ids + the edge source/target/handle fields
        # that reference them). Scoped — not a global blob replace — so a
        # user-authored value (e.g. a prompt that mentions the type name) can
        # never be silently rewritten (Laura NICE-TO-HAVE #1).
        _rewrite_type_references(flow_data, old_type, _TARGET_NODE_TYPE)

    return True


def _rewrite_type_references(flow_data: dict, old_type: str, new_type: str) -> None:
    """Replace ``old_type`` with ``new_type`` only in structural ref fields.

    React-Flow flow data embeds a node's component type in its ``id`` (e.g.
    ``LanguageModelComponent-ab12c``) and in the edges that reference it via
    ``source``/``target`` (the node id) and ``sourceHandle``/``targetHandle``
    (a serialized handle object whose ``id``/``dataType``/``name`` carry the type
    string). We rewrite ONLY those fields, never free-text node ``value`` slots,
    so a user-authored value containing the substring is left untouched.
    """
    def _sub(val: object) -> object:
        # Replace inside a handle string or a nested handle dict; leave other
        # scalar types untouched.
        if isinstance(val, str):
            return val.replace(old_type, new_type)
        if isinstance(val, dict):
            return {k: _sub(v) for k, v in val.items()}
        return val

    for node in flow_data.get("nodes", []):
        if isinstance(node, dict) and isinstance(node.get("id"), str):
            node["id"] = node["id"].replace(old_type, new_type)

    for edge in flow_data.get("edges", []):
        if not isinstance(edge, dict):
            continue
        for ref_field in ("source", "target", "sourceHandle", "targetHandle"):
            if ref_field in edge:
                edge[ref_field] = _sub(edge[ref_field])
        # React-Flow also mirrors the handles under edge["data"].
        edge_data = edge.get("data")
        if isinstance(edge_data, dict):
            for ref_field in ("sourceHandle", "targetHandle"):
                if ref_field in edge_data:
                    edge_data[ref_field] = _sub(edge_data[ref_field])


async def _ensure_initialized(client: httpx.AsyncClient, base_url: str) -> tuple[str, str]:
    """Initialize Langflow: auto-login, get API key, find or create flow."""
    global _api_key, _flow_id, _initialized
    if _initialized and _api_key and _flow_id:
        return _api_key, _flow_id

    # Step 1: Auto-login to get bearer token
    resp = await client.get(f"{base_url}/api/v1/auto_login")
    if resp.status_code != 200:
        raise RuntimeError(f"Langflow auto_login failed: {resp.status_code}")

    token_data = resp.json()
    bearer_token = token_data.get("access_token", "")
    if not bearer_token:
        raise RuntimeError("Langflow auto_login returned no access_token")

    auth_headers = {"Authorization": f"Bearer {bearer_token}"}

    # Step 2: Create or get API key
    # Always create a fresh API key — existing keys are masked and unusable
    resp = await client.post(
        f"{base_url}/api/v1/api_key/",
        json={"name": "yashigani-gateway"},
        headers=auth_headers,
    )
    if resp.status_code in (200, 201):
        _api_key = resp.json().get("api_key", "")

    if not _api_key:
        raise RuntimeError("Langflow: could not create API key")

    # Step 3: Find or create a chat flow
    api_headers = {"x-api-key": _api_key}

    # Check for existing user flows
    resp = await client.get(f"{base_url}/api/v1/flows/", headers=api_headers)
    existing_flow = None
    if resp.status_code == 200:
        flows = resp.json()
        for flow in flows:
            if flow.get("name") == "Yashigani Chat" and flow.get("user_id"):
                existing_flow = flow
                _flow_id = flow["id"]
                logger.info("Langflow: found existing flow %s", _flow_id)
                break

    if existing_flow is not None:
        # Self-heal: flows persisted by earlier gateway versions used the
        # LanguageModelComponent + (unset) Ollama provider, which is
        # structurally unrunnable (langflow can't reach ollama; the model node
        # has no provider). Repair the persisted flow in place so existing
        # deployments recover without a fresh install. Idempotent: a no-op once
        # the node is already a gateway-pointed OpenAIModel.
        flow_data = existing_flow.get("data") or {}
        try:
            changed = await _repair_flow_data(
                client, base_url, api_headers, flow_data
            )
            if changed:
                patch = await client.patch(
                    f"{base_url}/api/v1/flows/{_flow_id}",
                    json={"data": flow_data},
                    headers=api_headers,
                )
                if patch.status_code in (200, 201):
                    logger.info(
                        "Langflow: self-healed flow %s -> OpenAIModel via %s",
                        _flow_id,
                        _GATEWAY_MESH_BASE_URL,
                    )
                else:
                    logger.warning(
                        "Langflow: self-heal PATCH of flow %s failed: %s",
                        _flow_id,
                        patch.status_code,
                    )
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
            # Self-heal is best-effort: a healthy flow still runs. Log and
            # continue rather than blocking initialization of a working flow.
            logger.warning("Langflow: self-heal of flow %s failed: %s", _flow_id, exc)

    if not _flow_id:
        # Find the "Basic Prompting" starter flow and convert its model node to
        # a gateway-pointed OpenAIModel so the new flow is runnable.
        starter_data = None
        if resp.status_code == 200:
            for flow in flows:
                if "basic prompting" in flow.get("name", "").lower():
                    starter_data = flow.get("data", {})
                    break

        if starter_data:
            await _repair_flow_data(client, base_url, api_headers, starter_data)

        flow_body = {
            "name": "Yashigani Chat",
            "description": (
                "Default chat flow for Yashigani gateway — OpenAIModel via "
                "gateway mesh endpoint (OpenAI-compatible)"
            ),
            "endpoint_name": "yashigani-chat",
        }
        if starter_data:
            flow_body["data"] = starter_data

        resp = await client.post(
            f"{base_url}/api/v1/flows/",
            json=flow_body,
            headers=api_headers,
        )
        if resp.status_code in (200, 201):
            _flow_id = resp.json().get("id", "")
            logger.info(
                "Langflow: created flow %s with OpenAIModel/gateway config", _flow_id
            )
        else:
            raise RuntimeError(f"Langflow flow creation failed: {resp.status_code}")

    _initialized = True
    return _api_key, _flow_id


async def langflow_chat(
    base_url: str,
    messages: list[dict],
    timeout: float = 120.0,
) -> dict:
    """
    Send messages to Langflow and return an OpenAI-compatible response.

    Args:
        base_url: Langflow upstream URL (e.g., http://langflow:7860)
        messages: List of {"role": ..., "content": ...} dicts
        timeout: Request timeout in seconds

    Returns:
        OpenAI ChatCompletionResponse-shaped dict
    """
    # Extract the last user message as input
    user_message = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            user_message = m.get("content", "")
            break
    if not user_message:
        user_message = messages[-1].get("content", "") if messages else ""

    async with httpx.AsyncClient(timeout=timeout) as client:
        api_key, flow_id = await _ensure_initialized(client, base_url)

        resp = await client.post(
            f"{base_url}/api/v1/run/{flow_id}",
            json={
                "input_value": user_message,
                "output_type": "chat",
                "input_type": "chat",
            },
            headers={"x-api-key": api_key},
        )

        if resp.status_code in (403, 500):
            # 403: API key may be stale.
            # 500: the persisted flow may be structurally broken (e.g. an
            #      unrunnable model node from an earlier gateway version that
            #      slipped past init-time self-heal).
            # Either way: reset cache, re-init (which re-runs the self-heal /
            # repair path), and retry once.
            global _api_key, _flow_id, _initialized
            _api_key = None
            _flow_id = None
            _initialized = False
            api_key, flow_id = await _ensure_initialized(client, base_url)
            resp = await client.post(
                f"{base_url}/api/v1/run/{flow_id}",
                json={
                    "input_value": user_message,
                    "output_type": "chat",
                    "input_type": "chat",
                },
                headers={"x-api-key": api_key},
            )

        if resp.status_code != 200:
            raise RuntimeError(f"Langflow run failed: {resp.status_code}")

        data = resp.json()

        # Extract text from Langflow response
        assistant_text = ""
        try:
            outputs = data.get("outputs", [])
            if outputs:
                inner_outputs = outputs[0].get("outputs", [])
                if inner_outputs:
                    results = inner_outputs[0].get("results", {})
                    message = results.get("message", {})
                    assistant_text = message.get("text", "")
        except (IndexError, KeyError, TypeError):
            pass

        if not assistant_text:
            assistant_text = "Langflow returned no output. The flow may need configuration."

    return {
        "id": f"chatcmpl-langflow-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "model": "langflow",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": assistant_text},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
