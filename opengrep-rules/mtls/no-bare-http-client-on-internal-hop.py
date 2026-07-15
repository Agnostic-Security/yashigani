"""
opengrep test fixture for no-bare-http-client-on-internal-hop.

Run via: opengrep test opengrep-rules/mtls/

Path filters (paths.include in the sibling rule file) are NOT applied in
test mode -- this file validates pattern correctness only. The
paths.include scoping (restricting the rule to the real closed set of
Ollama-mesh consumer modules) is exercised separately by the CI opengrep
scan step against the real source tree.
"""
import httpx
import requests

from yashigani.inspection._ollama_transport import (
    ollama_async_client,
    ollama_get_json,
    ollama_post_json,
    ollama_sync_client,
)


def bare_async_client_positive():
    async def _inner():
        # ruleid: no-bare-http-client-on-internal-hop
        async with httpx.AsyncClient(timeout=10.0) as client:
            return await client.get("https://caddy:11435/ollama/api/tags")
    return _inner


def bare_sync_client_positive():
    # ruleid: no-bare-http-client-on-internal-hop
    with httpx.Client(timeout=5.0) as client:
        return client.get("https://caddy:11435/ollama/api/tags")


def bare_httpx_get_positive(base_url):
    # ruleid: no-bare-http-client-on-internal-hop
    return httpx.get(f"{base_url}/api/tags", timeout=5.0)


def bare_httpx_post_positive(base_url, payload):
    # ruleid: no-bare-http-client-on-internal-hop
    return httpx.post(f"{base_url}/api/generate", json=payload)


def bare_requests_get_positive(base_url):
    # ruleid: no-bare-http-client-on-internal-hop
    return requests.get(f"{base_url}/api/tags", timeout=5.0)


def bare_requests_session_positive():
    # ruleid: no-bare-http-client-on-internal-hop
    return requests.Session()


def wrapper_get_json_negative(base_url):
    # ok: no-bare-http-client-on-internal-hop
    return ollama_get_json(base_url, "/api/tags", timeout=5.0)


def wrapper_post_json_negative(base_url, payload):
    # ok: no-bare-http-client-on-internal-hop
    return ollama_post_json(base_url, "/api/generate", payload)


def wrapper_sync_client_negative(base_url):
    # ok: no-bare-http-client-on-internal-hop
    with ollama_sync_client(base_url, timeout=10.0) as client:
        return client.get(f"{base_url}/api/tags")


async def wrapper_async_client_negative(base_url):
    # ok: no-bare-http-client-on-internal-hop
    async with ollama_async_client(base_url, timeout=10.0) as client:
        return await client.get(f"{base_url}/api/tags")
