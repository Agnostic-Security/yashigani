# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""`/api/embeddings` translation: ollama request/response <-> llama-server `/embedding`."""

from __future__ import annotations

from typing import Any


def translate_embeddings_request(ollama_request: dict[str, Any]) -> dict[str, Any]:
    """Ollama accepts either `prompt` (legacy `/api/embeddings`) or `input`
    (newer `/api/embed`, str or list[str]) — normalize both into
    llama-server's native `/embedding` `content` field."""
    if "input" in ollama_request:
        content = ollama_request["input"]
    else:
        content = ollama_request.get("prompt", "")
    return {"content": content}


def translate_embeddings_response(llama_response: dict[str, Any] | list[Any]) -> dict[str, Any]:
    """llama-server's native `/embedding` returns either a single
    `{"embedding": [...]}` object or a list of such objects for batch input.
    Ollama's legacy `/api/embeddings` returns a single `{"embedding": [...]}`.
    """
    if isinstance(llama_response, list):
        if len(llama_response) == 1:
            return {"embedding": llama_response[0].get("embedding", [])}
        return {"embeddings": [item.get("embedding", []) for item in llama_response]}
    return {"embedding": llama_response.get("embedding", [])}


def translate_embed_response(
    llama_response: dict[str, Any] | list[Any], *, model: str
) -> dict[str, Any]:
    """Response shape for the NEWER `/api/embed` (ollama >= 0.5.x).

    YSG-RISK-289. `/api/embed` and `/api/embeddings` are different endpoints
    with different response shapes, and the product calls the newer one:
    `gateway/openai_router.py` POSTs `{model, input}` to `/api/embed` and reads
    `resp_json["embeddings"]` as a list-of-float-lists, one per input item,
    plus `resp_json["model"]`. The legacy singular `{"embedding": [...]}` is
    only its fallback, not what it asks for.

    So this always returns the plural list-of-lists, even for a single input —
    that is the contract the caller parses, and collapsing a one-element batch
    to the singular shape would push it down the fallback path for no reason.
    """
    if isinstance(llama_response, list):
        vectors = [item.get("embedding", []) for item in llama_response]
    elif "embeddings" in llama_response:
        vectors = list(llama_response["embeddings"])
    else:
        vectors = [llama_response.get("embedding", [])]
    return {"model": model, "embeddings": vectors}


__all__ = [
    "translate_embeddings_request",
    "translate_embeddings_response",
    "translate_embed_response",
]
