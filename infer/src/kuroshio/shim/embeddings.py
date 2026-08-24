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


__all__ = ["translate_embeddings_request", "translate_embeddings_response"]
