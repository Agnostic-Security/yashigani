# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""`/api/embed` route + response shape — YSG-RISK-289.

The shim served `/api/embeddings` (legacy) but not `/api/embed` (>= 0.5.x),
which is the endpoint the Yashigani gateway actually calls. Repointing
OLLAMA_BASE_URL at the shim would therefore 404 here and surface as 502 to
every /v1/embeddings caller.

The contract under test is the CALLER's, read off
`src/yashigani/gateway/openai_router.py`: it POSTs {model, input} and reads
`resp_json["embeddings"]` as a list-of-float-lists plus `resp_json["model"]`.
"""

from __future__ import annotations

from kuroshio.shim.embeddings import translate_embeddings_request


def _embed_resp(*args, **kwargs):  # noqa: ANN002,ANN003,ANN202
    # Imported lazily so a missing symbol fails THIS test rather than module
    # collection — a collection error masks whether each test discriminates.
    from kuroshio.shim.embeddings import translate_embed_response

    return translate_embed_response(*args, **kwargs)


def test_embed_request_accepts_a_string_input() -> None:
    assert translate_embeddings_request({"model": "m", "input": "hello"}) == {"content": "hello"}


def test_embed_request_accepts_a_list_input() -> None:
    assert translate_embeddings_request({"model": "m", "input": ["a", "b"]}) == {
        "content": ["a", "b"]
    }


def test_embed_response_is_always_plural_even_for_one_vector() -> None:
    """The caller reads resp_json["embeddings"]; the singular shape sends it
    down its legacy-fallback branch for no reason."""
    out = _embed_resp({"embedding": [0.1, 0.2]}, model="m")
    assert out == {"model": "m", "embeddings": [[0.1, 0.2]]}


def test_embed_response_batches_a_list_from_llama_server() -> None:
    out = _embed_resp(
        [{"embedding": [1.0]}, {"embedding": [2.0]}, {"embedding": [3.0]}], model="m"
    )
    assert out == {"model": "m", "embeddings": [[1.0], [2.0], [3.0]]}


def test_embed_response_passes_through_an_already_plural_body() -> None:
    out = _embed_resp({"embeddings": [[1.0], [2.0]]}, model="m")
    assert out == {"model": "m", "embeddings": [[1.0], [2.0]]}


def test_embed_response_echoes_the_requested_model_name() -> None:
    """The caller does resp_json.get("model", selected_model) — echo it back."""
    assert _embed_resp({"embedding": []}, model="qwen2.5:1.5b")["model"] == (
        "qwen2.5:1.5b"
    )


def test_embed_response_never_returns_the_singular_key() -> None:
    for body in ({"embedding": [1.0]}, [{"embedding": [1.0]}], {"embeddings": [[1.0]]}):
        out = _embed_resp(body, model="m")
        assert "embedding" not in out
        assert isinstance(out["embeddings"], list)
        assert all(isinstance(v, list) for v in out["embeddings"])


def test_api_embed_route_is_registered() -> None:
    """The whole defect: the route did not exist."""
    from kuroshio import app as app_module

    src = __import__("inspect").getsource(app_module.create_app)
    assert '@app.post("/api/embed")' in src, (
        "the gateway calls /api/embed; without the route the cutover 502s "
        "every /v1/embeddings request (YSG-RISK-289)"
    )
    assert '@app.post("/api/embeddings")' in src, "legacy route must remain for older callers"
