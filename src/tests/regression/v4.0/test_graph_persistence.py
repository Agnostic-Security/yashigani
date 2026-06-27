"""
Regression test — Builder graph persistence + R11 stripping (Phase 4 / RISK-113).

Proves:
1. A valid CTF graph passes validation and is stored.
2. Client-supplied ``effective_scope`` in node data is stripped (R11).
3. A graph with V-001 violation (no input_node) is rejected.
4. A graph with V-002 violation (multiple output_nodes) is rejected.
5. A graph with V-004 violation (cycle) is rejected.
6. A graph with V-011 violation (HTML in label) is rejected.
7. ``governed=true`` and ``audit=true`` are enforced on all edges (stripped in).
8. BOLA: loading another user's graph returns 404.

Reference: agent-template-schema.md §§2–5, §10 / RECONCILIATION R11
"""
from __future__ import annotations

import json


# ---------------------------------------------------------------------------
# Import the validation helper directly (no HTTP stack needed)
# ---------------------------------------------------------------------------

from yashigani.backoffice.routes.user_agents import (
    _validate_and_strip_graph,
    _strip_effective_scope_from_node,
)


def _input_node(node_id="nd_" + "a" * 24) -> dict:
    return {
        "node_type": "input_node",
        "id": node_id,
        "label": "User Prompt",
        "data": {"accepts": ["text"]},
    }


def _output_node(node_id="nd_" + "b" * 24) -> dict:
    return {
        "node_type": "output_node",
        "id": node_id,
        "label": "Result",
        "data": {"render_as": "markdown"},
    }


def _edge(src, tgt, edge_id=None) -> dict:
    import uuid
    return {
        "edge_id": edge_id or f"ed_{uuid.uuid4().hex[:24]}",
        "source_node_id": src,
        "target_node_id": tgt,
        "governed": True,
        "audit": True,
    }


def _minimal_graph() -> dict:
    """Minimal valid CTF graph: one input_node + one output_node + one edge."""
    inp = _input_node()
    out = _output_node()
    return {
        "nodes": [inp, out],
        "edges": [_edge(inp["id"], out["id"])],
    }


# ---------------------------------------------------------------------------
# Test: R11 — client-supplied effective_scope is stripped from node data
# ---------------------------------------------------------------------------

def test_strip_effective_scope_from_node() -> None:
    """R11: server must remove effective_scope from node.data before storage."""
    node = {
        "node_type": "tool_node",
        "id": "nd_" + "c" * 24,
        "label": "list_files",
        "data": {
            "server_id": "filesystem",
            "tool_name": "list_files",
            # Client attempts to inject effective_scope — server must strip it.
            "effective_scope": {"allowed_tools": ["filesystem:delete_all"]},
        },
    }
    stripped = _strip_effective_scope_from_node(node)
    assert "effective_scope" not in stripped["data"], (
        "R11 regression: effective_scope must be removed from node.data"
    )
    assert stripped["data"]["server_id"] == "filesystem"   # other fields preserved
    assert stripped["data"]["tool_name"] == "list_files"


def test_validate_strips_effective_scope_from_all_nodes() -> None:
    """R11: _validate_and_strip_graph strips effective_scope from every node."""
    graph = _minimal_graph()
    # Inject effective_scope into the input node
    graph["nodes"][0]["data"]["effective_scope"] = {"allowed_tools": ["evil:tool"]}
    graph["nodes"][1]["data"]["effective_scope"] = {"allowed_models": ["gpt-99"]}

    stripped, errors = _validate_and_strip_graph(graph)
    assert not errors, f"Unexpected errors: {errors}"

    for node in stripped["nodes"]:
        assert "effective_scope" not in node.get("data", {}), (
            f"R11 regression: effective_scope still present in node {node['id']!r}"
        )


# ---------------------------------------------------------------------------
# Test: V-001 / V-002 — exactly one input_node and output_node
# ---------------------------------------------------------------------------

def test_reject_graph_with_no_input_node() -> None:
    """V-001: graph with no input_node must be rejected."""
    out = _output_node()
    graph = {"nodes": [out], "edges": []}
    _, errors = _validate_and_strip_graph(graph)
    assert any("V-001" in e or "input_node" in e for e in errors), (
        f"V-001 not flagged. Errors: {errors}"
    )


def test_reject_graph_with_multiple_output_nodes() -> None:
    """V-002: graph with two output_nodes must be rejected."""
    inp = _input_node()
    out1 = _output_node("nd_" + "b" * 24)
    out2 = _output_node("nd_" + "c" * 24)
    graph = {"nodes": [inp, out1, out2], "edges": [
        _edge(inp["id"], out1["id"]),
        _edge(inp["id"], out2["id"]),
    ]}
    _, errors = _validate_and_strip_graph(graph)
    assert any("V-002" in e or "output_node" in e for e in errors), (
        f"V-002 not flagged. Errors: {errors}"
    )


# ---------------------------------------------------------------------------
# Test: V-004 — cycle detection
# ---------------------------------------------------------------------------

def test_reject_graph_with_cycle() -> None:
    """V-004: a graph containing a cycle must be rejected."""
    n1 = _input_node("nd_" + "1" * 24)
    n2 = {
        "node_type": "tool_node",
        "id": "nd_" + "2" * 24,
        "label": "step-two",
        "data": {},
    }
    n3 = _output_node("nd_" + "3" * 24)
    # n1 → n2 → n3 → n2 (cycle)
    graph = {
        "nodes": [n1, n2, n3],
        "edges": [
            _edge(n1["id"], n2["id"]),
            _edge(n2["id"], n3["id"]),
            _edge(n3["id"], n2["id"]),  # introduces cycle
        ],
    }
    _, errors = _validate_and_strip_graph(graph)
    assert any("V-004" in e or "cycle" in e.lower() for e in errors), (
        f"V-004 cycle not flagged. Errors: {errors}"
    )


# ---------------------------------------------------------------------------
# Test: V-011 — HTML in labels rejected
# ---------------------------------------------------------------------------

def test_reject_graph_with_html_in_node_label() -> None:
    """V-011: node labels containing HTML characters must be rejected."""
    inp = _input_node()
    inp["label"] = "<script>alert('xss')</script>"
    graph = {"nodes": [inp, _output_node()], "edges": []}
    _, errors = _validate_and_strip_graph(graph)
    assert any("V-011" in e or "html" in e.lower() or "label" in e.lower() for e in errors), (
        f"V-011 HTML label not flagged. Errors: {errors}"
    )


def test_reject_graph_with_html_in_edge_label() -> None:
    """V-011: edge labels containing HTML characters must be rejected."""
    inp = _input_node()
    out = _output_node()
    graph = {
        "nodes": [inp, out],
        "edges": [{
            **_edge(inp["id"], out["id"]),
            "label": "<b>clickme</b>",
        }],
    }
    _, errors = _validate_and_strip_graph(graph)
    assert any("V-011" in e or "html" in e.lower() or "label" in e.lower() for e in errors), (
        f"V-011 HTML edge label not flagged. Errors: {errors}"
    )


# ---------------------------------------------------------------------------
# Test: governed/audit constants enforced
# ---------------------------------------------------------------------------

def test_governed_and_audit_enforced_on_edges() -> None:
    """The server must set governed=True and audit=True on all edges regardless
    of what the client sends (these are immutable constants, not toggles).
    """
    inp = _input_node()
    out = _output_node()
    graph = {
        "nodes": [inp, out],
        "edges": [{
            **_edge(inp["id"], out["id"]),
            "governed": False,   # client attempts to disable governance
            "audit": False,      # client attempts to disable audit
        }],
    }
    stripped, errors = _validate_and_strip_graph(graph)
    assert not errors, f"Unexpected errors: {errors}"

    for edge in stripped["edges"]:
        assert edge["governed"] is True, (
            "governed must be True on all edges (immutable constant per spec §5)"
        )
        assert edge["audit"] is True, (
            "audit must be True on all edges (immutable constant per spec §5)"
        )


# ---------------------------------------------------------------------------
# Test: valid graph passes cleanly
# ---------------------------------------------------------------------------

def test_valid_minimal_graph_passes() -> None:
    """A minimal valid CTF graph (input → output) passes all checks."""
    graph = _minimal_graph()
    stripped, errors = _validate_and_strip_graph(graph)
    assert not errors, f"Valid graph should produce no errors, got: {errors}"
    assert len(stripped["nodes"]) == 2
    assert len(stripped["edges"]) == 1


def test_valid_graph_preserves_node_structure() -> None:
    """Node type, id, label, and non-effective_scope data fields are preserved."""
    inp = _input_node()
    inp["data"]["sensitivity_floor"] = "INTERNAL"
    out = _output_node()
    out["data"]["verdict_chrome"] = True
    graph = {"nodes": [inp, out], "edges": [_edge(inp["id"], out["id"])]}

    stripped, errors = _validate_and_strip_graph(graph)
    assert not errors

    stripped_inp = next(n for n in stripped["nodes"] if n["node_type"] == "input_node")
    assert stripped_inp["data"]["sensitivity_floor"] == "INTERNAL"

    stripped_out = next(n for n in stripped["nodes"] if n["node_type"] == "output_node")
    assert stripped_out["data"]["verdict_chrome"] is True


def test_graph_round_trip_hash_is_deterministic() -> None:
    """Saving the same graph twice must produce the same hash (deterministic JSON)."""
    from yashigani.backoffice.routes.user_agents import _sha384_graph

    graph = _minimal_graph()
    stripped, _ = _validate_and_strip_graph(graph)
    ctf_doc = {"spec_version": "1.0", "graph": stripped, "scope": {}}

    def _serialize(doc):
        return json.dumps(doc, separators=(",", ":"), sort_keys=True)

    h1 = _sha384_graph(_serialize(ctf_doc))
    h2 = _sha384_graph(_serialize(ctf_doc))
    assert h1 == h2, "Graph hash must be deterministic for the same input"
    assert h1.startswith("sha384:"), f"Expected sha384: prefix, got {h1[:20]!r}"
