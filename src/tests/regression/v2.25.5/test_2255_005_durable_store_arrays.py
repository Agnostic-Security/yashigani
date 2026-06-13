"""
Regression test — 2255-005: IdentityDurableStore upsert fails with
``malformed array literal: "[]"`` on backoffice startup.

Root cause
----------
``_j()`` in ``upsert()`` called ``json.dumps(v)`` for list values, producing a
JSON string (e.g. ``'["users"]'``).  The ``identities`` table columns
``expertise``, ``capabilities``, ``allowed_tools``, ``allowed_models``,
``groups``, ``allowed_callers``, ``allowed_paths``, ``allowed_cidrs`` are
Postgres ``text[]`` — they expect a Postgres array literal (``{users}``),
not a JSON string.  Only ``container_config`` is ``jsonb``.

Fix
---
``_pg_array()`` passes a Python list; psycopg2 adapts it to a Postgres array
natively.  ``_pg_jsonb()`` calls ``json.dumps`` for ``container_config`` only.
``_pg_array()`` also handles the back-fill path where Redis stores lists as
JSON strings.

These tests verify:
  1. Correct param types are passed to the cursor for text[] vs jsonb columns.
  2. An identity with populated array fields upserts without error (mock cursor).
  3. An identity with all-empty lists upserts without error (the ``"[]"`` case
     that triggered the original bug).
  4. The back-fill path (Redis JSON string → upsert) works correctly.
  5. The ``_pg_array`` helper handles all three input shapes.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helper to build a minimal identity dict
# ---------------------------------------------------------------------------

def _make_identity(**overrides) -> dict:
    base = {
        "identity_id": "idnt_test2255005",
        "kind": "service",
        "name": "Test 2255-005",
        "slug": "test-2255-005",
        "description": "",
        "expertise": [],
        "system_prompt": "",
        "model_preference": "",
        "sensitivity_ceiling": "PUBLIC",
        "upstream_url": "",
        "container_image": "",
        "container_config": {},
        "capabilities": [],
        "allowed_tools": [],
        "allowed_models": [],
        "icon_url": "",
        "groups": [],
        "allowed_callers": [],
        "allowed_paths": [],
        "allowed_cidrs": [],
        "org_id": "00000000-0000-0000-0000-000000000000",
        "bound_spiffe_uri": "",
        "api_key_hash": "$2b$12$fakehash",
        "status": "active",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "last_seen_at": "",
        "token_rotation_schedule": "",
        "api_key_created_at": "2026-01-01T00:00:00+00:00",
        "api_key_expires_at": "2026-12-31T00:00:00+00:00",
        "api_key_rotated_at": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


def _make_store():
    from yashigani.identity.durable_store import IdentityDurableStore
    return IdentityDurableStore(dsn="postgresql://fake:fake@localhost:5432/fake")


def _mock_conn():
    """Return a mock psycopg2 connection + cursor that records execute() calls."""
    conn = MagicMock()
    cur = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn.cursor.return_value = cur
    conn.autocommit = False
    return conn, cur


# ---------------------------------------------------------------------------
# 1. Column type assertions — text[] params must be lists, not JSON strings
# ---------------------------------------------------------------------------

TEXT_ARRAY_COLUMNS = [
    "expertise", "capabilities", "allowed_tools", "allowed_models",
    "groups", "allowed_callers", "allowed_paths", "allowed_cidrs",
]

_TEXT_ARRAY_POSITIONS = {
    # Zero-based index in the VALUES tuple passed to cursor.execute() on the
    # INSERT. Positions correspond to the column order in the upsert SQL:
    # tenant_id(0), identity_id(1), kind(2), name(3), slug(4), description(5),
    # expertise(6), system_prompt(7), model_preference(8), sensitivity_ceiling(9),
    # upstream_url(10), container_image(11), container_config(12),
    # capabilities(13), allowed_tools(14), allowed_models(15), icon_url(16),
    # groups(17), allowed_callers(18), allowed_paths(19), allowed_cidrs(20),
    # org_id(21), bound_spiffe_uri(22), api_key_hash(23), status(24),
    # created_at(25), updated_at(26), last_seen_at(27),
    # token_rotation_schedule(28), api_key_created_at(29),
    # api_key_expires_at(30), api_key_rotated_at(31)
    "expertise":       6,
    "capabilities":    13,
    "allowed_tools":   14,
    "allowed_models":  15,
    "groups":          17,
    "allowed_callers": 18,
    "allowed_paths":   19,
    "allowed_cidrs":   20,
    "container_config": 12,  # jsonb — must be a JSON string
}


class TestUpsertColumnTypes:
    """text[] columns must be Python lists; container_config (jsonb) must be a JSON string."""

    def _run_upsert(self, identity: dict):
        store = _make_store()
        conn, cur = _mock_conn()
        # _connect() is called twice: once for SET LOCAL in _connect(), once for upsert.
        # We intercept the outer _connect patch.
        with patch.object(store, "_connect", return_value=conn):
            store.upsert(identity)
        # The second cursor call is the INSERT execute (first is the RLS SET).
        all_calls = cur.execute.call_args_list
        # Find the INSERT call (it has a large SQL string)
        insert_call = next(
            c for c in all_calls
            if "INSERT INTO identities" in str(c)
        )
        return insert_call

    def test_empty_arrays_are_lists_not_json_strings(self):
        """All-empty text[] columns must be [] (Python list), not '[]' (JSON string).

        This is the exact 2255-005 bug: empty list → json.dumps → '[]' →
        Postgres rejects as 'malformed array literal'.
        """
        identity = _make_identity()  # all array fields are []
        insert_call = self._run_upsert(identity)
        params = insert_call[0][1]  # positional params tuple

        for col, pos in _TEXT_ARRAY_POSITIONS.items():
            if col == "container_config":
                continue  # jsonb — different assertion below
            val = params[pos]
            assert isinstance(val, list), (
                f"Column '{col}' at params[{pos}] must be a Python list "
                f"(psycopg2 → text[]), got {type(val).__name__!r}: {val!r}. "
                f"This is the 2255-005 bug: json.dumps([]) → '[]' → "
                f"'malformed array literal'."
            )

    def test_populated_arrays_are_lists_not_json_strings(self):
        """Populated text[] columns must remain Python lists."""
        identity = _make_identity(
            groups=["users", "owui-users"],
            expertise=["python", "security"],
            capabilities=["code_execution"],
            allowed_tools=["bash", "read_file"],
            allowed_models=["qwen2.5:3b"],
            allowed_callers=["idnt_caller1"],
            allowed_paths=["/api/v1/*"],
            allowed_cidrs=["10.0.0.0/8"],
        )
        insert_call = self._run_upsert(identity)
        params = insert_call[0][1]

        assert params[_TEXT_ARRAY_POSITIONS["groups"]] == ["users", "owui-users"]
        assert params[_TEXT_ARRAY_POSITIONS["expertise"]] == ["python", "security"]
        assert params[_TEXT_ARRAY_POSITIONS["capabilities"]] == ["code_execution"]
        assert params[_TEXT_ARRAY_POSITIONS["allowed_tools"]] == ["bash", "read_file"]

    def test_container_config_is_json_string(self):
        """container_config is jsonb — must be a JSON string, not a dict."""
        identity = _make_identity(container_config={"memory": "512m", "cpus": 2})
        insert_call = self._run_upsert(identity)
        params = insert_call[0][1]
        val = params[_TEXT_ARRAY_POSITIONS["container_config"]]
        assert isinstance(val, str), (
            f"container_config (jsonb) must be a JSON string, got {type(val).__name__!r}"
        )
        # Must be valid JSON
        parsed = json.loads(val)
        assert parsed == {"memory": "512m", "cpus": 2}

    def test_empty_container_config_is_json_string(self):
        """Empty container_config must be '{}' (JSON), not an empty dict."""
        identity = _make_identity(container_config={})
        insert_call = self._run_upsert(identity)
        params = insert_call[0][1]
        val = params[_TEXT_ARRAY_POSITIONS["container_config"]]
        assert isinstance(val, str)
        assert json.loads(val) == {}


# ---------------------------------------------------------------------------
# 2. Back-fill path: Redis JSON strings → upsert (mixed input shapes)
# ---------------------------------------------------------------------------

class TestUpsertBackfillPath:
    """The back-fill path calls _decode() which returns Python lists, then upsert().

    But test that _pg_array() also handles JSON strings (defensive: Redis hashes
    store lists as JSON strings, and any intermediate path that doesn't call
    _decode() first passes strings).
    """

    def _run_upsert(self, identity: dict):
        store = _make_store()
        conn, cur = _mock_conn()
        with patch.object(store, "_connect", return_value=conn):
            store.upsert(identity)
        all_calls = cur.execute.call_args_list
        insert_call = next(
            c for c in all_calls if "INSERT INTO identities" in str(c)
        )
        return insert_call[0][1]

    def test_json_string_arrays_are_parsed_to_lists(self):
        """If array fields arrive as JSON strings (back-fill path), they must be
        parsed to Python lists before being passed to psycopg2."""
        identity = _make_identity(
            groups='["users", "owui-users"]',  # JSON string, as stored in Redis
            expertise='["python"]',
            capabilities="[]",  # empty JSON string
        )
        params = self._run_upsert(identity)
        assert params[_TEXT_ARRAY_POSITIONS["groups"]] == ["users", "owui-users"]
        assert params[_TEXT_ARRAY_POSITIONS["expertise"]] == ["python"]
        assert params[_TEXT_ARRAY_POSITIONS["capabilities"]] == []

    def test_none_array_fields_become_empty_list(self):
        """None for a text[] field must produce [] not crash."""
        identity = _make_identity(groups=None, expertise=None)
        params = self._run_upsert(identity)
        assert params[_TEXT_ARRAY_POSITIONS["groups"]] == []
        assert params[_TEXT_ARRAY_POSITIONS["expertise"]] == []


# ---------------------------------------------------------------------------
# 3. _pg_array helper unit tests
# ---------------------------------------------------------------------------

class TestPgArrayHelper:
    """Direct unit tests for the _pg_array() inner function.

    We exercise it via upsert() because it's an inner function, but we can also
    verify the behaviour via the params.
    """

    def _get_param(self, col: str, value) -> object:
        """Run upsert with the given field value and return the parameter at col's position."""
        store = _make_store()
        conn, cur = _mock_conn()
        identity = _make_identity(**{col: value})
        with patch.object(store, "_connect", return_value=conn):
            store.upsert(identity)
        all_calls = cur.execute.call_args_list
        insert_call = next(c for c in all_calls if "INSERT INTO identities" in str(c))
        return insert_call[0][1][_TEXT_ARRAY_POSITIONS[col]]

    def test_list_passthrough(self):
        assert self._get_param("groups", ["a", "b"]) == ["a", "b"]

    def test_empty_list(self):
        assert self._get_param("groups", []) == []

    def test_json_string_populated(self):
        assert self._get_param("groups", '["x", "y"]') == ["x", "y"]

    def test_json_string_empty(self):
        assert self._get_param("groups", "[]") == []

    def test_none(self):
        assert self._get_param("groups", None) == []

    def test_empty_string(self):
        assert self._get_param("groups", "") == []
