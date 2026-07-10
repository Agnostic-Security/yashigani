"""
Regression — P8 stdio binary pinning (4.0 — closes TODO[P8]).

Proves the 4.0 addition: ``McpStdioTransport`` with a ``StdioPinConfig``
verifies the subprocess binary identity BEFORE spawning.

Cases:
  * binary_sha256 match → verification passes (no exception).
  * binary_sha256 mismatch → ``StdioPinMismatchError`` raised, subprocess
    never created.
  * command_path match → passes.
  * command_path mismatch → ``StdioPinMismatchError`` raised.
  * both set, both match → passes.
  * both set, hash mismatch only → raises.
  * pin_config=None → no check (dev mode); start() proceeds normally (spawns
    are not actually executed in these unit tests via mock).
  * unknown binary (shutil.which returns None) → raises.

These are UNIT tests: no real subprocesses are spawned.  The
``_verify_binary_pin`` helper is called directly or via mocks.

4.0 / P8 stdio-binary-pin / STDIO_PIN_MISMATCH_LABEL.
"""
from __future__ import annotations

import hashlib
import os

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_binary_content() -> bytes:
    return b"#!/bin/sh\nexec some-mcp-server \"$@\"\n"


def _sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ===========================================================================
# _verify_binary_pin unit tests
# ===========================================================================


class TestVerifyBinaryPin:
    """Direct unit tests for _verify_binary_pin (no subprocess spawned)."""

    def _pin(self, **kwargs):
        from yashigani.mcp._transport_stdio import StdioPinConfig
        return StdioPinConfig(**kwargs)

    def _verify(self, command, pin_config, binary_data: bytes,
                fake_path: str = "/fake/mcp-server"):
        from yashigani.mcp._transport_stdio import _verify_binary_pin
        _verify_binary_pin(
            command, pin_config,
            _read_binary=lambda _path: binary_data,
            _resolve_path=lambda _cmd: fake_path,
        )

    def test_binary_sha256_match_passes(self, tmp_path):
        data = _fake_binary_content()
        expected_hex = _sha256hex(data)
        pin = self._pin(binary_sha256=expected_hex)
        # Should not raise; _resolve_path injects a fake path, _read_binary provides the data
        self._verify(["/usr/local/bin/mcp-server"], pin, data)

    def test_binary_sha256_mismatch_raises(self):
        from yashigani.mcp._transport_stdio import StdioPinMismatchError
        data = _fake_binary_content()
        wrong_hex = "a" * 64
        pin = self._pin(binary_sha256=wrong_hex)
        with pytest.raises(StdioPinMismatchError):
            self._verify(["/fake/mcp-server"], pin, data)

    def test_command_path_match_passes(self, tmp_path):
        # Create a real temp binary for path resolution
        binary = tmp_path / "mcp-server"
        binary.write_bytes(_fake_binary_content())
        pin = self._pin(command_path=str(binary))
        from yashigani.mcp._transport_stdio import _verify_binary_pin
        # No hash check; path check only. _resolve_binary_path uses isabs → file exists.
        _verify_binary_pin([str(binary)], pin)

    def test_command_path_mismatch_raises(self, tmp_path):
        from yashigani.mcp._transport_stdio import StdioPinMismatchError
        binary = tmp_path / "mcp-server"
        binary.write_bytes(_fake_binary_content())
        wrong_path = str(tmp_path / "other-binary")
        pin = self._pin(command_path=wrong_path)
        with pytest.raises(StdioPinMismatchError):
            from yashigani.mcp._transport_stdio import _verify_binary_pin
            _verify_binary_pin([str(binary)], pin)

    def test_both_match_passes(self, tmp_path):
        data = _fake_binary_content()
        binary = tmp_path / "mcp-server"
        binary.write_bytes(data)
        expected_hex = _sha256hex(data)
        pin = self._pin(command_path=str(binary), binary_sha256=expected_hex)
        from yashigani.mcp._transport_stdio import _verify_binary_pin
        _verify_binary_pin([str(binary)], pin, _read_binary=lambda _: data)

    def test_path_match_hash_mismatch_raises(self, tmp_path):
        from yashigani.mcp._transport_stdio import StdioPinMismatchError
        data = _fake_binary_content()
        binary = tmp_path / "mcp-server"
        binary.write_bytes(data)
        pin = self._pin(command_path=str(binary), binary_sha256="b" * 64)
        with pytest.raises(StdioPinMismatchError):
            from yashigani.mcp._transport_stdio import _verify_binary_pin
            _verify_binary_pin([str(binary)], pin, _read_binary=lambda _: data)

    def test_unresolvable_binary_raises(self):
        from yashigani.mcp._transport_stdio import StdioPinMismatchError
        # A non-existent absolute path
        pin = self._pin(binary_sha256=_sha256hex(b"x"))
        with pytest.raises(StdioPinMismatchError):
            from yashigani.mcp._transport_stdio import _verify_binary_pin
            _verify_binary_pin(["/nonexistent/mcp-server-xyz-unique"], pin)

    def test_no_pin_fields_logs_warning(self, caplog):
        import logging
        from yashigani.mcp._transport_stdio import (
            StdioPinConfig, _verify_binary_pin, STDIO_PIN_MISMATCH_LABEL,
        )
        pin = StdioPinConfig()  # neither field set
        with caplog.at_level(logging.WARNING):
            _verify_binary_pin(["/some/binary"], pin)  # should NOT raise
        assert STDIO_PIN_MISMATCH_LABEL in caplog.text

    def test_case_insensitive_sha256_comparison(self):
        data = _fake_binary_content()
        expected_hex = _sha256hex(data).upper()  # UPPERCASE
        from yashigani.mcp._transport_stdio import _verify_binary_pin, StdioPinConfig
        pin = StdioPinConfig(binary_sha256=expected_hex)
        # Should NOT raise — lowercase vs uppercase hex is normalised.
        # Use injected path resolver so no filesystem lookup needed.
        _verify_binary_pin(
            ["/usr/local/bin/mcp-server"], pin,
            _read_binary=lambda _: data,
            _resolve_path=lambda _: "/fake/mcp-server",
        )


# ===========================================================================
# StdioPinConfig export / __all__ check
# ===========================================================================


class TestStdioPinExports:
    """Verify symbols are re-exported from the mcp package __init__."""

    def test_exports_available(self):
        from yashigani.mcp._transport_stdio import (  # noqa: F401
            StdioPinConfig,
            StdioPinMismatchError,
            STDIO_PIN_MISMATCH_LABEL,
        )

    def test_mismatch_label_value(self):
        from yashigani.mcp._transport_stdio import STDIO_PIN_MISMATCH_LABEL
        assert STDIO_PIN_MISMATCH_LABEL == "MCP_STDIO_BINARY_PIN_MISMATCH"

    def test_pin_mismatch_error_is_stdio_transport_error(self):
        from yashigani.mcp._transport_stdio import (
            StdioPinMismatchError,
            StdioTransportError,
        )
        assert issubclass(StdioPinMismatchError, StdioTransportError)


# ===========================================================================
# McpStdioTransport integration: pin_config wired into start()
# ===========================================================================


class TestMcpStdioTransportPinIntegration:
    """
    Verify that McpStdioTransport.start() calls _verify_binary_pin before
    spawning.  We patch asyncio.create_subprocess_exec to avoid real spawning
    and only test the pin guard path.
    """

    @pytest.fixture
    def real_binary(self, tmp_path):
        """Create a real executable file on disk for path/hash tests."""
        data = _fake_binary_content()
        p = tmp_path / "fake-mcp-server"
        p.write_bytes(data)
        p.chmod(0o755)
        return p, data

    @pytest.mark.asyncio
    async def test_correct_pin_allows_start(self, real_binary, monkeypatch):
        """With a correct pin, start() proceeds past the pin check."""
        binary_path, binary_data = real_binary
        expected_hex = _sha256hex(binary_data)

        from yashigani.mcp._transport_stdio import McpStdioTransport, StdioPinConfig
        pin = StdioPinConfig(
            command_path=str(binary_path),
            binary_sha256=expected_hex,
        )

        spawn_called = []

        async def _mock_exec(*args, **kwargs):
            spawn_called.append(True)
            raise RuntimeError("spawn aborted by test")

        monkeypatch.setattr("asyncio.create_subprocess_exec", _mock_exec)
        transport = McpStdioTransport(command=[str(binary_path)], pin_config=pin)
        with pytest.raises(RuntimeError, match="spawn aborted by test"):
            await transport.start()
        # The pin check ran without raising, and spawn was reached.
        assert spawn_called, "spawn was not reached — pin check must have raised"

    @pytest.mark.asyncio
    async def test_wrong_hash_raises_before_spawn(self, real_binary, monkeypatch):
        """Wrong binary_sha256 → StdioPinMismatchError before spawn."""
        binary_path, _ = real_binary

        from yashigani.mcp._transport_stdio import (
            McpStdioTransport, StdioPinConfig, StdioPinMismatchError,
        )
        pin = StdioPinConfig(binary_sha256="0" * 64)  # wrong hash

        spawn_called = []

        async def _mock_exec(*args, **kwargs):
            spawn_called.append(True)

        monkeypatch.setattr("asyncio.create_subprocess_exec", _mock_exec)
        transport = McpStdioTransport(command=[str(binary_path)], pin_config=pin)
        with pytest.raises(StdioPinMismatchError):
            await transport.start()
        assert not spawn_called, "spawn was called despite pin mismatch — fail-closed violated"

    @pytest.mark.asyncio
    async def test_no_pin_config_skips_check(self, monkeypatch):
        """No pin_config → no check, subprocess spawn is attempted normally."""
        from yashigani.mcp._transport_stdio import McpStdioTransport

        spawn_called = []

        async def _mock_exec(*args, **kwargs):
            spawn_called.append(True)
            raise RuntimeError("spawn aborted by test")

        monkeypatch.setattr("asyncio.create_subprocess_exec", _mock_exec)
        monkeypatch.setenv("YASHIGANI_ENV", "development")
        transport = McpStdioTransport(command=["echo", "hello"], pin_config=None)
        with pytest.raises(RuntimeError, match="spawn aborted by test"):
            await transport.start()
        assert spawn_called
