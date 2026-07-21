"""
Unit tests for docker/caddy/config_broker.py — FINDING-V412-CADDYADMIN-001
(R1 + R2) validating broker.

These prove the VALIDATION LOGIC in-process: the live two-container proof
(real Caddy + real broker, throwaway podman containers, Laura's exact PoC
shape + a rogue docker/caddy/agents/*.caddy snippet) was run manually during
the fix and is cited in the commit body; this file is the regression net
(SOP5 — every fix needs a test that would re-fail on the original bug) run on
every CI pass without needing a container.

The broker lives at a non-importable path (it is baked into its own image,
not the yashigani package), so we load it by file path via importlib — same
pattern as src/tests/unit/test_extractor_worker.py for
docker/extractor/worker.py.

Requires a local `caddy` binary (the SAME structural check config_broker.py
itself performs — `caddy adapt` is the source of truth, never a hand-rolled
Caddyfile parser). Skipped if absent, matching codegen.py's C10
`_validate_caddy_snippet` precedent (LAURA-005 — CI/production must set
YSG_REQUIRE_CADDY_VALIDATE to make an absent binary a hard failure instead).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_BROKER_PATH = _REPO_ROOT / "docker" / "caddy" / "config_broker.py"

_CADDY_BIN = shutil.which("caddy")
pytestmark = pytest.mark.skipif(
    _CADDY_BIN is None,
    reason="no local `caddy` binary — this suite validates against the REAL "
           "adapter (never a hand-rolled parser), matching codegen.py C10",
)


def _load_broker():
    spec = importlib.util.spec_from_file_location("ysg_config_broker", _BROKER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def broker(monkeypatch):
    mod = _load_broker()
    monkeypatch.setattr(mod, "_CADDY_BIN", _CADDY_BIN)
    return mod


# ---------------------------------------------------------------------------
# Fixtures — small, self-contained Caddyfiles (NOT the real production
# family — this suite tests the VALIDATION LOGIC in isolation, independent
# of /etc/caddy staging; the live container proof used the real files).
# ---------------------------------------------------------------------------

def _rogue_ca_der_b64() -> str:
    """Ephemeral rogue CA cert, DER-encoded, base64 — same shape Laura used
    (CN=ROGUE-ATTACKER-CA). Generated fresh per test run via openssl."""
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "/dev/null", "-out", "-", "-days", "1",
         "-subj", "/CN=ROGUE-ATTACKER-CA", "-outform", "DER"],
        capture_output=True, timeout=15,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return base64.b64encode(proc.stdout).decode("ascii")


_BASE_FIXTURE = """\
{
    admin unix//run/caddy-admin/admin.sock|0666
}

:443 {
    tls internal

    handle_path /admin/* {
        respond "admin ui" 200
    }

    handle /mesh/* {
        reverse_proxy https://backoffice:8443 {
            transport http {
                tls
                tls_trust_pool file /run/secrets/ca_intermediate.crt
                tls_client_auth /run/secrets/caddy_client.crt /run/secrets/caddy_client.key
            }
        }
    }
}

:8444 {
    tls internal {
        client_auth {
            mode require_and_verify
            trust_pool file /run/secrets/ca_intermediate.crt
        }
    }
    respond "mesh listener" 200
}
"""

_LEGIT_GROWTH_FIXTURE = _BASE_FIXTURE.replace(
    'handle /mesh/* {',
    'handle_path /agents/default/newagent/* {\n'
    '        uri strip_prefix /agents/default/newagent\n'
    '        reverse_proxy {\n'
    '            to newagent-upstream.internal:9000\n'
    '            transport http {\n'
    '                tls\n'
    '                tls_server_name newagent-upstream.internal\n'
    '            }\n'
    '        }\n'
    '    }\n\n'
    '    handle /mesh/* {',
)


# ---------------------------------------------------------------------------
# _extract_invariants
# ---------------------------------------------------------------------------

class TestExtractInvariants:
    def test_admin_listen_addrs_ca_refs(self, broker):
        cfg = broker._adapt_text(_BASE_FIXTURE)
        inv = broker._extract_invariants(cfg)

        assert inv["admin"] == {"listen": "unix//run/caddy-admin/admin.sock|0666"}
        assert ":443" in inv["listen_addrs"]
        assert ":8444" in inv["listen_addrs"]
        assert not inv["has_pki_app"]
        assert not inv["inline_hits"]
        # Two file-based CA refs (the mesh reverse_proxy transport + the
        # :8444 client_auth) — both point at the same pinned intermediate.
        assert len(inv["ca_refs"]) == 2
        for ca in inv["ca_refs"]:
            assert ca.get("provider") in (None, "file")
            assert ca.get("pem_files") == ["/run/secrets/ca_intermediate.crt"]

    def test_inline_provider_detected_anywhere_in_tree(self, broker):
        rogue = _rogue_ca_der_b64()
        text = _BASE_FIXTURE.replace(
            "trust_pool file /run/secrets/ca_intermediate.crt",
            'trust_pool inline {\n                trust_der "%s"\n            }' % rogue,
            1,
        )
        cfg = broker._adapt_text(text)
        inv = broker._extract_invariants(cfg)
        assert inv["inline_hits"], "inline provider must be detected"
        assert inv["inline_hits"][0]["provider"] == "inline"


# ---------------------------------------------------------------------------
# validate_candidate — the actual gate config_broker.py enforces on /load
# ---------------------------------------------------------------------------

class TestValidateCandidate:
    @pytest.fixture()
    def baseline(self, broker):
        cfg = broker._adapt_text(_BASE_FIXTURE)
        return broker._extract_invariants(cfg)

    def test_unchanged_reload_passes(self, broker, baseline):
        """The exact same Caddyfile text re-posted (the real
        mcp_onboard.py contract — it rereads and reposts the active
        Caddyfile verbatim) must pass."""
        ok, reason = broker.validate_candidate(_BASE_FIXTURE, baseline)
        assert ok, reason

    def test_legitimate_onboarding_growth_passes(self, broker, baseline):
        """A NEW route attached to the EXISTING :443 site (the shape
        codegen.py _gen_caddy_snippet always produces — handle_path within
        the existing site, never a new listener/tls/admin) must NOT be
        rejected — legitimate onboarding must keep working after this fix."""
        ok, reason = broker.validate_candidate(_LEGIT_GROWTH_FIXTURE, baseline)
        assert ok, reason

    def test_new_listener_rejected(self, broker, baseline):
        """R1 — Laura's exact PoC shape: a brand-new isolated listener
        (POST /config/apps/http/servers/rogue_poc equivalent, delivered via
        /load instead of the raw admin API). `tls internal` matches the
        base fixture's own automation issuer so this is rejected by the
        LISTEN-SET check specifically, not an unrelated automation-policy
        parse conflict (Caddy requires matching default issuers across
        sites sharing a catch-all policy — a real-world detail orthogonal
        to what this test targets)."""
        rogue = _BASE_FIXTURE + '\n:19999 {\n    tls internal\n    respond "rogue" 200\n}\n'
        ok, reason = broker.validate_candidate(rogue, baseline)
        assert not ok, reason
        assert "listen" in reason.lower(), reason

    def test_inline_ca_on_existing_listener_rejected(self, broker, baseline):
        """R1 — inline rogue CA swapped into an EXISTING listener's trust
        pool (no new port at all) — Laura's actual trust-anchor-injection
        outcome, minimal-diff shape."""
        rogue_der = _rogue_ca_der_b64()
        rogue = _BASE_FIXTURE.replace(
            "trust_pool file /run/secrets/ca_intermediate.crt",
            'trust_pool inline {\n                trust_der "%s"\n            }' % rogue_der,
            1,
        )
        ok, reason = broker.validate_candidate(rogue, baseline)
        assert not ok
        assert "inline" in reason.lower()

    def test_unexpected_ca_file_path_rejected(self, broker, baseline):
        """Even a FILE-based (not inline) CA pointed at a path OUTSIDE the
        baseline's pinned set must be rejected — not just the inline vector."""
        rogue = _BASE_FIXTURE.replace(
            "/run/secrets/ca_intermediate.crt",
            "/run/secrets/attacker_planted_ca.crt",
            1,
        )
        ok, reason = broker.validate_candidate(rogue, baseline)
        assert not ok
        assert "trust-anchor" in reason.lower() or "ca" in reason.lower()

    def test_admin_directive_change_rejected(self, broker, baseline):
        """A resubmitted config that widens/repoints the admin API itself
        must be rejected — this is exactly what would let a compromised
        backoffice re-share the admin socket after this fix ships."""
        rogue = _BASE_FIXTURE.replace(
            "admin unix//run/caddy-admin/admin.sock|0666",
            "admin unix//run/caddy/admin.sock|0666",
            1,
        )
        ok, reason = broker.validate_candidate(rogue, baseline)
        assert not ok
        assert "admin" in reason.lower()

    def test_pki_app_extract_invariants_flags_it(self, broker, baseline):
        """A merged config carrying Caddy's internal-CA management app
        (apps.pki) must be flagged by has_pki_app — regardless of provider
        shape, minting/trusting arbitrary certs via that app is in scope.
        Exercised directly on the JSON tree (not round-tripped through
        Caddyfile syntax, which requires a nontrivial `pki` global-options
        stanza orthogonal to what this test targets) — this is the same
        _extract_invariants() call validate_candidate() itself makes on
        whatever `caddy adapt` returns, so it covers the real code path."""
        cfg = broker._adapt_text(_BASE_FIXTURE)
        cfg["apps"]["pki"] = {"certificate_authorities": {"attacker-ca": {}}}
        inv = broker._extract_invariants(cfg)
        assert inv["has_pki_app"] is True

    def test_malformed_body_rejected_fail_closed(self, broker, baseline):
        """A syntactically-broken submission must fail closed (422/adapt
        error), never silently pass through or crash the handler."""
        ok, reason = broker.validate_candidate("{ this is not } valid { caddyfile", baseline)
        assert not ok
        assert reason  # a reason must always be present


# ---------------------------------------------------------------------------
# K8s "live" baseline mode — see config_broker.py "BASELINE MODE".
# ---------------------------------------------------------------------------

class TestLiveBaselineMode:
    def test_live_mode_strips_agents_import_and_matches_baked_equivalent(
        self, broker, tmp_path, monkeypatch,
    ):
        """The K8s sidecar computes its baseline by reading the live
        ConfigMap-mounted Caddyfile at startup (safe there — see the mode
        docstring: no chart RBAC grants any workload configmaps access).
        Its invariants must match what the SAME text would produce via the
        "baked" path (same _extract_invariants call, different source),
        proving the two modes are equivalent, not just independently
        plausible."""
        caddyfile_with_agents_import = _BASE_FIXTURE + "\n" + broker._AGENTS_IMPORT_SENTINEL + "\n"
        live_path = tmp_path / "Caddyfile"
        live_path.write_text(caddyfile_with_agents_import)

        monkeypatch.setattr(broker, "_BASELINE_MODE", "live")
        monkeypatch.setattr(broker, "_LIVE_CADDYFILE", str(live_path))
        live_baseline = broker._load_baseline()

        baked_cfg = broker._adapt_text(_BASE_FIXTURE)  # no agents-import at all
        baked_baseline = broker._extract_invariants(baked_cfg)

        assert live_baseline["admin"] == baked_baseline["admin"]
        assert live_baseline["listen_addrs"] == baked_baseline["listen_addrs"]
        assert live_baseline["ca_refs"] == baked_baseline["ca_refs"]
        assert live_baseline["has_pki_app"] == baked_baseline["has_pki_app"] is False

    def test_strip_agents_import_removes_sentinel_only(self, broker):
        text = "line one\n" + broker._AGENTS_IMPORT_SENTINEL + "\nline two\n"
        stripped = broker._strip_agents_import(text)
        assert broker._AGENTS_IMPORT_SENTINEL not in stripped
        assert "line one" in stripped
        assert "line two" in stripped


# ---------------------------------------------------------------------------
# Live HTTP-handler smoke test — the actual server code path (Content-Length
# parsing, body cap, 404s, the reject-before-forward invariant), not just the
# pure validate_candidate() function. Runs entirely in-process; the real
# admin socket is a tiny stub server (also in-process) so no container/caddy
# instance is required for the FORWARDING half of the contract.
# ---------------------------------------------------------------------------

class _StubAdminHandler:
    """Minimal stand-in for the real Caddy admin socket's /load endpoint —
    always returns 200, and records whether it was ever called."""

    def __init__(self):
        self.called = False


def _run_stub_admin_socket(path: str, state: _StubAdminHandler, stop_event: threading.Event):
    import http.server
    import socketserver

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            state.called = True
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # noqa: D102 — silence stdlib default logging
            pass

    class UnixServer(socketserver.UnixStreamServer):
        allow_reuse_address = True

    srv = UnixServer(path, Handler)
    srv.timeout = 0.2
    while not stop_event.is_set():
        srv.handle_request()
    srv.server_close()


class TestBrokerHttpServerLive:
    def test_reject_never_reaches_admin_forward(self, broker, tmp_path, monkeypatch):
        """A REJECTED candidate must 422 and the stub admin socket must
        record ZERO calls — proves the fail-closed ordering (validate BEFORE
        forward) end-to-end through the real handler code, not just the
        pure function."""
        # AF_UNIX sockaddr_un.sun_path is ~104 bytes on macOS/BSD — pytest's
        # tmp_path (nested under /private/var/.../pytest-of-.../pytest-N/...)
        # routinely exceeds that. Sockets are transient bind()-only test
        # artifacts (cleaned up in `finally`, never a deliverable), so use a
        # short-path tempdir purely to satisfy the kernel constraint.
        sock_dir = pathlib.Path(tempfile.mkdtemp(prefix="ysgb-"))
        real_admin_sock = str(sock_dir / "admin.sock")
        broker_sock = str(sock_dir / "broker.sock")
        baseline_dir = tmp_path / "reference"
        baseline_dir.mkdir()

        cfg = broker._adapt_text(_BASE_FIXTURE)
        (baseline_dir / "adapted-selfsigned.json").write_text(json.dumps(cfg))

        monkeypatch.setattr(broker, "_BASELINE_DIR", str(baseline_dir))
        monkeypatch.setattr(broker, "_TLS_MODE", "selfsigned")
        monkeypatch.setattr(broker, "_REAL_ADMIN_SOCKET", real_admin_sock)
        broker._load_baseline_or_die()
        assert broker._BASELINE_CACHE is not None, broker._BASELINE_LOAD_ERROR

        stop_event = threading.Event()
        stub_state = _StubAdminHandler()
        admin_thread = threading.Thread(
            target=_run_stub_admin_socket,
            args=(real_admin_sock, stub_state, stop_event),
            daemon=True,
        )
        admin_thread.start()
        time.sleep(0.1)

        httpd = broker.UnixHTTPServer(broker_sock, broker.BrokerHandler)
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.1)

        try:
            rogue = _BASE_FIXTURE + '\n:19999 {\n    tls internal\n    respond "rogue" 200\n}\n'
            status, body = _post_unix(broker_sock, "/load", rogue.encode())
            assert status == 422, body
            assert b"listen" in body.lower(), body
            assert stub_state.called is False, (
                "REJECTED submission must NEVER reach the real admin socket"
            )

            status2, body2 = _post_unix(broker_sock, "/load", _BASE_FIXTURE.encode())
            assert status2 == 200, body2
            assert stub_state.called is True, (
                "APPROVED submission must be forwarded to the real admin socket"
            )
        finally:
            httpd.shutdown()
            stop_event.set()
            admin_thread.join(timeout=2)
            server_thread.join(timeout=2)

    def test_wrong_path_404_without_touching_validator(self, broker, tmp_path, monkeypatch):
        # See test_reject_never_reaches_admin_forward — short path needed
        # for the AF_UNIX sun_path length limit.
        sock_dir = pathlib.Path(tempfile.mkdtemp(prefix="ysgb-"))
        broker_sock = str(sock_dir / "broker.sock")
        baseline_dir = tmp_path / "reference"
        baseline_dir.mkdir()
        cfg = broker._adapt_text(_BASE_FIXTURE)
        (baseline_dir / "adapted-selfsigned.json").write_text(json.dumps(cfg))
        monkeypatch.setattr(broker, "_BASELINE_DIR", str(baseline_dir))
        monkeypatch.setattr(broker, "_TLS_MODE", "selfsigned")
        broker._load_baseline_or_die()

        httpd = broker.UnixHTTPServer(broker_sock, broker.BrokerHandler)
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.1)
        try:
            status, _ = _post_unix(broker_sock, "/config/", b"{}")
            assert status == 404
            status2, _ = _post_unix(broker_sock, "/stop", b"")
            assert status2 in (400, 404)  # empty body -> 400 before path check on POST is fine too
        finally:
            httpd.shutdown()
            server_thread.join(timeout=2)


def _post_unix(sock_path: str, path: str, body: bytes) -> tuple[int, bytes]:
    import http.client

    class _UnixConn(http.client.HTTPConnection):
        def connect(self):  # noqa: D102
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(sock_path)
            self.sock = s

    # Retry transport-level failures ONLY (connection refused/reset while the
    # server thread is still starting up under heavy parallel-test load) —
    # never retry-into-pass on an HTTP status (SOP4: first non-2xx from the
    # APPLICATION is final; this loop is purely about the listener not being
    # ready yet, the same class of retry the release-gate probe allows for
    # curl exit 7/28/35).
    last_exc: Exception | None = None
    for attempt in range(20):
        conn = _UnixConn("localhost", timeout=5)
        try:
            conn.request("POST", path, body=body, headers={
                "Content-Type": "text/caddyfile",
                "Content-Length": str(len(body)),
            })
            resp = conn.getresponse()
            return resp.status, resp.read()
        except OSError as exc:
            last_exc = exc
            time.sleep(0.05 * (attempt + 1))
        finally:
            conn.close()
    raise AssertionError(f"could not reach {sock_path} after retries: {last_exc}")
