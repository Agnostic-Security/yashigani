"""Regression — svid-sidecar rotation-response file perms (v4.1 Phase 1, Nico Q4).

docker/svid-sidecar/rotate.sh writes the backoffice rotation response
(.rotate_response.json — contains ``key_pem``) into the SHARED SVID volume via
``curl --output``.  Before this fix the file landed at curl-default mode
(umask 022 → 0644): every group/other reader of the volume (Caddy via
group 2003; the agent container's ro mount) could read the new private key.

Pinned invariants:
  * ``umask 077`` is set before any file is created (private-by-default).
  * The response file is explicitly re-created 0600 before curl writes it
    (repairs a pre-existing file left at older perms).
  * The ready flag is explicitly chmod 0644 (agent-side polls keep working
    under the tightened umask).
  * The perms-bearing chmods for the projected certs/key are unchanged
    (0444 cert/ca, 0440 + :2003 key).

Last updated: 2026-07-06T00:00:00+00:00
"""
from __future__ import annotations

import re
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parents[4] / "docker" / "svid-sidecar" / "rotate.sh"
)


def _text() -> str:
    return _SCRIPT.read_text()


def test_umask_set_before_first_file_write():
    text = _text()
    umask_pos = text.find("umask 077")
    assert umask_pos != -1, "rotate.sh must set umask 077 (Nico Q4)"
    first_write = min(
        p
        for p in (
            text.find('cp "${INIT_DIR}'),        # init-phase cert copies
            text.find('HTTP_CODE="$(curl'),      # rotation-phase response write
        )
        if p != -1
    )
    assert umask_pos < first_write, "umask 077 must precede every file creation"


def test_response_file_recreated_private_before_curl():
    text = _text()
    m = re.search(
        r'rm -f "\$\{RESPONSE_FILE\}"\s*\n\s*touch "\$\{RESPONSE_FILE\}"\s*\n'
        r'\s*chmod 0600 "\$\{RESPONSE_FILE\}"',
        text,
    )
    assert m, "response file must be rm/touch/chmod-0600'd before curl --output"
    assert m.start() < text.find('--output "${RESPONSE_FILE}"'), (
        "0600 re-create must happen BEFORE curl writes the key material"
    )


def test_ready_flag_stays_world_readable():
    assert 'chmod 0644 "${READY_FLAG}"' in _text()


def test_projected_cert_and_key_perms_unchanged():
    text = _text()
    assert text.count('chmod 0444') >= 2   # cert + ca (init) [+ rotated cert tmp]
    assert 'chmod 0440' in text            # key (group 2003 for Caddy)
    assert 'chown :2003' in text
