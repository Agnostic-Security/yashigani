"""
Regression tests — YSG-RISK-172 (chat-path repair, 2026-07-30).

Root cause: install.sh's ``langflow_yashigani_token`` file-permission fix
(BUG-4.0-LANGFLOW-TOKEN-PERMS / BUG-411-PODMAN-LANGFLOW-PERMS-V2) chowned the
secret to ``0:0`` (root:root) mode ``0440`` so that LANGFLOW's container
(uid=1000, gid=0) could read it via the group bit. That fix accounted for
langflow's own read path but NOT the GATEWAY's — the gateway bind-mounts the
whole host ``./secrets`` directory read-only (it has no per-secret Docker
``secrets:`` stanza for this particular file, unlike langflow), so host file
permissions govern its access directly on both Docker and Podman.

The gateway's fixed container UID/GID is 1001:1001
(``docker/Dockerfile.gateway``). Mode ``0440`` owned ``root:root`` has a zero
"other" bit, so the gateway process got ``EACCES`` reading the file at
startup, ``_load_token_role_map()`` in ``openai_router.py`` silently loaded
0 ``p1_agent`` entries (logged: ``token_role_map: error reading secret file
/run/secrets/langflow_yashigani_token -- agent__langflow will not be
resolvable as p1_agent: [Errno 13] Permission denied``), and EVERY
langflow-originated ``/v1/chat/completions`` call was resolved as anonymous
by ``_resolve_identity()`` and rejected with HTTP 401 ("Anonymous
/v1/chat/completions caller rejected ... zero-trust fail-closed (Path 2)")
at the deliver hop -- live-confirmed via `docker logs gateway`:

    egress-eval: ALLOW caller=spiffe://.../langflow prefix=llm
    upstream_status=401

(the OPA egress-eval gate correctly ALLOWs -- confirming YSG-RISK-170's
ceiling fix works -- but the DELIVER hop's `/v1/chat/completions` treats the
forwarded request as anonymous because the bearer token it carries,
langflow's `OPENAI_API_KEY` == the content of `langflow_yashigani_token`,
was never loaded into the gateway's `token_role_map` in the first place).

Fix: chown the file to ``1001:0`` (owner = gateway's fixed UID, matching the
host-bind-mounted read path; group = langflow's fixed GID) with mode
``0640`` -- owner-read via the UID match (gateway), group-read via the GID
match (langflow), no world-read (CWE-732 safe). Mirrors the existing
symmetric owner-reads/group-reads pattern already used for
``pgbouncer_authenticator_password`` (``70:999 0640``) elsewhere in
``generate_secrets()``. Applied at BOTH sites that chown this file:
``generate_secrets()`` (initial generation) and the Podman post-PKI-sweep
restore inside ``_pki_chown_client_keys()`` (which re-applies the same
ownership after ``_prepare_secrets_dir_for_pki()``'s recursive
``chown -R 1001:1001`` sweep clobbers it).

Docker: langflow's OWN read is unaffected -- it is governed by its compose
``secrets:`` stanza (``mode: 0440``, Docker-synthesized in-container, ignores
host permissions), unchanged by this fix.
Podman: langflow reads via the GID-0 group bit (unchanged); gateway now ALSO
reads via the UID-1001 owner bit (new).
"""
from __future__ import annotations

import os
import re

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
_INSTALL_SH = os.path.join(_REPO_ROOT, "install.sh")


def _read_install_sh() -> str:
    with open(_INSTALL_SH, "r", encoding="utf-8") as fh:
        return fh.read()


class TestRisk172LangflowTokenGatewayReadable:
    """install.sh must chown langflow_yashigani_token so BOTH the gateway
    (uid=1001, host-bind-mount read path) and langflow (gid=0, Podman
    host-permission read path) can read it -- never root:root 0440, which
    only satisfies langflow and EACCESes the gateway."""

    def test_generate_secrets_chowns_owner_readable_by_gateway(self):
        sh = _read_install_sh()
        # The BUG-4.0-LANGFLOW-TOKEN-PERMS call site: initial generation.
        assert '_do_chown "1001:0" "$_lf_token_file" "langflow_yashigani_token" "0640"' in sh, (
            "YSG-RISK-172 regression: generate_secrets() must chown "
            "langflow_yashigani_token to 1001:0 0640 (owner=gateway's fixed "
            "UID 1001 for its host-bind-mount read path, group=langflow's "
            "fixed GID 0) -- NOT '0:0 0440', which zeroes the gateway's "
            "'other' read bit and silently breaks agent__langflow "
            "resolution (0 p1_agent entries loaded, every langflow call "
            "401s as anonymous)."
        )

    def test_no_regression_to_root_owned_0440(self):
        """The ORIGINAL bug pattern (chown 0:0 ... 0440, langflow-only-
        readable) must not reappear anywhere for this specific file."""
        sh = _read_install_sh()
        # Every _do_chown call touching this exact file must use 1001:0/0640,
        # never the old 0:0/0440 pair.
        for m in re.finditer(
            r'_do_chown\s+"([^"]+)"\s+"\$?_?lf_tok(?:en_file|_path)"\s+'
            r'"langflow_yashigani_token"\s+"([^"]+)"',
            sh,
        ):
            uid_spec, mode = m.group(1), m.group(2)
            assert uid_spec == "1001:0", (
                f"YSG-RISK-172 regression: found a langflow_yashigani_token "
                f"chown call using uid_spec={uid_spec!r} (expected '1001:0') "
                f"-- this is the exact class of bug that broke gateway "
                f"read access"
            )
            assert mode == "0640", (
                f"YSG-RISK-172 regression: found a langflow_yashigani_token "
                f"chown call using mode={mode!r} (expected '0640') -- mode "
                f"'0440' zeroes both the owner-write AND (with owner != "
                f"gateway) the gateway's read access entirely"
            )

    def test_podman_post_pki_sweep_restore_uses_matching_perms(self):
        """The Podman-only recovery block inside _pki_chown_client_keys()
        (BUG-411-PODMAN-LANGFLOW-PERMS-V2) re-applies ownership after
        _prepare_secrets_dir_for_pki()'s 'chown -R 1001:1001 secrets/' sweep
        clobbers it -- this recovery call must use the SAME 1001:0/0640
        pair as the initial generation, not revert to 0:0/0440."""
        sh = _read_install_sh()
        assert (
            '_do_chown "1001:0" "$_lf_tok_path" "langflow_yashigani_token" "0640"' in sh
        ), (
            "YSG-RISK-172 regression: the Podman post-PKI-sweep restore "
            "block must re-chown langflow_yashigani_token to 1001:0 0640 "
            "(matching generate_secrets()'s fix) -- reverting to 0:0 0440 "
            "here would re-break gateway read access on every Podman "
            "install/upgrade that runs the PKI issuer."
        )

    def test_old_root_root_0440_langflow_specific_pattern_absent(self):
        """Guard against literal reintroduction of the exact broken
        invocation string this bug shipped with."""
        sh = _read_install_sh()
        assert (
            '_do_chown "0:0" "$_lf_token_file" "langflow_yashigani_token" "0440"'
            not in sh
        )
        assert (
            '_do_chown "0:0" "$_lf_tok_path" "langflow_yashigani_token" "0440"'
            not in sh
        )
