# 2.25.1 — remaining hardening (diagnosed, need a TESTED pass)

Two items from the live 2.24.4→2.25.1 upgrade remain. Both are **precisely diagnosed**
below but deliberately **not** committed yet: one touches a LOCKED security control and one
is app code — each needs a focused, *validated* change, not a tail-of-session guess. These
are 2.25.1 work (not deferred to a later release).

Already shipped on this branch: Wazuh full-mTLS provisioning (`0317b2c`) + 4 install.sh
upgrade fixes (`75ead40`) — all pre-push-reviewed (SOP 4.3).

## A. Dual-wrap pre-upgrade backup fails against read-only containers (YSG-RISK-050/051 — LOCKED)

**Symptom:** `install.sh --upgrade` aborts at the encrypted-backup step —
`YSG-RISK-050: Failed to copy staging data into container docker-backoffice-1`.

**Root cause (confirmed live):** the crypto step `docker cp`s the staging dir + script
INTO a running gateway/backoffice container. Those containers run **`ReadonlyRootfs=true`**,
and **`docker cp` refuses any read-only-rootfs container even when the target is a writable
tmpfs** (Docker 29). So the transport is fundamentally incompatible with our hardened
containers.

**What was tried and is NOT sufficient:** replacing `docker cp` with `tar -cf - | docker
exec -i tar -xf -` (stream over exec into tmpfs `/tmp`). Live test result: the stream
"succeeds" but the extracted files land with ownership the in-container app user
(`yashigani`, uid 1001) **cannot read or remove** (`Permission denied`) — so the crypto,
which runs as that user, still can't consume the staging. A naive transport swap is wrong.

**Candidate fix (for the tested pass):**
- stream in via `docker exec -i ... tar -xf - --no-same-owner --no-same-permissions -C <dir>`
  (extract as the exec user, don't preserve archive uid/mode), OR extract then
  `chown -R` to the container user; verify the crypto can read the staging.
- the container has tmpfs `/tmp` (1777) + `/dev/shm` (1777) writable, and RW volume mounts
  `/data/audit`, `/data/bootstrap` — pick a path the app user owns cleanly.
- **Validate end-to-end:** run the real backup flow against the read-only containers and
  confirm `bundle.enc` + `backup-meta.json` are produced AND decryptable (don't just check
  the transport). This is a LOCKED control (no-plaintext-fallback, fail-closed) — keep that
  invariant; change only the transport.

**Interim:** the 4 shipped install.sh fixes already make the *plain* secrets staging cp
non-fatal, so the upgrade is not blocked by the secrets copy; this item is specifically the
encrypted-bundle step.

## B. OPA / RBAC groups are not persisted (app code)

**Symptom:** RBAC groups created via the admin API (`POST /admin/rbac/groups` + `policy/push`)
are **lost on any policy-container restart** (e.g. an upgrade). Confirmed: postgres
`rbac_groups`/`rbac_members`/`identity_group_membership` are **0 rows**, the durable
`policy/data/rbac_data.json` has empty `groups`, and the groups live **only in OPA's
in-memory store** (`GET https://policy:8181/v1/data/yashigani/rbac`).

**Fix (for the tested pass, backoffice app code):** the RBAC-group create/push handler must
persist the group + memberships to postgres (`rbac_groups`/`rbac_members`) and regenerate
`policy/data/rbac_data.json` (or re-push from postgres on policy startup) — so groups
survive a restart. Requires a backoffice image rebuild + a test that creates a group,
restarts the policy container, and confirms the group is still enforced.

**Interim (operational):** export live OPA state before any policy-container recreate
(`/v1/data/yashigani/rbac` via mTLS) and re-PUT it after — as done during this upgrade
(backup at `testing_runs/yashigani/backup-pre-nuke-20260531/opa_live_state.json`).
