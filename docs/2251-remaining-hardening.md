# 2.25.1 — hardening from the live 2.24.4→2.25.1 upgrade

Status of the items surfaced during the live in-place upgrade. All fixes are codified in
the repo, pre-push-reviewed (SOP 4.3), and validated end-to-end on the live AMD64/Docker
29.1.3 stack unless noted.

## ✅ A. Dual-wrap pre-upgrade backup vs read-only containers (YSG-RISK-050/051) — DONE (`91adde0`)
`docker cp` refuses ReadonlyRootfs=true containers in BOTH directions (Docker 29), so the
encrypted-backup step aborted ("Failed to copy staging data into container") on our
read_only gateway/backoffice. Fixed transport-only (LOCKED crypto unchanged): tar-over-`exec`
in + out, `chmod -R u+rwX` for the umask-000 exec dirs, and a sha256 integrity check on the
streamed bundle before install (tar streaming isn't atomic). **Validated live:** full
dual-wrap completes, bundle.enc (1.65 MB) + backup-meta.json produced, integrity-verified,
saved to host (0600).

## ✅ B. OPA/RBAC groups dropped on restart — DONE (`2ce1033`)
OPA holds the RBAC document in memory only; the RBACStore persists write-through to Redis
db/3 and replays on startup, but the backoffice never re-pushed to OPA — so an OPA/upgrade
restart left OPA empty until the next mutation. Fixed: re-push the store→OPA at the end of
the backoffice lifespan startup (post-PKI; NOT _bootstrap, which runs pre-PKI at import).
Best-effort (retry, warn, never blocks startup). **Validated live end-to-end:** group in
Redis → OPA emptied → backoffice restart → re-synced → OPA repopulated; confirmed across the
real 6 groups (now restored durably to the store).

## ⚠️ C. Runtime PKI manifest bootstrap tokens (NEW — needs install.sh attention)
`docker/var/runtime/service_identities.yaml` carries the per-install `bootstrap_token_sha256`
values that the internal mTLS client needs for backoffice→OPA pushes (and likely other
service→service calls). After repeated `install.sh --upgrade` re-runs + a branch checkout
during this session, that runtime manifest was found with **all tokens empty**, which breaks
ALL backoffice→OPA pushes ("Service 'backoffice' has no bootstrap_token_sha256 in the
manifest"). Restored from the pre-upgrade backup (28 populated tokens) to recover the stack.

Root cause not fully isolated (genuine `--upgrade` gap vs. this session's git-checkout/stash
churn of the runtime file). **Action:** install.sh `--upgrade` must guarantee the runtime
manifest's bootstrap tokens are present/repopulated (idempotently) — a missing/blanked runtime
manifest silently breaks internal mTLS auth for the push path. Validate by running `--upgrade`
on an install and asserting `grep -c 'bootstrap_token_sha256: "[a-f0-9]' var/runtime/...` is
non-zero afterwards. Until then: if backoffice→OPA pushes fail post-upgrade with the manifest
error, restore the runtime manifest from the pre-upgrade backup (or re-run bootstrap PKI).
