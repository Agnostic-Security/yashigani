# Wazuh SIEM on Linux / Docker 29.x — fixes (v2.25.1)

Status: **HTTPS restore + securityadmin automation VALIDATED green on the 2.25.1 config
(AMD64 / Docker 29.1.3, 2026-05-30).** One follow-up is installer-scope: verified mTLS
(server-cert verification) is blocked until the indexer is put on the internal CA — see
"Verified mTLS — installer work-item" below. Full validation report:
`testing_runs/yashigani/wazuh-2251-validation/VALIDATION.md`.

Validated PASS: dependency chain (no deadlock), `wazuh-security-init` securityadmin
(exit 0, security index created), indexer cluster **green** over HTTPS, all healthchecks
go **healthy** (were false-unhealthy), manager **0 restarts**, filebeat→indexer **TLSv1.2**
handshake OK, end-to-end audit write/read over HTTPS (HTTP 201 + read-back).

## TL;DR

v2.25.0-prep's `docker/docker-compose.wazuh.yml` pointed the **manager**
(`INDEXER_URL`), **dashboard** (`OPENSEARCH_HOSTS` / `WAZUH_API_URL`) and all three
**healthchecks** at `http://` — while the `wazuh-indexer` image serves **TLS on 9200
by default** (the OpenSearch security plugin is ON; there is no `DISABLE_SECURITY`).
That is a **broken, plaintext-intent** configuration:

- the `http://` healthchecks never succeed against the TLS listener → containers
  flap **false-unhealthy**, and `depends_on: service_healthy` stalls the stack;
- any traffic that did flow would be **unencrypted** — unacceptable for internal
  SIEM traffic.

**Internal Wazuh traffic must be HTTPS + mTLS.** Wazuh/OpenSearch support this
natively (proven on v2.24.4) — **no TLS sidecar is needed.** This change reverses
the `http://` downgrade and carries the Docker-29.x boot fixes.

## What changed in `docker-compose.wazuh.yml`

| Area | v2.25.0-prep (wrong) | v2.25.1 (this fix) |
|---|---|---|
| manager → indexer | `INDEXER_URL: http://…` | `https://…` + filebeat mTLS (`SSL_CERTIFICATE`/`_KEY`/`_AUTHORITIES`, `FILEBEAT_SSL_VERIFICATION_MODE: full`) |
| manager cert mounts | none | `wazuh-manager_client.crt/.key` + `ca_root.crt` mounted to the paths the env already referenced |
| indexer healthcheck | `curl http://localhost:9200` | `curl -k https://localhost:9200` (200/401/403 all prove TLS + security up) |
| dashboard → indexer | `OPENSEARCH_HOSTS: http://…`, `SERVER_SSL_ENABLED:false` | `opensearch_dashboards.yml` mounted → `https://wazuh-indexer:9200` |
| dashboard → manager API | `WAZUH_API_URL: http://…` | `https://…` |

## Docker 29.x boot fixes (carried from the E2E)

1. **Volume-mount-readiness race** — the stock s6 `cont-init` runs `find`/`cp` over
   per-subdir volume mounts before they are ready (~94% of cycles on Docker 29.1.3)
   and `error_and_exit`s the boot. Fix: patched `docker/wazuh-patch/0-wazuh-init`
   logs the miss and **continues** instead of aborting. **Mount it writable** (not
   `:ro`) — s6 chmods it on boot.
2. **`cap_drop:[ALL]` vs the s6 entrypoint** — Wazuh must chown/setuid to `wazuh(999)`
   and `chroot` analysisd into `/var/ossec`. Grant minimal caps incl. **`SYS_CHROOT`**
   and **`SETPCAP`** on the manager; the indexer/dashboard need the chown/setuid set.
   `no-new-privileges:true` retained everywhere.
3. **filebeat certs never mounted** — the manager env referenced cert paths the stock
   compose never mounted, so filebeat could not establish TLS. Now mounted.
4. **dashboard had no `opensearch_dashboards.yml`** — the image ships none; mounted a
   minimal one pointing at the HTTPS indexer.
5. **Healthchecks were false-unhealthy** — `curl -sf https://localhost:9200 -k` fails on
   the **503** ("security not initialized") and the **401** a security-enabled indexer
   returns (`-f` errors on HTTP≥400), so the indexer never reported healthy (seen live:
   the v2.24.4 deploy clone's three wazuh containers all "unhealthy" over a green cluster).
   With `wazuh-security-init` gating on `indexer healthy`, that would **deadlock**. Fixed:
   indexer/dashboard healthchecks now match the HTTP status code (`200|401|403` /
   `200|302|401`), the sidecar gates on `service_started` (its own wait-loop blocks on the
   TLS port — `curl -o /dev/null` succeeds on 503), and the indexer `start_period` is 150 s
   so it stays "starting" (not "unhealthy") while the sidecar initialises security.

## Security-index init (`securityadmin`) — AUTOMATED

The `wazuh-security-init` one-shot service runs securityadmin automatically once the
indexer TLS listener is up, using the admin cert baked into the indexer image
(`-cd …/config/opensearch-security -cacert/-cert/-key …/config/certs/{root-ca,admin,admin-key}.pem
-h wazuh-indexer`). Manager + dashboard gate on `service_completed_successfully`.
**Validated 2026-05-30:** exit 0, "Done with success", `.opendistro_security` created,
10 config types applied. No manual step.

## Verified mTLS — INSTALLER work-item (Finding 1)

filebeat currently runs `WAZUH_FILEBEAT_SSL_VERIFICATION_MODE=none` (TLS-encrypted but the
server cert is **not** verified). Root cause: the `wazuh-indexer` image ships the **Wazuh
demo PKI** (server SAN `demo.indexer`, `admin_dn=CN=admin,OU=Wazuh`, `nodes_dn=CN=demo.indexer`)
while the installer issues the indexer an internal-CA cert (`wazuh-indexer_client.crt`,
`O=Agnostic Security`, SAN `wazuh-indexer`) but **never mounts it onto the container**. The
two PKIs are disjoint, so `full`/`certificate` verification cannot succeed and filebeat
won't ship. To enable verified mTLS (then flip the env to `full` — one line):
1. mount `wazuh-indexer_client.crt` (fullchain) + `.key` over
   `/usr/share/wazuh-indexer/config/certs/indexer.pem` + `indexer-key.pem`;
2. mount the internal-CA chain (root+intermediate) over `…/certs/root-ca.pem`;
3. set `plugins.security.nodes_dn: [CN=wazuh-indexer,O=Agnostic Security]`;
4. issue+mount an internal-CA admin cert, set `plugins.security.authcz.admin_dn` to its DN;
5. re-run securityadmin (the sidecar already does this).

## Follow-ups before / at release

- [x] **e2e validation on the 2.25.1 config** — done 2026-05-30 (PASS; see VALIDATION.md).
- [x] **Automate `securityadmin`** — done (`wazuh-security-init` sidecar, validated).
- [ ] **Enable verified mTLS** — installer work-item above; flip `WAZUH_FILEBEAT_SSL_VERIFICATION_MODE`
      to `full` once the indexer is on the internal CA.
- [ ] **Reconcile secret names** — the override expects `/run/secrets/wazuh_admin_password`
      and `wazuh_api_key`; the 2026-05-29 installer generated `wazuh_api_password` /
      `wazuh_indexer_password` / `wazuh_dashboard_password` instead. Align installer↔compose.
- [ ] **Harden dashboard→indexer credentials** — `opensearch_dashboards.yml` carries the
      OpenSearch demo default (`admin`/`admin`); replace with the bootstrap-generated indexer
      credential (customise `internal_users.yml` + re-run `securityadmin`).
- [ ] **Bump indexer mem_limit** — idle indexer sat ~918 MiB / 1 GiB; set
      `YASHIGANI_WAZUH_INDEXER_MEM_LIMIT` ≥ 2g for real ingest.
- [ ] Confirm the SiemSink `wazuh_api_key` (KMS) path against the HTTPS `_bulk` endpoint.
