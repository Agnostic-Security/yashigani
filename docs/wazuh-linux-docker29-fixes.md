# Wazuh SIEM on Linux / Docker Engine 29.x — deployment findings & fixes

From an end-to-end deploy test of **v2.24.4** (`--deploy production --wazuh …`) on **Ubuntu 22.04, Docker Engine 29.1.3 (overlayfs)**, 2026-05-30. The full Wazuh stack (manager + indexer + dashboard) did **not** come up; the manager crash-looped indefinitely. Below is the complete root-cause chain and the fixes that brought it to a functional SIEM (indexer cluster **green**, manager stable with `analysisd` + core daemons running).

> Note: these were diagnosed against the v2.24.4 compose (wazuh-manager defined in `docker/docker-compose.yml` **and** `docker/docker-compose.wazuh.yml` — a duplicate, see #4). The `docker-compose.wazuh.yml` layout differs on some branches; apply the relevant fixes to whichever single definition you keep. The exact v2.24.4 compose diff is in `docs/wazuh-compose-v2.24.4.patch`.

## The 8 stacked bugs (in discovery order)

1. **Host `vm.max_map_count` too low** (`65530 < 262144`) → indexer OpenSearch bootstrap check fails.
   Fix: pre-set it (sysctl init / privileged init container). No host edit needed at runtime: `docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144`.

2. **`cap_drop:[ALL]` is incompatible with Wazuh.** The s6 entrypoint must `chown`/`setuid` to the `wazuh`(999)/`wazuh-indexer`(1000) users and `chroot`. With all caps dropped, root obeys DAC → `Permission denied` on `ossec.conf`, can't drop privileges.
   Fix: `cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, FSETID, SETGID, SETUID, KILL, SETPCAP]` (or simply don't `cap_drop:[ALL]` for the wazuh services). *(Branches that already removed `cap_drop:[ALL]` get Docker's default caps, which cover these — but still need #3.)*

3. **Manager needs `CAP_SYS_CHROOT`** (`wazuh-analysisd` chroots into `/var/ossec`). It IS in Docker's default cap set, but NOT when you `cap_drop:[ALL]` + selectively `cap_add`. Add `SYS_CHROOT` to the manager's `cap_add`.

4. **Duplicate `wazuh-manager` definition** (`docker-compose.yml` **and** `docker-compose.wazuh.yml`) with **conflicting `INDEXER_URL`** (`https://` vs `http://`). When both `-f` files merge, the overlay's `http` wins (breaks manager↔indexer TLS) and volume lists *append*. Fix: keep ONE definition; `INDEXER_URL=https://wazuh-indexer:9200`.

5. **Flaky `0-wazuh-init` cont-init `cp` restore** (~90% of container starts fail: `Error executing command: cp -ar …/var/ossec/var/multigroups…`). NOT reproducible in isolation (the same `cp` succeeds by hand) — an intrinsic timing flake of the wazuh 4.14.5 image init under Docker 29.x. Independent of named volumes vs image-layer.
   Mitigation: the empty runtime dirs (`var/multigroups`, `agentless`, `integrations`, `active-response/bin`) are non-critical — make their restore **non-fatal**. See `docker/wazuh-patch/0-wazuh-init` (bind-mount over `/etc/cont-init.d/0-wazuh-init`); the only change is the restore `cp` → `… || echo WARN` instead of `error_and_exit`.

6. **The patched cont-init must be bind-mounted writable, NOT `:ro`.** s6's `ensuring user provided files have correct perms` runs `s6-chmod` on `/etc/cont-init.d/*`; a read-only mount → `s6-chmod fatal: Read-only file system` → s6 tears the container down. Mount without `:ro`.

7. **filebeat→indexer mTLS certs referenced but never mounted.** The manager env points `SSL_CERTIFICATE=/etc/wazuh-indexer/certs/wazuh.manager.pem`, `SSL_KEY=…-key.pem`, `SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem`, but the compose never mounts them → filebeat `Exiting: error initializing publisher … no such file` → s6 teardown. The certs exist in `docker/secrets/` (`wazuh-manager_client.crt/key`, `ca_root.crt`) — just mount them:
   ```yaml
   - ./secrets/wazuh-manager_client.crt:/etc/wazuh-indexer/certs/wazuh.manager.pem:ro
   - ./secrets/wazuh-manager_client.key:/etc/wazuh-indexer/certs/wazuh.manager-key.pem:ro
   - ./secrets/ca_root.crt:/etc/ssl/root-ca.pem:ro
   ```
   *(On http-only branches that don't set SSL_* env, this doesn't apply.)*

8. **Indexer security index never initialized** (`OpenSearch Security not initialized` / `.opendistro_security not found`, HTTP 503). The wazuh-indexer entrypoint's `securityadmin` run isn't firing here. Run it once:
   ```sh
   docker exec docker-wazuh-indexer-1 bash \
     /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
     -cd /usr/share/wazuh-indexer/config/opensearch-security -icl -nhnv \
     -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
     -cert  /usr/share/wazuh-indexer/config/certs/admin.pem \
     -key   /usr/share/wazuh-indexer/config/certs/admin-key.pem
   ```
   → cluster goes **green**. Should be an init container / entrypoint step.

## Also: mis-written healthchecks (false "unhealthy")

- **Indexer**: `curl -sf https://localhost:9200` returns **401** once security is enabled (auth required) → `-f` fails → container marked unhealthy though the cluster is green. Use `curl -sk -u admin:<pw> https://localhost:9200/_cluster/health` or accept 401 as "up".
- These false-unhealthy labels also stall `depends_on: service_healthy` for the manager/dashboard.

## Outcome after fixes
- indexer: cluster **green**, security initialized, stable (restarts=0)
- manager: **stable (restarts=0)**, `analysisd` + 9 other core daemons running
- dashboard: residual flap (own cert/auth path — not yet root-caused)

Recommended productionization: bake the caps + `SYS_CHROOT`, the non-fatal cont-init (or pin a different upstream wazuh image tag (compose only)), the filebeat cert mounts, an auto `securityadmin` init, correct healthchecks, and `vm.max_map_count` provisioning into the installer/compose so the SIEM comes up unattended.
