# Podman Deployment Guide
<!-- Last updated: 2026-07-13 (rootless is the supported macOS mode; removed stale rootful-machine requirement -- podman is always rootless, no root access needed) -->

Yashigani supports Podman as a drop-in Docker replacement. The Pool Manager
(container-per-identity isolation, required for CIAA compliance) needs access
to the Podman socket to create per-user agent containers.

## macOS (Podman Machine)

Podman on macOS runs a Linux VM. The Pool Manager needs the VM's libpod
socket bridged to the macOS host.

### Setup: rootless machine

```bash
podman machine init
podman machine start
```

Podman on macOS is **always rootless** -- no root access is required. The
default machine exposes the rootless libpod socket, which the compose override
bind-mounts into the gateway container at `/var/run/container.sock` (read-only)
for the Pool Manager.

### Why rootless?

Rootless Podman is the supported mode on every platform -- macOS, Linux, and
production. There is **no rootful requirement and no need for root access**: the
Pool Manager creates per-identity agent containers over the rootless podman
socket. (Earlier releases documented a rootful machine for internal-network
joining; that limitation has been resolved -- the rootful step is no longer
needed, and this section is kept so operators following older guides know to
skip it.)

### Verify

```bash
podman machine info           # a running rootless machine
podman info                   # should succeed
```

## Linux (systemd user socket)

```bash
systemctl --user enable --now podman.socket
loginctl enable-linger "$USER"  # keeps socket alive across logout
```

The compose override automatically uses `/run/user/$UID/podman/podman.sock`.
No rootful requirement on Linux -- user namespaces handle isolation.

## Troubleshooting

- **"Pool Manager: no Docker or Podman SDK available -- running in STUB MODE"**:
  the gateway container cannot reach any container socket. On macOS,
  restart the rootless machine (`podman machine stop && podman machine start`)
  and confirm the socket is exposed. On Linux, check the podman socket
  unit is active: `systemctl --user status podman.socket`.

- **Stub mode is NEVER acceptable in production** -- it disables container-per-
  identity isolation and breaks CIAA compliance claims.

## Storage Management

Rootless Podman accumulates image layers and build cache over time, particularly during active development and release cycles. When disk usage becomes a concern, operators should follow the prune SOP:

- **Dangling image prune** (safe, run freely): `podman image prune`
- **Unused image prune** (verify no running containers first): `podman image prune --all --filter until=168h`
- **System prune** (stopped containers + dangling images): `podman system prune`

**Critical constraint:** never add `--volumes` to any prune command and never run `podman volume rm` without explicit operator authorisation. Named Yashigani volumes (postgres data, Redis, audit logs, PKI) are irreplaceable without a verified backup.

The full storage prune SOP — including per-agent namespace isolation behaviour, schedule recommendations, and recovery procedures — is available to licensed operators as an internal runbook. Contact your account team for access.
