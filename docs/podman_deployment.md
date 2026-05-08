# Podman Deployment Guide
<!-- Last updated: 2026-05-08T13:00:00+01:00 -->

Yashigani supports Podman as a drop-in Docker replacement. The Pool Manager
(container-per-identity isolation, required for CIAA compliance) needs access
to the Podman socket to create per-user agent containers.

## macOS (Podman Machine)

Podman on macOS runs a Linux VM. The Pool Manager needs the VM's libpod
socket bridged to the macOS host.

### Required: rootful machine

```bash
podman machine stop 2>/dev/null || true
podman machine rm -f 2>/dev/null || true
podman machine init --rootful
podman machine start
```

This exposes a Docker-compatible socket at `/var/run/docker.sock` on the
macOS host. The compose override bind-mounts it into the gateway container
at `/var/run/container.sock` (read-only).

### Why rootful?

Rootless Podman Machine cannot create containers that join the Yashigani
internal network from outside the VM's user namespace. Rootful mode is
required for full Pool Manager isolation. This is a trust boundary on your
developer workstation only -- production deployments use Linux rootful
podman or Kubernetes.

### Verify

```bash
ls -l /var/run/docker.sock   # should be a socket
podman --remote info          # should succeed
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
  re-run the rootful machine init above. On Linux, check the podman socket
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
