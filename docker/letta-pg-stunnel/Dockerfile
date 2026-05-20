# letta-pg-stunnel — multi-arch stunnel sidecar for letta→postgres mTLS
#
# Base: alpine:3.20 (current LTS as of 2026-05-20). Chosen over alpine:3.21
# because 3.20 is the active stable release with guaranteed security backports
# through 2026-11. Alpine is the correct base for a ~4 MB stunnel sidecar —
# no glibc bloat, minimal attack surface, stunnel in the official apk tree.
#
# This image replaces docker.io/dweomer/stunnel:latest which is amd64-only
# (single-arch manifest, no arm64 variant on Docker Hub). Building locally
# from alpine ensures the image runs natively on the host's arch (amd64 / arm64).
#
# Security posture:
#   - Non-root user stunnel (UID 101, GID 101) — created below
#   - No USER-directive-then-root-drop (dweomer pattern) — we start as non-root
#   - cap_drop ALL enforced in compose / Helm (no capabilities needed post-bind)
#   - Port 5432 is >= 1024 so no NET_BIND_SERVICE needed
#   - read_only: true compatible — /etc/stunnel, /var/run/stunnel, /var/log/stunnel
#     are tmpfs mounts provided by compose/Helm at runtime
#   - No package index cache retained (--no-cache)

FROM alpine:3.20

# stunnel: the TLS proxy itself
# ca-certificates: system CA bundle (for update-ca-certificates)
# netcat-openbsd: nc binary used in healthcheck (nc -z 127.0.0.1 5432)
RUN apk add --no-cache stunnel ca-certificates netcat-openbsd

# Create a dedicated non-root stunnel user.
# UID/GID 101 is conventionally used for stunnel on Alpine; it doesn't conflict
# with any Alpine system account (100 = xfs, 65534 = nobody).
# --no-create-home: no home dir (nothing to write to in read-only rootfs).
# --disabled-password: service account, no login.
RUN addgroup -g 101 -S stunnel && \
    adduser -u 101 -S -G stunnel -H -D stunnel

# entrypoint.sh generates stunnel.conf from STUNNEL_* env vars and execs stunnel.
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# Runtime write paths come from tmpfs mounts in compose/Helm:
#   /etc/stunnel        — generated stunnel.conf
#   /var/run/stunnel    — PID file
#   /var/log/stunnel    — log output
# These paths are owned by root in the image; tmpfs mounts shadow them at runtime
# and are writable by any process regardless of UID (mode=0755 in compose tmpfs).
# We do NOT mkdir them here — tmpfs mounts replace them entirely.

USER 101

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD nc -z 127.0.0.1 5432

ENTRYPOINT ["/entrypoint.sh"]
