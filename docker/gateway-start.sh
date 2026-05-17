#!/bin/sh
# Yashigani Gateway — dual-port startup wrapper
#
# Starts two uvicorn processes:
#   Port 8080 (mTLS) — external-facing, Caddy ingress only (caddy_internal network)
#   Port 8081 (HTTP) — internal mesh, Open WebUI ingress only (data network)
#
# The mTLS port requires ssl.CERT_REQUIRED + CaddyVerifiedMiddleware.
# The mesh port is plain HTTP, protected by Docker/K8s network isolation only.
#
# Signal handling: SIGTERM/SIGINT is forwarded to both uvicorn processes.
# When either exits, the other is killed and the wrapper exits with the same code.

set -eu

# ── mTLS port 8080 ─────────────────────────────────────────────────────────
uvicorn yashigani.gateway.entrypoint:app \
    --host 0.0.0.0 \
    --port 8080 \
    --ssl-keyfile  /run/secrets/gateway_client.key \
    --ssl-certfile /run/secrets/gateway_client.crt \
    --ssl-ca-certs /run/secrets/ca_root.crt \
    --ssl-cert-reqs 2 \
    --no-access-log &
MTLS_PID=$!

# ── Internal mesh port 8081 ─────────────────────────────────────────────────
uvicorn yashigani.gateway.mesh_entrypoint:app \
    --host 0.0.0.0 \
    --port 8081 \
    --no-access-log &
MESH_PID=$!

# ── Signal forwarding ───────────────────────────────────────────────────────
_stop() {
    kill "$MTLS_PID" "$MESH_PID" 2>/dev/null || true
}
trap _stop TERM INT

# Wait for either process to exit; kill the other
wait -n 2>/dev/null || {
    # Fallback for shells that don't support wait -n
    wait "$MTLS_PID" "$MESH_PID"
}
EXIT_CODE=$?
kill "$MTLS_PID" "$MESH_PID" 2>/dev/null || true
exit $EXIT_CODE
