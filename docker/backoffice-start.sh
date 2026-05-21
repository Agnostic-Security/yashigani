#!/bin/sh
# Yashigani Backoffice — startup wrapper
#
# Sets umask 0077 so every file created by uvicorn, alembic, or any
# Python-layer code defaults to 0600 (owner-only), not 0644.
# Defence-in-depth: closes the class of world-readable runtime-written
# files regardless of whether the caller remembered os.chmod().
#
# Ref: Tom audit finding on 214c4fd (ISSUE-027 collateral — container
# umask default 0022 causes Python open() to create files at 0644).

umask 0077

exec uvicorn yashigani.backoffice.entrypoint:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-keyfile  /run/secrets/backoffice_client.key \
    --ssl-certfile /run/secrets/backoffice_client.crt \
    --ssl-ca-certs /run/secrets/ca_root.crt \
    --ssl-cert-reqs 2 \
    --no-access-log
