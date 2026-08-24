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

# DP-Y-004 §3.1 SECURITY PRECONDITION — single uvicorn worker (--workers 1,
# the uvicorn default; do NOT raise this above 1 without migrating state).
#
# The DP-Y-004 single-use guarantee relies on the ``CorrespondenceTable``
# ``consumed`` flag, the ``_results`` dict, and the ``_burned`` set all living
# in a SINGLE process's memory under a SINGLE-THREADED asyncio event loop.
# The consumed check+set is atomic ONLY because there is no ``await`` between
# them in that single thread (CPython asyncio non-preemptible synchronous
# block).  Raising ``--workers`` above 1 creates SEPARATE per-worker copies of
# ``_results``, ``_burned``, and ``consumed`` — two workers can both observe
# ``consumed=False`` and both serve the correspondence table, silently breaking
# single-use.  To scale horizontally, migrate ``_results`` and ``_burned`` to
# a shared external store (Redis) and replace the consumed flag with an atomic
# compare-and-set (e.g. Redis SET NX).
exec uvicorn yashigani.backoffice.entrypoint:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-keyfile  /run/secrets/backoffice_client.key \
    --ssl-certfile /run/secrets/backoffice_client.crt \
    --ssl-ca-certs /run/secrets/ca_root.crt \
    --ssl-cert-reqs 2 \
    --no-access-log
