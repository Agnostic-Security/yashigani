#!/usr/bin/env bash
# yashigani-rebundle.sh — Re-sign / re-inject for legitimate rebuilds (LR-02 fix)
#
# PURPOSE
#   When a legitimate operator performs a BYO-CA rotation, applies a lawful
#   source patch, or otherwise rebuilds Yashigani from source, the hash-bundle
#   constants in _integrity.py need to be re-computed and re-signed with the
#   counter private key.  Without a valid bundle, the runtime restrains the
#   deployment to Community limits — correct behaviour for tampered images,
#   but incorrect for a legitimate rebuild.
#
#   This script re-runs steps 1–5 of inject_hashes.sh against an already-built
#   source tree.  It is a Yashigani-side operation: the counter private key is
#   required and is held by Yashigani signing infrastructure only.
#
# USAGE (Yashigani signing infra — not the operator's machine)
#   COUNTER_KEY_PATH=/secure/signing-machine/keys/release-<VERSION>/yashigani_counter_private.pem \
#   COUNTER_PUB_KEY_PATH=/secure/signing-machine/keys/release-<VERSION>/yashigani_counter_public.pem \
#   SRC_ROOT=/path/to/patched/src \
#   bash scripts/yashigani-rebundle.sh
#
# OPERATOR WORKFLOW (BYO-CA rotation / lawful patch)
#   1. Operator notifies Yashigani support of the planned rebuild.
#   2. Yashigani signs infra pulls the patched source (or accepts a source tarball).
#   3. This script runs on the signing machine with the release counter key.
#   4. A new signed _integrity.py is provided to the operator.
#   5. Operator rebuilds the image/wheel against the signed _integrity.py.
#   6. Runtime checks pass; deployment returns to paid tier.
#
#   Alternative (operator holds counter key — advanced / Enterprise only):
#   When an Enterprise customer has been granted the counter key for self-service
#   rebuilds, they may run this script directly.  The counter key must still be
#   held in their own HSM/signing infra — never baked into the image.
#
# ENVIRONMENT (same as inject_hashes.sh)
#   COUNTER_KEY_PATH        Path to counter private key PEM  [required]
#   COUNTER_PUB_KEY_PATH    Path to counter public key PEM   [required]
#   SRC_ROOT                Python source root               [default: src/]
#   FIPS_MODE               1 = use OpenSSL FIPS provider     [default: 0]
#   COMMUNITY_SEAT_POLICY   KDF seat policy                  [default: 20,5,2]
#
# NOTE: This script delegates entirely to inject_hashes.sh, which implements
# the canonical 5-step injection order.  Any change to the injection protocol
# must be made in inject_hashes.sh; this script is a thin convenience wrapper
# that adds operator-facing documentation and a pre-flight check.

set -euo pipefail
IFS=$'\n\t'

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
INJECT_SCRIPT="${SCRIPT_DIR}/inject_hashes.sh"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

: "${COUNTER_KEY_PATH:?COUNTER_KEY_PATH must be set}"
: "${COUNTER_PUB_KEY_PATH:?COUNTER_PUB_KEY_PATH must be set}"

if [ ! -f "${INJECT_SCRIPT}" ]; then
    printf 'ERROR: inject_hashes.sh not found at %s\n' "${INJECT_SCRIPT}" >&2
    exit 1
fi

SRC_ROOT="${SRC_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)/src}"
INTEGRITY_PY="${INTEGRITY_PY:-${SRC_ROOT}/yashigani/licensing/_integrity.py}"

if [ ! -f "${INTEGRITY_PY}" ]; then
    printf 'ERROR: _integrity.py not found at %s\n' "${INTEGRITY_PY}" >&2
    printf '       Set SRC_ROOT or INTEGRITY_PY environment variable\n' >&2
    exit 1
fi

printf '[rebundle] Starting re-injection for legitimate rebuild / BYO-CA rotation\n'
printf '[rebundle] SRC_ROOT:             %s\n' "${SRC_ROOT}"
printf '[rebundle] INTEGRITY_PY:         %s\n' "${INTEGRITY_PY}"
printf '[rebundle] COUNTER_PUB_KEY_PATH: %s\n' "${COUNTER_PUB_KEY_PATH}"
printf '[rebundle] COUNTER_KEY_PATH:     %s (not logged in full for security)\n' \
    "$(dirname "${COUNTER_KEY_PATH}")/..."

# ---------------------------------------------------------------------------
# Warn if the source tree looks unmodified (belt-and-suspenders)
# ---------------------------------------------------------------------------

if grep -q 'PLACEHOLDER_YASHIGANI_INTEGRITY' "${INTEGRITY_PY}" 2>/dev/null; then
    printf '[rebundle] NOTE: _integrity.py still contains placeholders — running fresh injection\n'
fi

# ---------------------------------------------------------------------------
# Delegate to inject_hashes.sh (the canonical 5-step implementation)
# ---------------------------------------------------------------------------

export COUNTER_KEY_PATH
export COUNTER_PUB_KEY_PATH
export SRC_ROOT
export INTEGRITY_PY
export SCRIPT_DIR
export FIPS_MODE="${FIPS_MODE:-0}"
export COMMUNITY_LICENCE_ID="${COMMUNITY_LICENCE_ID:-}"
export COMMUNITY_SEAT_POLICY="${COMMUNITY_SEAT_POLICY:-20,5,2}"

bash "${INJECT_SCRIPT}"

printf '[rebundle] Re-bundle complete. Rebuild the wheel/image against the updated _integrity.py.\n'
printf '[rebundle] Next step: pip install -e . (or python -m build --wheel) to activate.\n'
