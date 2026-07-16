"""
Mesh ring-topology generator — licence-hardening-v2 Phase C
(LAURA-V2-003 hardening, 2026-07-16).

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     §5/§11 addendum (6-file mutual-integrity mesh) +
     testing_runs/yashigani/licence-v2-redteam-laura-v2001-verify-20260715T235500Z.md
     (LAURA-V2-003: coordinated verifier.py+enforcer.py checker-neutering
     silently suppresses the tamper alarm — the finding this mesh closes).

BUILD-TIME ONLY. This module is invoked from exactly two places:
  1. scripts/inject_hashes.sh (the build pipeline), which calls
     compute_ring_order() once per release to derive MESH_TOPOLOGY_JSON,
     then embeds+signs the RESULT into _integrity.py.
  2. Tests, to independently confirm a given (version, seed) reproduces the
     expected ring order.

It is deliberately NEVER imported by any of the six runtime enforcement
files (licensing/verifier.py, licensing/enforcer.py,
licensing/gate_middleware.py, sso/oidc.py, backoffice/routes/sso.py,
backoffice/routes/scim.py) — those files only ever read the already-
computed, already-signed MESH_TOPOLOGY_JSON constant from _integrity.py at
their own module-load time. This is intentional and load-bearing: even if
an attacker with local write access somehow altered this file inside a
running deployment, it would have ZERO effect, because the ring order it
would produce is never consulted at check time — only the value ALREADY
BAKED into the signed bundle at build time is. This module is build
tooling, not a runtime trust boundary.

RANDOMIZATION IS OBSCURITY, NOT A NEW CRYPTOGRAPHIC PROPERTY (say this
plainly, no overclaim): the 6-file ring is a Hamiltonian cycle regardless
of which specific permutation is drawn — the graph-connectivity guarantee
("any proper nonempty subset of tampered files leaves at least one
untouched file whose ring-check target is tampered, hence at least one
independent detector always fires") holds IDENTICALLY for every possible
ordering. What per-release randomization buys is that a coordinated-edit
strip-script written against release N's specific topology ("patch lines X
in file A, line Y in file B, ...") does not carry over to release N+1 — the
attacker must re-derive which file checks which neighbour every release.
This raises attacker TIME/tooling-reuse cost. It does not change the
underlying detection guarantee, and it is not a substitute for the
signature-based BUNDLE_SIG chain, which is the actual cryptographic control.
"""
from __future__ import annotations

import hashlib
import random

# The 6 mesh roles. Order in this tuple is irrelevant — it is only the
# SOURCE list that gets permuted; it is NOT the ring order itself.
MESH_ROLES: tuple[str, ...] = (
    "VERIFIER",
    "ENFORCER",
    "GATE_MIDDLEWARE",
    "OIDC",
    "SSO_ROUTES",
    "SCIM_ROUTES",
)


def compute_ring_order(version: str, seed: str) -> list[str]:
    """
    Deterministically compute this release's mesh ring order from
    (version, seed).

    Reproducibility: the SAME (version, seed) pair always produces the SAME
    ring order — required so a build can be re-derived/audited later given
    the recorded seed. A DIFFERENT seed (the normal case — a fresh random
    seed is drawn at each release cut, see scripts/inject_hashes.sh) yields
    a different, unpredictable-in-advance cyclic ordering of the same 6
    roles.

    Raises ValueError on empty version/seed — never silently substitutes a
    default (a silently-constant topology would defeat the entire point of
    per-release randomization).
    """
    if not version or not version.strip():
        raise ValueError("version must be non-empty")
    if not seed or not seed.strip():
        raise ValueError("seed must be non-empty")

    digest = hashlib.sha256(f"{version.strip()}:{seed.strip()}".encode("utf-8")).hexdigest()
    rng = random.Random(int(digest, 16))
    order = list(MESH_ROLES)
    rng.shuffle(order)
    return order


def validate_ring_order(ring_order: object) -> bool:
    """
    Return True iff `ring_order` is a well-formed permutation of MESH_ROLES
    (a list containing each of the 6 role names exactly once, any order).

    Used by tests and by scripts/inject_hashes.sh's own post-embed sanity
    check. The runtime ring-check files each re-implement an equivalent
    (but deliberately differently-styled) validation inline — this function
    is not imported by them (see module docstring).
    """
    if not isinstance(ring_order, list):
        return False
    return sorted(ring_order) == sorted(MESH_ROLES)
