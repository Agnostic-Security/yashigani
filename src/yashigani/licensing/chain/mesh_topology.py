"""
Mesh full-graph topology generator — licence-hardening-v2 Phase D
(LAURA-V2-003 RE-VERIFY hardening, 2026-07-17).

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     §5/§11 addendum (mutual-integrity mesh) +
     testing_runs/yashigani/licence-v2-redteam-mesh-verify-20260717/
     (LAURA-V2-003 RE-VERIFY: the Phase C RING topology left per-feature
     blind spots — a 3-file {verifier,enforcer,gate_middleware} edit
     silently defeated SCIM end-to-end, and a 4-file edit adding
     routes/sso.py silently defeated SAML end-to-end, both well below the
     accepted "any 1-5 file edit is caught" bar. Root cause: each file only
     checked its 2 RING-NEIGHBOURS, so a file whose 2 neighbours (for that
     release's random permutation) didn't happen to include the touched
     files was blind to them; the shared verifier/enforcer-getter fallback
     was the SAME pair the attacker had already neutered. Fix: every mesh
     member now independently checks EVERY OTHER member — a complete graph,
     not a cycle — closing the blind-spot class structurally rather than
     patching the topology.)

BUILD-TIME ONLY. This module is invoked from exactly two places:
  1. scripts/inject_hashes.sh (the build pipeline), which calls
     compute_mesh_order() once per release to derive MESH_TOPOLOGY_JSON,
     then embeds+signs the RESULT into _integrity.py.
  2. Tests, to independently confirm a given (version, seed) reproduces the
     expected member order.

It is deliberately NEVER imported by any of the seven runtime enforcement
files (licensing/verifier.py, licensing/enforcer.py,
licensing/gate_middleware.py, sso/oidc.py, sso/saml.py,
backoffice/routes/sso.py, backoffice/routes/scim.py) — those files only
ever read the already-computed, already-signed MESH_TOPOLOGY_JSON constant
from _integrity.py at their own module-load time. This is intentional and
load-bearing: even if an attacker with local write access somehow altered
this file inside a running deployment, it would have ZERO effect, because
the order it would produce is never consulted at check time — only the
value ALREADY BAKED into the signed bundle at build time is. This module is
build tooling, not a runtime trust boundary.

WHY A COMPLETE GRAPH, NOT A RING (Phase D, 2026-07-17 — supersedes Phase
C's hexagonal-cycle design after LAURA-V2-003's re-verify disproved it):
Phase C connected the mesh members into ONE cycle so that any nonempty
proper subset of tampered files always left SOME untouched file whose
cycle-neighbour was in that subset — true, but insufficient: "some detector
fires somewhere" is not the same guarantee as "the specific gate deciding
THIS feature is blocked". A file whose 2 ring-neighbours happened not to be
among the touched set was fully blind to that edit, and its fallback (the
shared verifier/enforcer getters) was exactly the pair already neutered by
the same edit. A COMPLETE graph closes this precisely: every member checks
EVERY OTHER member's bytes, so ANY untouched member independently detects
ANY nonempty subset of tampered members in full — there is no "blind
neighbour" configuration to land in, for any topology, for any feature.

RANDOMIZATION IS OBSCURITY, NOT A NEW CRYPTOGRAPHIC PROPERTY (say this
plainly, no overclaim): completeness of the graph does not depend on the
member order at all — every member checks every other member regardless of
any permutation. What per-release randomization still buys, now purely as
strip-script resistance: (a) MESH_TOPOLOGY_JSON's member order determines
the ITERATION order each file walks its 6 peers in, so a strip-script
hardcoded against one release's specific line-by-line check sequence does
not carry over to the next; (b) a malformed/missing member order is itself
treated as tamper (see is_mesh_topology_placeholder()), so the constant
remains a live, checked part of the signed bundle even though it no longer
gates WHICH peers are checked (all of them always are). This raises
attacker TIME/tooling-reuse cost. It is not a substitute for the
signature-based BUNDLE_SIG chain, which is the actual cryptographic
control.
"""
from __future__ import annotations

import hashlib
import random

# The 7 mesh roles. Order in this tuple is irrelevant — it is only the
# SOURCE list that gets permuted; it is NOT a ring order, and (Phase D) no
# longer determines who checks whom — every member checks every OTHER
# member unconditionally. SAML is a full mesh member as of Phase D
# (2026-07-17 — LAURA-V2-003 re-verify: sso/saml.py being held out of the
# Phase C ring left the SAML enforcement path with zero mesh coverage of
# its own, only the pre-existing shared verifier/enforcer-getter fallback,
# which is exactly what the 4-file SAML bypass exploited).
MESH_ROLES: tuple[str, ...] = (
    "VERIFIER",
    "ENFORCER",
    "GATE_MIDDLEWARE",
    "OIDC",
    "SAML",
    "SSO_ROUTES",
    "SCIM_ROUTES",
)


def compute_mesh_order(version: str, seed: str) -> list[str]:
    """
    Deterministically compute this release's mesh member order from
    (version, seed).

    Phase D: this order is NOT a ring/neighbour-selection order any more —
    every mesh member checks every OTHER member regardless of ordering. The
    order is used only as each file's own PEER-ITERATION order (which of
    its 6 checks it performs first) — cosmetic per-release polymorphism for
    strip-script resistance, not a detection-completeness input.

    Reproducibility: the SAME (version, seed) pair always produces the SAME
    member order — required so a build can be re-derived/audited later
    given the recorded seed. A DIFFERENT seed (the normal case — a fresh
    random seed is drawn at each release cut, see scripts/inject_hashes.sh)
    yields a different, unpredictable-in-advance ordering of the same 7
    roles.

    Raises ValueError on empty version/seed — never silently substitutes a
    default (a silently-constant order would defeat the entire point of
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


def validate_mesh_order(member_order: object) -> bool:
    """
    Return True iff `member_order` is a well-formed permutation of
    MESH_ROLES (a list containing each of the 7 role names exactly once,
    any order).

    Used by tests and by scripts/inject_hashes.sh's own post-embed sanity
    check. The runtime mesh-check files each re-implement an equivalent
    (but deliberately differently-styled) validation inline — this function
    is not imported by them (see module docstring).
    """
    if not isinstance(member_order, list):
        return False
    return sorted(member_order) == sorted(MESH_ROLES)
