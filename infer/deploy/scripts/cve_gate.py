#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""CVE gate for the llama.cpp pin — YSG-RISK-302.

`infer/deploy/manifests/llama-cpp-build-manifest.md` declares a CVE re-check
MANDATORY on every re-pin. No code implemented it: `--cve-check` was an
unconditional `exit 3`. This is that gate.

It is a deterministic comparator, not a heuristic, because upstream publishes
GitHub Security Advisories whose `vulnerable_version_range` is expressed in the
same `bNNNN` build tags we pin to. Verified against real data:

    GHSA-j8rj-fmpv-wcxw  CVE-2026-34159  critical  CVSS 9.8  <= b7991
    GHSA-96jg-mvhq-q7q7  CVE-2026-33298  high                <  b7437   patched b7824
    GHSA-3p4r-fq3f-q74v  CVE-2026-27940  high                <= b8145   patched >= b8146

An earlier reading of upstream's SECURITY.md concluded there was no advisory
feed at all. That was wrong: SECURITY.md disables the *intake* channel (how
researchers report in), not the *output* channel. There are 13 advisories with
CVE ids, CVSS scores and machine-readable ranges.

NOTHING IS SILENTLY SKIPPED. Each advisory lands in one of three buckets:
  - covers      -> blocked outright
  - clear       -> our pin is outside the vulnerable range
  - unresolved  -> cannot be decided mechanically; surfaced and must be
                   acknowledged by name, never dropped
Plus: a network/API failure blocks (absence of data is not absence of risk),
an unparseable pin blocks, and no human verdict blocks even at zero matches.

That last one matters: a clean automated result is necessary but not sufficient.
Upstream has disabled private disclosure, so fixes can land as public PRs with
no advisory ever filed. A green gate means "no KNOWN advisory applies", which is
a weaker claim than "safe", and the recorded verdict is where a human says they
understood that distinction.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

API = "https://api.github.com/repos/{repo}/security-advisories?per_page=100"
_BUILD_TAG = re.compile(r"^b(\d+)$")
# e.g. "<= b7991", "< b7437", ">= b8146", "> b1, < b9"
_CONSTRAINT = re.compile(r"(<=|>=|<|>|=)\s*b(\d+)")
_SHA_CONSTRAINT = re.compile(r"(<=|>=|<|>)?\s*\b([0-9a-f]{7,40})\b")


class GateError(RuntimeError):
    """Raised for any condition that must block a pin."""


@dataclass(frozen=True)
class Advisory:
    ghsa: str
    cve: str | None
    severity: str
    summary: str
    vulnerable_range: str


def parse_build_tag(tag: str) -> int:
    """`b10976` -> 10976. Anything else blocks."""
    m = _BUILD_TAG.match(tag.strip())
    if not m:
        raise GateError(
            f"cannot parse {tag!r} as a llama.cpp build tag (expected bNNNN). "
            "Refusing to evaluate the gate against an unrecognised pin."
        )
    return int(m.group(1))


def classify(vulnerable_range: str, build: int, sha_resolver=None) -> str:
    """Classify an advisory range against our pinned build.

    Returns "covers" | "clear" | "unresolved".

    Real upstream data uses at least four shapes, not one — measured across the
    13 published advisories:

        "< b3561"                  operator + build tag
        "<=b3426"                  same, no space
        "<= 55d4206c8"             operator + commit SHA
        "c33fe8b8"                 bare SHA, no operator
        "All versions before patch"  free text

    An earlier version of this gate understood only the first and raised on the
    rest, which made it fail-closed on EVERY run and therefore useless — a gate
    that always blocks is not a gate, it is an outage, and it gets disabled.

    So anything not decidable mechanically returns "unresolved" rather than
    being silently treated as non-applicable. Unresolved items are surfaced and
    must be acknowledged by the reviewer; they are never quietly dropped.
    """
    text = (vulnerable_range or "").strip()
    if not text:
        return "unresolved"

    constraints = _CONSTRAINT.findall(text)
    if constraints:
        for op, num in constraints:
            n = int(num)
            if op == "<=" and not build <= n: return "clear"
            if op == "<"  and not build <  n: return "clear"
            if op == ">=" and not build >= n: return "clear"
            if op == ">"  and not build >  n: return "clear"
            if op == "="  and build != n:     return "clear"
        return "covers"

    # No bNNNN constraint. If it names a commit SHA and we were given a
    # resolver, ask upstream whether our pin is at-or-before that commit.
    m = _SHA_CONSTRAINT.search(text)
    if m and sha_resolver is not None:
        op, sha = m.group(1) or "<=", m.group(2)
        verdict = sha_resolver(sha)          # "ahead" | "behind" | "identical" | None
        if verdict is None:
            return "unresolved"
        if op in ("<=", "<"):
            # our pin is vulnerable if it is NOT ahead of the fixed commit
            return "clear" if verdict == "ahead" else "covers"
        return "unresolved"
    return "unresolved"


def make_sha_resolver(repo: str, our_sha: str, token: str | None = None):
    """Resolve whether our pinned commit is ahead of / behind a given commit.

    Uses the compare API, which answers exactly the question an advisory range
    of the form "<= <sha>" asks. Returns None on any failure so the caller
    records "unresolved" rather than guessing in either direction.
    """
    def _resolve(base_sha: str) -> str | None:
        url = f"https://api.github.com/repos/{repo}/compare/{base_sha}...{our_sha}"
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r).get("status")
        except Exception:
            return None
    return _resolve


def fetch_advisories(repo: str, token: str | None = None, timeout: int = 30) -> list[Advisory]:
    """Fetch published advisories. Any failure blocks — never returns [] on error."""
    req = urllib.request.Request(
        API.format(repo=repo), headers={"Accept": "application/vnd.github+json"}
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = json.load(r)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        raise GateError(
            f"could not reach the advisory API for {repo}: {exc}. "
            "Absence of data is NOT absence of risk — the pin is blocked."
        ) from exc
    out: list[Advisory] = []
    for a in raw:
        for v in a.get("vulnerabilities") or [{}]:
            out.append(
                Advisory(
                    ghsa=a.get("ghsa_id", "?"),
                    cve=a.get("cve_id"),
                    severity=a.get("severity", "?"),
                    summary=(a.get("summary") or "")[:100],
                    vulnerable_range=(v or {}).get("vulnerable_version_range") or "",
                )
            )
    return out


def evaluate(
    advisories: list[Advisory], build: int, sha_resolver=None
) -> tuple[list[Advisory], list[Advisory]]:
    """Return (covers, unresolved). Everything else is clear."""
    covers, unresolved = [], []
    for a in advisories:
        verdict = classify(a.vulnerable_range, build, sha_resolver)
        if verdict == "covers":
            covers.append(a)
        elif verdict == "unresolved":
            unresolved.append(a)
    return covers, unresolved


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="CVE gate for a llama.cpp pin (YSG-RISK-302)")
    p.add_argument("--tag", required=True, help="pinned build tag, e.g. b10976")
    p.add_argument("--repo", default="ggml-org/llama.cpp")
    p.add_argument("--token", default=None, help="GitHub token (optional; raises rate limits)")
    p.add_argument(
        "--reviewer",
        default=None,
        help="REQUIRED. Name of the human who reviewed this pin. A clean automated "
        "result is not a pass on its own: upstream has disabled private disclosure, "
        "so fixes can land as public PRs with no advisory filed.",
    )
    p.add_argument("--commit", default=None,
                   help="the pinned commit SHA; enables resolving SHA-form advisory ranges "
                        "via the compare API instead of leaving them unresolved")
    p.add_argument("--ack-unresolved", action="store_true",
                   help="acknowledge advisories that could not be decided mechanically, "
                        "after reviewing each one")
    args = p.parse_args(argv)

    try:
        build = parse_build_tag(args.tag)
        advisories = fetch_advisories(args.repo, args.token)
    except GateError as exc:
        print(f"!!  BLOCKED: {exc}", file=sys.stderr)
        return 1

    resolver = make_sha_resolver(args.repo, args.commit, args.token) if args.commit else None
    covers, unresolved = evaluate(advisories, build, resolver)

    print(f"    --> pin {args.tag} (build {build}) checked against "
          f"{len(advisories)} published advisories for {args.repo}")

    if covers:
        print(f"!!  BLOCKED: {len(covers)} advisory/advisories cover this pin:", file=sys.stderr)
        for a in covers:
            print(f"      {a.ghsa}  {a.cve or '(no CVE)'}  {a.severity:8}  "
                  f"range={a.vulnerable_range!r}\n        {a.summary}", file=sys.stderr)
        return 1

    if unresolved:
        print(f"    --> {len(unresolved)} advisory/advisories could not be decided "
              f"mechanically and need review:")
        for a in unresolved:
            print(f"      {a.ghsa}  {a.cve or '(no CVE)'}  {a.severity:8}  "
                  f"range={a.vulnerable_range!r}")
        if not args.ack_unresolved:
            print(
                "!!  BLOCKED: unresolved advisories above were not acknowledged. "
                "Review each and re-run with --ack-unresolved once you have. They are "
                "surfaced rather than skipped precisely so this decision is explicit.",
                file=sys.stderr,
            )
            return 1

    if not args.reviewer:
        print(
            "!!  BLOCKED: no reviewer recorded. Zero matching advisories is necessary "
            "but NOT sufficient — upstream disabled private disclosure (SECURITY.md), so "
            "a fix can land as a public PR with no advisory. Re-run with --reviewer to "
            "record who accepted that residual.",
            file=sys.stderr,
        )
        return 1

    print(f"    --> no published advisory covers {args.tag}")
    print(f"    --> reviewer: {args.reviewer}"
          + (f"  (acknowledged {len(unresolved)} unresolved)" if unresolved else ""))
    print("    --> NOTE: 'no known advisory' is weaker than 'safe'. Upstream publishes "
          "fixes as public PRs without always filing an advisory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
