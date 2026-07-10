#!/usr/bin/env python3
"""Decode Yashigani orchestration decision codes — support triage helper.

A user's chat answer may include opaque coded steps like::

    [Decision codes — decode with decision-code-legend.yml]
      7F3A:1:0:8:7:14

Paste the code(s) here to see what OPA actually did (and whether it looks like
it is blocking *normal* usage):

    python3 scripts/decode-steps.py 7F3A:1:0:8:7:14
    python3 scripts/decode-steps.py 7F3A:1:0:8:7:14 9B2C:2:1:8:3:0

Compute tool uids (to fill `known_tools` in the legend):

    python3 scripts/decode-steps.py --tools mcp__demo__echo "@langflow"

Tables are read from docs/decision-code-legend.yml when present (so the support
notes show); otherwise a built-in copy is used. Only the Python stdlib is
required (PyYAML is used for the legend if available).
"""
import hashlib
import os
import sys

# --- built-in fallback tables (kept in sync with decision_codes.py) ---------
STATUS = {0: "blocked", 1: "ok"}
LEG = {6: "inspection", 7: "ingress", 8: "egress", 9: "seed"}
ACTION = {3: "allow", 7: "deny", 9: "route-local", 0: "redact", 6: "pseudonymize"}
REASON = {
    0: "clean", 41: "default_deny", 63: "client_policy_denied",
    28: "identity_not_active", 52: "model_not_allocated",
    14: "response_sensitivity_exceeds_ceiling", 36: "sensitivity_ceiling_exceeded",
    71: "invalid_identity_ceiling", 17: "response_blocked_by_inspection",
    59: "pii_detected", 84: "routing_unsafe_sensitive_to_cloud", 47: "provenance_cap",
    92: "unknown_tool", 33: "unsupported_tool", 68: "injection_budget",
    25: "sensitivity_exceeds_egress_ceiling", 76: "classified_requires_local",
    88: "pci_data_present", 99: "unmapped",
}
REASON_NOTE = {}
KNOWN_TOOLS = {}

_LEGEND = os.path.join(os.path.dirname(__file__), os.pardir, "docs",
                       "decision-code-legend.yml")


def _load_legend():
    """Prefer the committed legend (for the support notes + known_tools)."""
    global REASON, REASON_NOTE, KNOWN_TOOLS, STATUS, LEG, ACTION
    try:
        import yaml  # noqa: PLC0415
        with open(_LEGEND) as fh:
            d = yaml.safe_load(fh)
    except Exception:
        return
    if not isinstance(d, dict):
        return
    STATUS = {int(k): v for k, v in (d.get("status") or {}).items()}
    LEG = {int(k): v for k, v in (d.get("leg") or {}).items()}
    ACTION = {int(k): v for k, v in (d.get("action") or {}).items()}
    rmap, rnote = {}, {}
    for k, v in (d.get("reason") or {}).items():
        if isinstance(v, dict):
            rmap[int(k)] = v.get("name", str(v))
            rnote[int(k)] = v.get("note", "")
        else:
            rmap[int(k)] = str(v)
    if rmap:
        REASON, REASON_NOTE = rmap, rnote
    KNOWN_TOOLS = {str(u).upper(): n for n, u in (d.get("known_tools") or {}).items() if u}


def tool_uid(name: str) -> str:
    return hashlib.sha256((name or "").encode("utf-8")).hexdigest()[:4].upper()


def _lookup(table, raw):
    try:
        return table.get(int(raw), f"<{raw}?>")
    except ValueError:
        return f"<{raw}?>"


def decode(code: str) -> str:
    parts = code.strip().split(":")
    if len(parts) != 6:
        return f"{code}\n  ! UNDECODABLE — expected 6 fields, got {len(parts)}"
    uid, depth, st, leg, ac, rs = parts
    tool = KNOWN_TOOLS.get(uid.upper(), f"<uid {uid}>")
    status = _lookup(STATUS, st)
    legn = _lookup(LEG, leg)
    actn = _lookup(ACTION, ac)
    reasn = _lookup(REASON, rs)
    note = REASON_NOTE.get(int(rs)) if rs.isdigit() else ""
    out = [code,
           f"  tool   : {tool}",
           f"  hop    : {depth}",
           f"  status : {status}",
           f"  leg    : {legn}",
           f"  action : {actn}",
           f"  reason : {reasn}"]
    if note:
        out.append(f"  note   : {note}")
    return "\n".join(out)


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    _load_legend()
    if argv[0] == "--tools":
        for name in argv[1:]:
            print(f"{tool_uid(name)}  {name}")
        return 0
    for code in argv:
        print(decode(code))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
