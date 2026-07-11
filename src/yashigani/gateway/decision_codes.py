"""Stable decision-code enumeration for the orchestration step transcript.

Why this exists
---------------
The per-hop orchestration transcript used to print raw OPA internals to the
end user, e.g.::

    - mcp__demo__echo (depth 1): BLOCKED [ingress_opa=allow
      egress_opa=deny:response_sensitivity_exceeds_ceiling inspection=BLOCKED]

That leaks the security logic (tool names, policy reasons, which leg fired) to
anyone who can see a chat answer. Instead we emit a compact, opaque, STABLE
coded tuple that a support engineer (or operator) can decode with the committed
legend (``docs/decision-code-legend.yml`` / ``scripts/decode-steps.py``) — the
full human reason stays in the tamper-evident audit sink, never in user output.

Format
------
A coded step is six colon-separated fields::

    <tooluid>:<depth>:<status>:<leg>:<action>:<reason>

* ``tooluid``  - stable 4-hex id of the tool (hides the raw tool name)
* ``depth``    - orchestration hop depth (integer)
* ``status``   - 0 blocked / 1 ok
* ``leg``      - which adjudication leg decided the outcome (see ``LEG``)
* ``action``   - allow / deny / route-local / redact / pseudonymize (see ``ACTION``)
* ``reason``   - numeric reason / inspection code (see ``REASON``)

The enumerations are STABLE across deployments (a fixed, committed contract), so
support can learn the common codes and a screenshot is enough to triage —
including spotting when OPA is blocking normal usage (a deny code on a benign
request). ``tooluid`` is a deterministic hash, so the legend can list known
tools; an unknown uid is still safe to show and resolvable from a tool list.
"""

from __future__ import annotations

import hashlib

# --- field enumerations (STABLE — do not renumber; append only) -------------

STATUS = {
    0: "blocked",
    1: "ok",
}

LEG = {
    6: "inspection",   # ResponseInspection pipeline made the call
    7: "ingress",      # OPA ingress leg (before the tool ran)
    8: "egress",       # OPA egress leg (on the tool/model result)
    9: "seed",         # seed-prompt / pre-flight adjudication
}

# Non-sequential (stable). Values may coincide with codes in OTHER fields
# (e.g. 7 = ingress leg AND deny action) — the decoder reads positionally.
ACTION = {
    3: "allow",
    7: "deny",
    9: "route-local",   # must be served by a local model (e.g. classified)
    0: "redact",        # content removed (doc-OPA)
    6: "pseudonymize",  # content reversibly tokenised (doc-OPA)
}

# Reason / inspection codes. STABLE — append new reasons with new numbers,
# never reuse a number. 99 is the catch-all for an as-yet-unmapped reason
# (the full string is always in the audit sink).
# Codes are STABLE but deliberately NON-SEQUENTIAL — you cannot infer an
# adjacent reason by guessing the next number. Assign new reasons any unused
# value; never reuse or renumber an existing one. 99 stays the catch-all.
REASON = {
    0:  "clean",                                # no block (action=allow)
    41: "default_deny",                         # OPA fail-closed / generic policy deny
    63: "client_policy_denied",                 # a client OPA policy bound to the caller denied
    28: "identity_not_active",                  # disabled / inactive account
    52: "model_not_allocated",                  # caller not allocated the requested model
    14: "response_sensitivity_exceeds_ceiling", # response data-classification > caller clearance
    36: "sensitivity_ceiling_exceeded",         # request data-classification > caller clearance
    71: "invalid_identity_ceiling",             # identity ceiling missing/invalid
    17: "response_blocked_by_inspection",       # injection / credential-exfil detected in result
    59: "pii_detected",                         # PII present, cannot send to provider
    84: "routing_unsafe_sensitive_to_cloud",    # sensitive content would route to a cloud model
    47: "provenance_cap",                       # provenance / hop-budget cap refused the call
    92: "unknown_tool",                         # tool not in the approved catalog
    33: "unsupported_tool",                     # tool/operation not supported
    68: "injection_budget",                     # per-hop injection budget exhausted
    25: "sensitivity_exceeds_egress_ceiling",   # egress ceiling exceeded
    76: "classified_requires_local",            # classified marking -> local model only
    88: "pci_data_present",                      # cardholder (PCI) data present
    99: "unmapped",                             # reason not in this table (see audit sink)
}

_REASON_BY_NAME = {name: code for code, name in REASON.items()}


def tool_uid(tool_name: str) -> str:
    """Stable 4-hex-char id for a tool name (hides the raw name in user output)."""
    return hashlib.sha256((tool_name or "").encode("utf-8")).hexdigest()[:4].upper()


def _reason_code(raw: str) -> int:
    """Map a raw leg value (e.g. ``deny:response_sensitivity_exceeds_ceiling``)
    to its stable numeric reason code. A bare ``deny`` (no reason) -> default_deny."""
    if not raw:
        return 0
    if ":" not in raw:
        # "allow" / "deny" / "not_reached" / "not_applicable"
        return 10 if raw == "deny" else 0
    name = raw.split(":", 1)[1].strip()
    return _REASON_BY_NAME.get(name, 99)


def encode_step(step: dict) -> str:
    """Encode one transcript step dict into the compact coded tuple.

    ``step`` keys: tool, depth, status ('blocked'|'ok'), ingress_opa, egress_opa,
    inspection. The TERMINAL deciding leg is reported (ingress deny wins over
    egress deny wins over an inspection block); an allowed hop reports egress/allow.
    """
    tool = tool_uid(step.get("tool", ""))
    try:
        depth = int(step.get("depth", 0))
    except (TypeError, ValueError):
        depth = 0
    status = 0 if step.get("status") == "blocked" else 1
    ingress = (step.get("ingress_opa", "") or "")
    egress = (step.get("egress_opa", "") or "")
    inspection = (step.get("inspection", "") or "").lower()

    if ingress.startswith("deny"):
        leg, action, reason = 7, 7, _reason_code(ingress)   # ingress leg, deny
    elif egress.startswith("deny"):
        leg, action, reason = 8, 7, _reason_code(egress)    # egress leg, deny
    elif inspection == "blocked":
        leg, action, reason = 6, 7, 17                      # inspection leg, deny
    else:
        leg, action, reason = 8, 3, 0                       # egress leg, allow

    return f"{tool}:{depth}:{status}:{leg}:{action}:{reason}"


def decode_step(code: str, tool_names: dict | None = None) -> dict:
    """Decode a coded tuple back into a structured, human-readable dict.

    ``tool_names`` optionally maps tool_uid -> tool name (built from the known
    tool catalog) so the decoder can name the tool; otherwise the uid is shown.
    """
    parts = (code or "").strip().split(":")
    if len(parts) != 6:
        return {"error": f"expected 6 fields, got {len(parts)}: {code!r}"}
    uid, depth, status, leg, action, reason = parts
    tool_names = tool_names or {}

    def _num(x):
        try:
            return int(x)
        except ValueError:
            return None

    s, lg, ac, rs = _num(status), _num(leg), _num(action), _num(reason)
    return {
        "code": code,
        "tool": tool_names.get(uid.upper(), f"<uid {uid}>"),
        "tool_uid": uid,
        "depth": _num(depth),
        "status": STATUS.get(s, f"<status {status}>"),
        "leg": LEG.get(lg, f"<leg {leg}>"),
        "action": ACTION.get(ac, f"<action {action}>"),
        "reason": REASON.get(rs, f"<reason {reason}>"),
    }


def explain(code: str, tool_names: dict | None = None) -> str:
    """One-line plain-English explanation for support triage."""
    d = decode_step(code, tool_names)
    if "error" in d:
        return f"{code}: UNDECODABLE ({d['error']})"
    if d["status"] == "ok":
        return (f"{code}  ->  tool {d['tool']} (hop {d['depth']}): OK, "
                f"delivered ({d['leg']} allowed).")
    return (f"{code}  ->  tool {d['tool']} (hop {d['depth']}): BLOCKED at the "
            f"{d['leg']} leg, action={d['action']}, reason={d['reason']}.")
