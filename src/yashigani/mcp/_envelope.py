"""
MCP capability-envelope — projection + deterministic STRUCTURAL diff.

This module is the **authority** for the imported-MCP tool-surface pin
(Build #3 / YSG-RISK-060).  It projects a raw MCP tool surface (the
``tools/list`` response) into a coarse, security-relevant *capability
envelope* and deterministically diffs a refreshed surface against an
**approved** envelope.

Design (Iris `capability-envelope-pin-architecture-20260610.md` §2/§3 +
Laura `laura-30-...-v2-20260610.md` §5):

  * The envelope is deliberately coarser than the byte surface, so it is
    stable across benign upstream churn (a description reword, a clarified
    field doc, a tightened constraint).
  * The byte-hash is retained as a *change-DETECTOR* (re-pinned on every
    benign auto-allow), NOT as the verdict.
  * The verdict is driven by a **structural subset check** over typed
    capability dimensions (D1..D8 + constraint-tightness): a refreshed
    surface is BENIGN iff it is *no more capable* than the approved
    envelope on every dimension — i.e. ``current ⊑ ORIGINAL_envelope``.
  * **Closed-world (Laura must-have #3 / Δ3):** any surface element that
    does not reduce to a typed, bounded dimension is treated as
    ``unknown ⇒ capability-expanding ⇒ block``.  Default-to-ignore on an
    unmodelled field is the silent leak; default-to-block is the floor.

This module is PURE — no I/O, no DB, no LLM.  The structural diff here is
the deterministic gate; the sidecar (escalate-only) is layered on top in
``_envelope_triage.py``.

Last updated: 2026-06-10T00:00:00+00:00
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Effect-class lattice (dimension D2)
# ---------------------------------------------------------------------------

class EffectClass(str, Enum):
    """
    The effect class of a tool — the load-bearing dimension.

    A tool may carry SEVERAL effect classes (a tool that both reads and
    writes carries {READ, WRITE}).  The structural floor is derived from the
    schema shape independently of the (attacker-controlled) description
    (Laura Δ2): the classifier may RAISE the class, never lower it.

    Ordering note: READ ⊏ WRITE ⊏ EXEC is a monotone lattice for the
    *severity* of a single in-band effect; NETWORK is its own orthogonal
    axis (egress reach).  The envelope stores the SET of effect classes per
    tool — expansion is set-membership growth (a READ tool gaining WRITE),
    which is what the diff checks.  We do not collapse the set to a single
    max, because {READ} → {READ, NETWORK} must trip even though NETWORK is
    not "higher" than READ on the in-band severity axis.
    """

    READ = "READ"
    WRITE = "WRITE"
    EXEC = "EXEC"
    NETWORK = "NETWORK"


# Severity rank for the in-band axis (READ ⊏ WRITE ⊏ EXEC).  Used only for
# the effect-class max-rule (Laura Δ2) when combining structural floor /
# sidecar / operator proposals on the in-band severity axis.  NETWORK is
# handled as set membership, never via this rank.
_INBAND_RANK = {
    EffectClass.READ: 1,
    EffectClass.WRITE: 2,
    EffectClass.EXEC: 3,
}


# ---------------------------------------------------------------------------
# Argument-schema shape signature (dimension D3 + constraint-tightness §5.2)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ArgShape:
    """
    The *shape signature* of a single argument — the type lattice, NOT the
    prose field description.

    Captures exactly the security-relevant tightness of one parameter so a
    *loosening* (the §5.2 attack: ``enum[3]`` → unconstrained string, or
    ``pattern`` dropped) is a structural expansion while a *tightening* (or
    a description reword) is not.

    Fields
    ------
    type_name:
        The JSON-Schema ``type`` (string|number|integer|boolean|array|object|
        null), or "" when absent.  An absent or widened type is an expansion.
    required:
        Whether the arg is in the schema's ``required`` set.  Making a
        previously-required arg optional is *not* an expansion (it narrows
        the contract the caller must satisfy); ADDING a new optional arg IS
        an expansion (a new field the model can be steered to fill — A4).
    enum:
        Sorted tuple of allowed enum values (as canonical JSON strings), or
        None when the field is not enum-constrained.  ``None`` (unconstrained)
        is strictly WIDER than any finite enum; a superset enum is wider than
        a subset.
    has_pattern:
        Whether a ``pattern`` constraint is present.  Dropping a pattern is a
        loosening (expansion).
    has_format:
        Whether a ``format`` constraint is present.  Dropping a format is a
        loosening (expansion).
    has_bounds:
        Whether any of min/max/minLength/maxLength/minItems/maxItems is
        present.  Dropping all bounds is a loosening (expansion).
    additional_properties:
        For object-typed args: whether ``additionalProperties`` permits
        unmodelled keys (D6 open-world flag).  ``True`` (open world) is
        strictly wider than ``False``/absent (closed).
    unknown_flags:
        Sorted tuple of any schema keys we recognise as capability-bearing
        but do NOT fully model (``$ref``, ``unevaluatedProperties``,
        ``oneOf``, ``anyOf``, ``allOf``, ``not``, ``$dynamicRef``).  ANY such
        flag present ⇒ closed-world ⇒ treated as expansion (Δ3).
    """

    type_name: str
    required: bool
    enum: Optional[tuple] = None
    has_pattern: bool = False
    has_format: bool = False
    has_bounds: bool = False
    additional_properties: bool = False
    unknown_flags: tuple = ()


# Schema keys we recognise as potentially capability-bearing but do not fully
# model with a typed component.  Their mere presence forces closed-world block
# (Laura §5.1-D6 / Δ3).  This list is reviewed by Lu against the live MCP-spec
# version (R3-11); bumping the spec is a gated event.
_CAPABILITY_BEARING_UNMODELLED_KEYS = (
    "$ref",
    "$dynamicRef",
    "unevaluatedProperties",
    "oneOf",
    "anyOf",
    "allOf",
    "not",
    "if",
    "then",
    "else",
    "patternProperties",
    "propertyNames",
    "dependentSchemas",
)

_BOUND_KEYS = (
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    "minLength", "maxLength", "minItems", "maxItems",
    "minProperties", "maxProperties", "multipleOf",
)


# ---------------------------------------------------------------------------
# Tool envelope + server envelope
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolEnvelope:
    """
    The capability envelope of a single tool — coarse, security-relevant.

    Dimensions:
      D1 tool identity .... tool_key (provenance_id::tool_name)
      D2 effect classes ... effect_classes (frozenset[EffectClass])
      D3 arg shapes ....... arg_shapes (name -> ArgShape)
      D4 data scope ....... data_scopes (frozenset[str])  (operator-declared)
      D5 egress posture ... egress (str)  (per-server header carries the floor)
      D7 annotations ...... annotation_flags (sorted tuple of model-facing
                            hints that change how the tool is *used*, e.g.
                            readOnlyHint:false, destructiveHint:true,
                            openWorldHint:true)
      D8 output shape ..... output_open (bool — whether the return shape is
                            open-world / unconstrained)
      closed-world ........ unknown_dims (sorted tuple of unmodelled,
                            capability-bearing surface elements found)
    """

    tool_key: str
    effect_classes: frozenset = field(default_factory=frozenset)
    arg_shapes: dict = field(default_factory=dict)        # name -> ArgShape
    data_scopes: frozenset = field(default_factory=frozenset)
    annotation_flags: tuple = ()
    output_open: bool = False
    unknown_dims: tuple = ()


@dataclass(frozen=True)
class ServerEnvelope:
    """
    The server-level capability envelope — the durable approval artefact.

    Bound to the P8 provenance pin via ``provenance_id``.  The byte-hash is
    retained as a change-detector only; the verdict is the structural diff.
    """

    provenance_id: str
    tenant_id: str
    tools: dict                       # tool_key -> ToolEnvelope
    egress_posture: str = "NONE"      # NONE | INTERNAL | OUTBOUND (D5 floor)
    surface_set_hash: str = ""        # byte-hash change-detector (informational)

    def tool_keys(self) -> frozenset:
        return frozenset(self.tools.keys())


# ---------------------------------------------------------------------------
# provenance_id = H(server_id ‖ pin-material)
# ---------------------------------------------------------------------------

def compute_provenance_id(server_id: str, pin_material: str) -> str:
    """
    provenance_id = SHA-256(server_id ‖ pin-material) — binds the envelope to
    the P8 transport identity (Laura R3-2 / Iris §2.1 header).  An envelope
    cannot be inherited by a different server (closes A3 cross-server
    shadowing structurally).

    ``pin_material`` is the P8 upstream-pin material (cert SPKI hash or SPIFFE
    ID) — the caller supplies whatever the P8 pin established for this server.
    """
    if not server_id:
        raise ValueError("server_id is required for provenance_id")
    if not pin_material:
        raise ValueError("pin_material is required for provenance_id")
    h = hashlib.sha256()
    h.update(server_id.encode("utf-8"))
    h.update(b"\x1e")  # record separator — unambiguous concatenation
    h.update(pin_material.encode("utf-8"))
    return h.hexdigest()


def namespaced_tool_key(provenance_id: str, tool_name: str) -> str:
    """provenance_id::tool_name — the D1 namespaced identity (Laura A3/R3-6)."""
    return f"{provenance_id}::{tool_name}"


# ---------------------------------------------------------------------------
# JCS-canonical byte-hash (the change-detector)
# ---------------------------------------------------------------------------

def surface_set_hash(raw_tools: list, raw_prompts: Optional[list] = None) -> str:
    """
    Deterministic byte-hash over the full raw surface (Laura §3.1
    ``surface_set_hash``).  RFC-8785-style canonicalisation: sort keys,
    no whitespace, ensure_ascii=False.  This is the *change-detector* — a
    mismatch is the TRIGGER to triage, never the verdict.
    """
    payload = {
        "tools": raw_tools or [],
        "prompts": raw_prompts or [],
    }
    canon = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Projection: raw surface -> envelope
# ---------------------------------------------------------------------------

# MCP annotation hint keys whose *value* changes how a tool is used (D7).
# A flip on any of these is an envelope change.
_ANNOTATION_HINT_KEYS = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
)

# Heuristic param-name tokens that imply a WRITE/EXEC/NETWORK structural floor
# (Laura Δ2: derive a floor effect-class from schema shape, independent of the
# attacker-controlled description).  These are conservative *floors* — they can
# only RAISE the effect class, never lower it.
_WRITE_SHAPE_TOKENS = ("content", "data", "body", "payload", "value", "text", "patch")
_PATH_SHAPE_TOKENS = ("path", "file", "filename", "dir", "directory", "target")
_EXEC_SHAPE_TOKENS = ("command", "cmd", "script", "exec", "shell", "code", "query", "sql")
_NETWORK_SHAPE_TOKENS = ("url", "uri", "endpoint", "host", "webhook", "callback", "address")


def _project_arg_shape(name: str, prop: dict, required_set: set) -> ArgShape:
    """Project one JSON-Schema property dict into an ArgShape signature."""
    if not isinstance(prop, dict):
        # A non-dict property schema is unmodellable → flag as unknown.
        return ArgShape(
            type_name="",
            required=name in required_set,
            unknown_flags=("non_object_schema",),
        )

    type_name = ""
    t = prop.get("type")
    if isinstance(t, str):
        type_name = t
    elif isinstance(t, list):
        # union type — treat as the widest; flag for review.
        type_name = "|".join(sorted(str(x) for x in t))

    enum_vals = None
    if "enum" in prop and isinstance(prop["enum"], list):
        enum_vals = tuple(sorted(
            json.dumps(v, sort_keys=True, ensure_ascii=False) for v in prop["enum"]
        ))

    has_bounds = any(k in prop for k in _BOUND_KEYS)

    additional_properties = False
    if type_name == "object" or "properties" in prop:
        ap = prop.get("additionalProperties", True)
        # JSON-Schema default for additionalProperties is True (open).  Absent
        # ⇒ open-world ⇒ wider.  Only an explicit False (or a sub-schema, which
        # we do not model → unknown) closes it.
        if ap is False:
            additional_properties = False
        elif ap is True:
            additional_properties = True
        else:
            additional_properties = True  # sub-schema — conservatively open

    unknown = tuple(sorted(
        k for k in _CAPABILITY_BEARING_UNMODELLED_KEYS if k in prop
    ))

    return ArgShape(
        type_name=type_name,
        required=name in required_set,
        enum=enum_vals,
        has_pattern="pattern" in prop,
        has_format="format" in prop,
        has_bounds=has_bounds,
        additional_properties=additional_properties,
        unknown_flags=unknown,
    )


def _structural_effect_floor(
    tool_name: str,
    arg_shapes: dict,
    annotations: dict,
) -> frozenset:
    """
    Derive the structural EFFECT-CLASS FLOOR from the schema shape +
    annotations alone (Laura Δ2).  Independent of the description.  This is a
    floor — the operator/sidecar may RAISE it, never lower it below this.

    Conservative rules:
      * any arg whose name implies a write payload ⇒ WRITE.
      * any arg whose name implies a command/code/query ⇒ EXEC.
      * any arg whose name implies a URL/host/webhook ⇒ NETWORK.
      * a path arg alone ⇒ at least READ (it touches a resource).
      * annotation destructiveHint:true ⇒ WRITE; readOnlyHint:true keeps READ.
    Always includes READ as the baseline (a tool that does nothing is still
    nameable/observable).
    """
    classes = {EffectClass.READ}
    lowered_name = (tool_name or "").lower()

    def _name_hits(tokens: tuple) -> bool:
        if any(tok in lowered_name for tok in tokens):
            return True
        for arg_name in arg_shapes:
            al = arg_name.lower()
            if any(tok in al for tok in tokens):
                return True
        return False

    if _name_hits(_WRITE_SHAPE_TOKENS) or _name_hits(_PATH_SHAPE_TOKENS) and (
        "write" in lowered_name or "delete" in lowered_name
        or "create" in lowered_name or "update" in lowered_name
        or "put" in lowered_name or "post" in lowered_name
    ):
        classes.add(EffectClass.WRITE)
    if _name_hits(_EXEC_SHAPE_TOKENS):
        classes.add(EffectClass.EXEC)
    if _name_hits(_NETWORK_SHAPE_TOKENS):
        classes.add(EffectClass.NETWORK)

    if isinstance(annotations, dict):
        if annotations.get("destructiveHint") is True:
            classes.add(EffectClass.WRITE)
        if annotations.get("openWorldHint") is True:
            classes.add(EffectClass.NETWORK)

    return frozenset(classes)


def project_tool(
    provenance_id: str,
    raw_tool: dict,
    *,
    declared_effect_classes: Optional[frozenset] = None,
    declared_data_scopes: Optional[frozenset] = None,
) -> ToolEnvelope:
    """
    Project a single raw tool dict (a tools/list entry) into a ToolEnvelope.

    The structural projection reads the schema shape + annotations only — NOT
    the prose description (which is attacker-controlled and handled by the
    escalate-only sidecar separately).

    ``declared_effect_classes`` / ``declared_data_scopes`` are the
    operator-confirmed values from the import ceremony.  The stored envelope
    effect class is ``max(structural_floor, sidecar, operator)`` (Laura Δ2);
    this function returns the structural projection — the max-combination is
    applied in the service/triage layer at approval time.
    """
    name = str(raw_tool.get("name") or "")
    tool_key = namespaced_tool_key(provenance_id, name)

    input_schema = raw_tool.get("inputSchema") or raw_tool.get("input_schema") or {}
    annotations = raw_tool.get("annotations") or {}
    output_schema = raw_tool.get("outputSchema") or raw_tool.get("output_schema")

    unknown_dims: list = []

    arg_shapes: dict = {}
    if isinstance(input_schema, dict):
        props = input_schema.get("properties") or {}
        required_set = set(input_schema.get("required") or [])
        # Top-level open-world on the input schema itself (D6).
        top_ap = input_schema.get("additionalProperties", True)
        if top_ap is True:
            unknown_dims.append("input.additionalProperties:open")
        elif top_ap not in (False,):
            unknown_dims.append("input.additionalProperties:subschema")
        # Top-level unmodelled capability-bearing keys.
        for k in _CAPABILITY_BEARING_UNMODELLED_KEYS:
            if k in input_schema:
                unknown_dims.append(f"input.{k}")
        if isinstance(props, dict):
            for arg_name, prop in props.items():
                shape = _project_arg_shape(str(arg_name), prop, required_set)
                if shape.unknown_flags:
                    for uf in shape.unknown_flags:
                        unknown_dims.append(f"arg.{arg_name}.{uf}")
                arg_shapes[str(arg_name)] = shape
        else:
            unknown_dims.append("input.properties:non_object")
    elif input_schema:
        # inputSchema present but not an object → unmodellable.
        unknown_dims.append("input_schema:non_object")

    # Annotation hint flags (D7) — capture value-bearing hints as a flag tuple.
    annotation_flags: list = []
    if isinstance(annotations, dict):
        for k in _ANNOTATION_HINT_KEYS:
            if k in annotations:
                annotation_flags.append(f"{k}={json.dumps(annotations[k])}")

    # Output shape (D8) — open-world return is an expansion vector.
    output_open = False
    if isinstance(output_schema, dict):
        out_ap = output_schema.get("additionalProperties", True)
        output_open = bool(out_ap is True)
        for k in _CAPABILITY_BEARING_UNMODELLED_KEYS:
            if k in output_schema:
                unknown_dims.append(f"output.{k}")
    elif output_schema is not None:
        unknown_dims.append("output_schema:non_object")

    structural_floor = _structural_effect_floor(name, arg_shapes, annotations)
    effect_classes = frozenset(structural_floor | (declared_effect_classes or frozenset()))

    return ToolEnvelope(
        tool_key=tool_key,
        effect_classes=effect_classes,
        arg_shapes=arg_shapes,
        data_scopes=frozenset(declared_data_scopes or frozenset()),
        annotation_flags=tuple(sorted(annotation_flags)),
        output_open=output_open,
        unknown_dims=tuple(sorted(set(unknown_dims))),
    )


def project_surface(
    provenance_id: str,
    tenant_id: str,
    raw_tools: list,
    *,
    egress_posture: str = "NONE",
    declared: Optional[dict] = None,
) -> ServerEnvelope:
    """
    Project a full raw tool surface into a ServerEnvelope.

    ``declared`` maps tool_name -> {"effect_classes": frozenset[EffectClass],
    "data_scopes": frozenset[str]} from the import ceremony (operator-declared,
    optional — defaults to structural-floor only).
    """
    declared = declared or {}
    tools: dict = {}
    for raw in raw_tools or []:
        name = str(raw.get("name") or "")
        d = declared.get(name, {})
        env = project_tool(
            provenance_id,
            raw,
            declared_effect_classes=d.get("effect_classes"),
            declared_data_scopes=d.get("data_scopes"),
        )
        tools[env.tool_key] = env
    return ServerEnvelope(
        provenance_id=provenance_id,
        tenant_id=tenant_id,
        tools=tools,
        egress_posture=egress_posture,
        surface_set_hash=surface_set_hash(raw_tools),
    )


# ---------------------------------------------------------------------------
# Effect-class max-rule (Laura Δ2)
# ---------------------------------------------------------------------------

def combine_effect_classes(
    structural_floor: frozenset,
    sidecar_proposal: Optional[frozenset],
    operator_choice: Optional[frozenset],
) -> frozenset:
    """
    Envelope effect-class = max(structural_floor, sidecar, operator) — the LLM
    may RAISE the class, never lower it (Laura Δ2).

    "max" on the effect-class SET = union of all proposed classes, but the
    structural floor is *mandatory* (the result can never drop a class the
    structure proves is present).  On the in-band severity axis, the result's
    severity is at least the structural floor's severity.
    """
    result = set(structural_floor)
    if sidecar_proposal:
        result |= set(sidecar_proposal)
    if operator_choice:
        result |= set(operator_choice)
    # Floor is mandatory — never below structural.
    result |= set(structural_floor)
    return frozenset(result)


def max_inband_severity(classes: frozenset) -> int:
    """Highest in-band severity rank in the set (READ=1, WRITE=2, EXEC=3, NETWORK ignored)."""
    return max((_INBAND_RANK.get(c, 0) for c in classes), default=0)


# ---------------------------------------------------------------------------
# Structural diff — the AUTHORITY
# ---------------------------------------------------------------------------

@dataclass
class DiffFinding:
    """One concrete expansion finding (drives the operator field-level diff)."""
    dimension: str        # "tool_set" | "effect_class" | "arg_shape" | "data_scope" | "egress" | "annotation" | "output" | "unknown"
    tool_key: str
    detail: str           # human-readable, e.g. "effect class READ -> READ,WRITE"


@dataclass
class StructuralDiffResult:
    """
    Result of diffing a refreshed surface against an APPROVED envelope.

    ``expanded`` is the AUTHORITY: True ⇒ capability-expanding ⇒ block.  The
    structural diff alone decides expansion; the sidecar can only *add*
    suspicion on a non-expanding result (escalate-only).
    """
    expanded: bool
    findings: list = field(default_factory=list)   # list[DiffFinding]

    @property
    def is_benign(self) -> bool:
        return not self.expanded


def _arg_shape_expands(approved: Optional[ArgShape], current: ArgShape) -> Optional[str]:
    """
    Return a non-None expansion reason iff ``current`` is structurally WIDER
    than ``approved`` (a loosening).  None ⇒ within-envelope (same or tighter).

    A brand-new arg (approved is None) is an expansion (A4: new field the model
    can be steered to fill).
    """
    if current.unknown_flags:
        return f"unmodelled schema flag(s): {','.join(current.unknown_flags)}"
    if approved is None:
        return "new argument added"

    # type widening: a changed type is an expansion (conservative; only an
    # identical type is within-envelope).
    if current.type_name != approved.type_name:
        return f"type {approved.type_name or '∅'} -> {current.type_name or '∅'}"

    # enum loosening: None (unconstrained) is widest; a superset is wider.
    if approved.enum is not None:
        if current.enum is None:
            return "enum -> unconstrained (widened)"
        if not set(current.enum).issubset(set(approved.enum)):
            return "enum members widened"
    # approved.enum is None (already unconstrained) → any current enum is a
    # tightening (within-envelope) — no expansion.

    # constraint drops (§5.2): dropping pattern/format/bounds is a loosening.
    if approved.has_pattern and not current.has_pattern:
        return "pattern constraint dropped (widened)"
    if approved.has_format and not current.has_format:
        return "format constraint dropped (widened)"
    if approved.has_bounds and not current.has_bounds:
        return "numeric/length bounds dropped (widened)"

    # additionalProperties: closed -> open is an expansion (D6).
    if current.additional_properties and not approved.additional_properties:
        return "additionalProperties opened (closed -> open)"

    # required: making required -> optional is NOT an expansion (it narrows the
    # caller contract).  optional -> required is also not a capability gain.
    return None


def diff_envelope(
    approved: ServerEnvelope,
    current: ServerEnvelope,
) -> StructuralDiffResult:
    """
    Deterministic structural diff: is ``current`` MORE CAPABLE than the
    APPROVED envelope on ANY dimension?  Returns ``expanded=True`` (block) on
    the first/every upward component; ``expanded=False`` (benign) only when
    ``current ⊑ approved`` on every dimension.

    **Diff is always vs the APPROVED (ORIGINAL) envelope** — never vs a
    previous auto-allowed state (Laura must-have #1 / Δ1: closes
    boiling-frog/salami; auto-allows consume slack under a fixed ceiling and
    never raise it).  The caller is responsible for passing the ORIGINAL
    approved envelope here, not the last materialisation.

    Closed-world (Δ3): any ``unknown_dims`` on a current tool ⇒ expansion.
    """
    findings: list = []

    # D1 — tool set membership.  A NEW tool (key not in approved) is expansion.
    # A REMOVED tool is a narrowing (within-envelope).
    new_tools = current.tool_keys() - approved.tool_keys()
    for tk in sorted(new_tools):
        findings.append(DiffFinding(
            dimension="tool_set", tool_key=tk, detail="new tool added",
        ))

    # D5 — server egress posture.  A raised posture is expansion.
    if _egress_rank(current.egress_posture) > _egress_rank(approved.egress_posture):
        findings.append(DiffFinding(
            dimension="egress", tool_key="",
            detail=f"egress posture {approved.egress_posture} -> {current.egress_posture}",
        ))

    # Per-tool dimensions for tools present in BOTH (new tools already flagged).
    for tk, cur_tool in current.tools.items():
        if tk not in approved.tools:
            # Closed-world: even a brand-new tool's unknown dims are caught by
            # the tool_set finding above; but surface its unknowns too.
            for ud in cur_tool.unknown_dims:
                findings.append(DiffFinding(
                    dimension="unknown", tool_key=tk,
                    detail=f"unmodelled capability dimension: {ud}",
                ))
            continue
        appr_tool = approved.tools[tk]

        # Closed-world (Δ3): any unmodelled dimension on the current tool blocks.
        for ud in cur_tool.unknown_dims:
            findings.append(DiffFinding(
                dimension="unknown", tool_key=tk,
                detail=f"unmodelled capability dimension: {ud}",
            ))

        # D2 — effect classes: a NEW effect class is expansion.
        new_effects = cur_tool.effect_classes - appr_tool.effect_classes
        if new_effects:
            appr_str = ",".join(sorted(e.value for e in appr_tool.effect_classes)) or "∅"
            cur_str = ",".join(sorted(e.value for e in cur_tool.effect_classes)) or "∅"
            findings.append(DiffFinding(
                dimension="effect_class", tool_key=tk,
                detail=f"effect class {appr_str} -> {cur_str}",
            ))

        # D3 — arg shapes: widening / new arg / unmodelled flag.
        for arg_name, cur_shape in cur_tool.arg_shapes.items():
            appr_shape = appr_tool.arg_shapes.get(arg_name)
            reason = _arg_shape_expands(appr_shape, cur_shape)
            if reason:
                findings.append(DiffFinding(
                    dimension="arg_shape", tool_key=tk,
                    detail=f"param '{arg_name}': {reason}",
                ))

        # D4 — data scope: a broadened scope is expansion.
        new_scopes = cur_tool.data_scopes - appr_tool.data_scopes
        if new_scopes and not _scopes_subsumed(new_scopes, appr_tool.data_scopes):
            findings.append(DiffFinding(
                dimension="data_scope", tool_key=tk,
                detail=f"data scope broadened: +{sorted(new_scopes)}",
            ))

        # D7 — annotation hints: a changed/added hint is an envelope change.
        new_annotations = set(cur_tool.annotation_flags) - set(appr_tool.annotation_flags)
        if new_annotations:
            findings.append(DiffFinding(
                dimension="annotation", tool_key=tk,
                detail=f"model-facing hint changed: {sorted(new_annotations)}",
            ))

        # D8 — output shape: closed -> open return is expansion.
        if cur_tool.output_open and not appr_tool.output_open:
            findings.append(DiffFinding(
                dimension="output", tool_key=tk,
                detail="output schema opened (closed -> open)",
            ))

    return StructuralDiffResult(expanded=bool(findings), findings=findings)


# ---------------------------------------------------------------------------
# Egress / data-scope ordering helpers
# ---------------------------------------------------------------------------

_EGRESS_RANK = {"NONE": 0, "INTERNAL": 1, "OUTBOUND": 2}


def _egress_rank(posture: str) -> int:
    return _EGRESS_RANK.get((posture or "NONE").upper(), 99)  # unknown ⇒ highest ⇒ expansion


def _scopes_subsumed(new_scopes: frozenset, approved_scopes: frozenset) -> bool:
    """
    Conservative data-scope subsumption: a new scope is *subsumed* (not an
    expansion) only if every new scope is a sub-path/sub-prefix of an approved
    scope.  Glob-aware for the common ``prefix/*`` form; otherwise exact-match
    only (closed-world: if we cannot prove subsumption, it is an expansion).
    """
    for ns in new_scopes:
        if not any(_scope_covers(approved, ns) for approved in approved_scopes):
            return False
    return True


def _scope_covers(approved: str, candidate: str) -> bool:
    """True iff ``approved`` scope covers ``candidate`` (candidate is narrower)."""
    if approved == candidate:
        return True
    # prefix glob: "db:read-only/*" covers "db:read-only/users"
    if approved.endswith("/*"):
        prefix = approved[:-1]  # keep trailing slash
        if candidate.startswith(prefix):
            # ensure candidate is not itself a broader glob
            return not (candidate.endswith("/*") and len(candidate) <= len(approved))
    if approved.endswith("*"):
        prefix = approved[:-1]
        if candidate.startswith(prefix) and candidate != approved:
            return True
    return False
