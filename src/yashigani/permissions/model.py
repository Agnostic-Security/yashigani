"""
Yashigani Permissions — Unified grant model.

Grant primitive: (subject, resource_type, resource_id, value)

Subject kinds
-------------
    org:<id>              — organisation-level grant (org ceiling)
    group:<id>            — group-level grant (can only narrow within org ceiling)
    user:<email>          — user-level grant (can only narrow within org ceiling)
    agent:<id>            — agent-level grant (can only narrow within org ceiling)
    gateway:orchestrator  — gateway orchestrator (literal constant)

Resource types
--------------
    mcp_server          boolean allow  blast-radius
    external_api        boolean allow  blast-radius
    cloud_model         boolean allow  blast-radius; MUST carry opa_policy_ref when allow=True
    agent               boolean allow  blast-radius
    browser_capability  tri-state off|self|allow_list (non-blast-radius)

Invariants
----------
    INV-1  DENY BY DEFAULT for blast-radius types.  A resource is denied unless an
           org-level grant explicitly allows it AND no group or user grant denies it.
           A lower-level allow with no org grant has NO effect.

    INV-2  cloud_model allow=True MUST carry a non-empty opa_policy_ref.
           Validation raises GrantValidationError at write time.

    INV-3  ORG IS THE CEILING.  Group and user grants can only NARROW (make more
           restrictive) within the org grant — they can never widen.
           - boolean:   effective = org_allow AND NOT any_group_deny AND NOT user_deny
           - tri-state: effective = most-restrictive of {org, group, user}
             where off=0 < self=1 < allow_list=2

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Resource types
# ---------------------------------------------------------------------------

class ResourceType(str, Enum):
    MCP_SERVER = "mcp_server"
    EXTERNAL_API = "external_api"
    CLOUD_MODEL = "cloud_model"
    AGENT = "agent"
    BROWSER_CAPABILITY = "browser_capability"


#: Resource types that are deny-by-default and carry boolean allow values.
BLAST_RADIUS_TYPES: frozenset[ResourceType] = frozenset({
    ResourceType.MCP_SERVER,
    ResourceType.EXTERNAL_API,
    ResourceType.CLOUD_MODEL,
    ResourceType.AGENT,
})

RESOURCE_TYPE_VALUES: frozenset[str] = frozenset(rt.value for rt in ResourceType)


# ---------------------------------------------------------------------------
# Subject kinds
# ---------------------------------------------------------------------------

class SubjectKind(str, Enum):
    ORG = "org"
    GROUP = "group"
    USER = "user"
    AGENT = "agent"
    GATEWAY = "gateway"


GATEWAY_ORCHESTRATOR = "gateway:orchestrator"


@dataclass(frozen=True)
class Subject:
    """
    A grant subject: one of org / group / user / agent / gateway.

    Serialised form: "{kind}:{id}"  e.g. "org:default", "user:alice@example.com",
    "gateway:orchestrator".
    """
    kind: SubjectKind
    id: str

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.id}"

    @classmethod
    def parse(cls, s: str) -> "Subject":
        """Parse "kind:id" string.  Raises ValueError on malformed input."""
        if not s or ":" not in s:
            raise ValueError(f"Invalid subject string: {s!r}")
        kind_str, _, id_ = s.partition(":")
        if not id_:
            raise ValueError(f"Subject id is empty in {s!r}")
        try:
            kind = SubjectKind(kind_str)
        except ValueError:
            raise ValueError(
                f"Unknown subject kind {kind_str!r}.  "
                f"Valid kinds: {[k.value for k in SubjectKind]}"
            )
        return cls(kind=kind, id=id_)

    @classmethod
    def org(cls, org_id: str) -> "Subject":
        return cls(kind=SubjectKind.ORG, id=org_id)

    @classmethod
    def group(cls, group_id: str) -> "Subject":
        return cls(kind=SubjectKind.GROUP, id=group_id)

    @classmethod
    def user(cls, email: str) -> "Subject":
        return cls(kind=SubjectKind.USER, id=email)

    @classmethod
    def agent(cls, agent_id: str) -> "Subject":
        return cls(kind=SubjectKind.AGENT, id=agent_id)

    @classmethod
    def gateway_orchestrator(cls) -> "Subject":
        return cls(kind=SubjectKind.GATEWAY, id="orchestrator")


# ---------------------------------------------------------------------------
# Grant values
# ---------------------------------------------------------------------------

@dataclass
class BooleanGrantValue:
    """
    Grant value for blast-radius resource types (mcp_server, external_api,
    cloud_model, agent).

    allow=True means the resource is explicitly permitted.
    allow=False means the resource is explicitly denied at this scope level
    (org deny = ceiling; group/user deny = narrowing).

    opa_policy_ref is REQUIRED when resource_type=cloud_model AND allow=True
    (INV-2).  It references the OPA policy that governs model-usage decisions
    (e.g. "yashigani/cloud_model/gpt4o").
    """
    allow: bool
    opa_policy_ref: Optional[str] = None

    def to_dict(self) -> dict:
        return {"allow": self.allow, "opa_policy_ref": self.opa_policy_ref}

    @classmethod
    def from_dict(cls, d: dict) -> "BooleanGrantValue":
        return cls(
            allow=bool(d["allow"]),
            opa_policy_ref=d.get("opa_policy_ref"),
        )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class GrantValidationError(ValueError):
    """Raised when a grant fails invariant validation."""


def validate_boolean_grant(
    resource_type: ResourceType,
    value: BooleanGrantValue,
) -> None:
    """
    Validate a boolean grant value.

    Raises GrantValidationError if:
      - resource_type is not a blast-radius type
      - INV-2: cloud_model allow=True without opa_policy_ref
    """
    if resource_type not in BLAST_RADIUS_TYPES:
        raise GrantValidationError(
            f"resource_type {resource_type!r} does not use boolean grants. "
            f"Boolean grants are for: {[rt.value for rt in BLAST_RADIUS_TYPES]}"
        )
    if resource_type == ResourceType.CLOUD_MODEL and value.allow:
        if not value.opa_policy_ref or not value.opa_policy_ref.strip():
            raise GrantValidationError(
                "INV-2: cloud_model allow=True requires a non-empty opa_policy_ref. "
                "Every cloud model permission must reference an OPA policy that governs "
                "its usage."
            )


def validate_resource_type(resource_type: str) -> ResourceType:
    """Parse and validate a resource_type string.  Raises GrantValidationError."""
    try:
        return ResourceType(resource_type)
    except ValueError:
        raise GrantValidationError(
            f"Unknown resource_type {resource_type!r}.  "
            f"Valid types: {sorted(RESOURCE_TYPE_VALUES)}"
        )


def validate_subject(subject: Subject) -> None:
    """Validate subject fields.  Raises GrantValidationError."""
    if not subject.id:
        raise GrantValidationError(f"Subject id must not be empty (kind={subject.kind})")
