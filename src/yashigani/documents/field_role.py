"""
Yashigani Document Enforcement — field-role classification (Laura D1, PART 2).

An opaque token breaks the cloud LLM wherever it must **operate on** the value:
sum currency amounts, validate an IBAN/email, reason over a date the task
computes on.  Fed an opaque blob in place of such a value, the model does not
error — it **hallucinates** a plausible value and reasons over the invention.
So a blanket "tokenise everything to an opaque blob" is wrong for operate-on
fields.  We classify each match's **field role** and route accordingly:

  * **REFERENCE_ONLY** — identifiers the LLM only needs a consistent placeholder
    for (name, email, postal address, national-ID, generic ID).  Safe to replace
    with an opaque token: the model reasons over "the same person/account"
    without needing the literal value.

  * **OPERATE_ON** — values the task computes on / validates (currency amounts,
    dates reasoned over, numeric IDs / IBANs / card numbers the model validates).
    An opaque blob here is a correctness *and* a safety problem: the model
    invents a value.  These must NOT be silently blobbed to the cloud.  Per the
    design the options are: **keep** (when non-sensitive), **aggregate/generalise**,
    or **route the whole document to a LOCAL model** (the existing
    sensitivity→local-model routing).

Classification is **conservative / fail-safe**: when the role is unknown we treat
the field as OPERATE_ON-sensitive (do not send a broken value to the cloud).  We
reuse the column-header / QI context the detector already builds (``qi_context``)
plus the ``data_class`` to infer the role — no new detection engine.
"""
from __future__ import annotations

from enum import Enum


class FieldRole(str, Enum):
    """How the downstream model must use a matched value."""

    #: The model only needs a consistent placeholder — safe to opaque-tokenise.
    REFERENCE_ONLY = "REFERENCE_ONLY"
    #: The model computes on / validates the value — an opaque blob makes it
    #: hallucinate.  Must not be silently blobbed to the cloud.
    OPERATE_ON = "OPERATE_ON"


#: Data classes whose values are purely REFERENTIAL — the model needs a stable
#: placeholder, never the literal value.  Keyed by the bare class name (the part
#: after the ``PII.``/``PCI.`` namespace) so both namespaced and bare forms work.
_REFERENCE_ONLY_CLASSES = frozenset({
    "PERSON_NAME",
    "CARDHOLDER_NAME",
    "EMAIL",
    "POSTAL_ADDRESS",
    "ADDRESS",
    "NATIONAL_INSURANCE",
    "NATIONAL_ID",
    "PASSPORT",
    "JOB_TITLE",
    "USERNAME",
})

#: Data classes whose values the model typically OPERATES ON / VALIDATES — an
#: opaque blob breaks the task (summation, validation, date arithmetic) and the
#: model hallucinates.  Sensitive ones must be routed local / kept, not blobbed.
_OPERATE_ON_CLASSES = frozenset({
    "SALARY",            # summed / compared
    "AMOUNT",            # currency arithmetic
    "CURRENCY",
    "DATE_OF_BIRTH",     # date reasoning / age computation
    "DATE",
    "PAN",               # Luhn-validated by the model
    "CREDIT_CARD",
    "CARD_EXPIRY",       # date validity check
    "CVV",
    "IBAN",              # checksum-validated
    "ACCOUNT_NUMBER",
    "SORT_CODE",
    "PHONE",             # format-validated / dialled
    "NHS_NUMBER",        # checksum-validated
})


def _bare(data_class: str) -> str:
    return data_class.rsplit(".", 1)[-1].upper()


def classify_field_role(data_class: str) -> FieldRole:
    """Infer the :class:`FieldRole` for a matched value from its data class.

    Conservative / fail-safe: a class we do not explicitly know to be
    reference-only is treated as OPERATE_ON, so an unrecognised value is never
    silently blobbed to the cloud.
    """
    bare = _bare(data_class)
    if bare in _REFERENCE_ONLY_CLASSES:
        return FieldRole.REFERENCE_ONLY
    if bare in _OPERATE_ON_CLASSES:
        return FieldRole.OPERATE_ON
    # Unknown class → fail-safe OPERATE_ON (do not send a broken value to cloud).
    return FieldRole.OPERATE_ON


#: Data classes that are operate-on AND sensitive enough that sending the cloud a
#: hallucinated stand-in is a confidentiality problem, not merely a correctness
#: one — these drive the route-local / keep decision (never silent-blob-to-cloud).
_OPERATE_ON_SENSITIVE = frozenset({
    "SALARY", "AMOUNT", "CURRENCY",
    "DATE_OF_BIRTH",
    "PAN", "CREDIT_CARD", "CARD_EXPIRY", "CVV",
    "IBAN", "ACCOUNT_NUMBER", "SORT_CODE",
    "NHS_NUMBER",
})


def is_operate_on_sensitive(data_class: str) -> bool:
    """Whether ``data_class`` is an operate-on field whose value must NOT be
    silently replaced with an opaque blob bound for the cloud.

    Used by the routing seam to decide whether a PSEUDONYMIZE-to-cloud
    (mode-B / egress) document must instead be routed to a LOCAL model, have the
    field kept/generalised, or be held — rather than feed the cloud an invented
    value (Laura D1).  Conservative: an unknown class is treated as sensitive."""
    bare = _bare(data_class)
    if bare in _OPERATE_ON_SENSITIVE:
        return True
    # An unknown operate-on class is fail-safe sensitive.
    return classify_field_role(data_class) == FieldRole.OPERATE_ON and bare not in {
        # known operate-on but non-sensitive (format only) → may be kept/tokenised
        "PHONE", "DATE",
    }
