"""
Yashigani PII detection — compiled regex patterns per PII type.

Each type exposes a list of compiled patterns. The detector iterates all
patterns for every enabled type and merges overlapping matches.

Design notes:
- Patterns are anchored to word boundaries where appropriate to reduce
  false positives.
- All patterns are compiled with re.IGNORECASE where casing is irrelevant
  (e.g. IBAN country codes, passport types).
- The DOB patterns are context-sensitive: they require a proximity keyword
  (born / dob / date of birth) within the same match group so that bare
  date strings are not flagged.
"""
from __future__ import annotations

import re
from typing import NamedTuple


class PatternSet(NamedTuple):
    name: str
    patterns: list[re.Pattern[str]]


# ---------------------------------------------------------------------------
# SSN (US Social Security Number)
# ---------------------------------------------------------------------------

SSN_PATTERNS: list[re.Pattern[str]] = [
    # Formatted with dashes:  123-45-6789
    re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    # Formatted with spaces: 123 45 6789 (LAURA-31DR-002 — spaced-digit variant
    # not previously covered; must be detected before reaching OPA).
    re.compile(r"\b(?!000|666|9\d{2})\d{3}\s(?!00)\d{2}\s(?!0000)\d{4}\b"),
    # Unformatted 9-digit block — only flag when surrounded by non-digits
    # to avoid matching credit card sub-sequences.
    re.compile(r"(?<!\d)(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}(?!\d)"),
]

# ---------------------------------------------------------------------------
# Credit card
# ---------------------------------------------------------------------------
# Post-regex we run Luhn validation; patterns here are intentionally broad
# (allow optional spaces/dashes) and narrow by network prefix.

CREDIT_CARD_PATTERNS: list[re.Pattern[str]] = [
    # Visa: 4xxx xxxx xxxx xxxx (13 or 16 digits)
    re.compile(r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    re.compile(r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{5}\b"),  # 13-digit Visa
    # Mastercard: 51-55 or 2221-2720 prefix
    re.compile(r"\b(?:5[1-5]\d{2}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720))[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    # Amex: 3[47]x 13 more digits  (4-6-5 grouping)
    re.compile(r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b"),
    # Discover: 6011, 622126-622925, 644-649, 65
    re.compile(r"\b(?:6(?:011|22(?:1(?:2[6-9]|[3-9]\d)|[2-8]\d{2}|9(?:[01]\d|2[0-5]))|4[4-9]\d|5\d{2}))\d{10,13}\b"),
]

# ---------------------------------------------------------------------------
# Email  (RFC 5322 simplified)
# ---------------------------------------------------------------------------

EMAIL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    ),
]

# ---------------------------------------------------------------------------
# Phone number
# ---------------------------------------------------------------------------
# International (+1, +44, +49, etc.) and common national formats.

PHONE_PATTERNS: list[re.Pattern[str]] = [
    # E.164-ish international: +<country_code> followed by 6–14 digits with
    # optional spaces/dashes between groups.
    re.compile(
        r"\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{1,4}[\s\-]?\d{1,4}[\s\-]?\d{0,4}"
        r"(?=\s|$|[^\d])"
    ),
    # US/CA NANP: (NXX) NXX-XXXX or NXX-NXX-XXXX
    # Note: no leading \b — opening paren is not a word char.
    re.compile(r"(?<!\d)(?:\(\d{3}\)[\s\-]?|\d{3}[\s\-])\d{3}[\s\-]\d{4}(?!\d)"),
    # UK landline / mobile without leading +44
    re.compile(r"\b0\d{3,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b"),
]

# ---------------------------------------------------------------------------
# IBAN (International Bank Account Number)
# ---------------------------------------------------------------------------
# ISO 13616: 2-letter country code + 2 check digits + up to 30 alphanumeric.
# Allowing optional spaces every 4 chars (print format).

IBAN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?[A-Z0-9]{4}[\s]?[A-Z0-9]{4}"
        r"[\s]?[A-Z0-9]{0,4}[\s]?[A-Z0-9]{0,4}[\s]?[A-Z0-9]{0,4}\b",
        re.IGNORECASE,
    ),
]

# ---------------------------------------------------------------------------
# Passport number
# ---------------------------------------------------------------------------

PASSPORT_PATTERNS: list[re.Pattern[str]] = [
    # US: letter + 8 digits
    re.compile(r"\b[A-Z]\d{8}\b"),
    # UK: 2 letters + 7 digits
    re.compile(r"\b[A-Z]{2}\d{7}\b"),
    # EU (DE, FR, NL, etc.): 1–2 letters + 6–9 alphanumeric, wide form.
    # PII-PASSPORT-FP-001: the original `[A-Z]{1,2}[0-9A-Z]{6,9}` matched every
    # uppercase English word of 7–11 chars (CUSTOMER, CLINICAL, PARTICIPANT, etc.).
    # Document-enforcement records these as PII "originals"; the residual check then
    # fails CLOSED on every document that contains uppercase words.
    # Fix: require at least one digit anywhere in the token via a lookahead
    # `(?=[A-Z0-9]*[0-9])`. Real passport numbers always contain digits;
    # all-alpha words (plain English) do not.
    re.compile(r"\b(?=[A-Z0-9]*[0-9])[A-Z]{1,2}[0-9A-Z]{6,9}\b"),
    # Canadian: 2 letters + 6 digits
    re.compile(r"\b[A-Z]{2}\d{6}\b"),
]

# ---------------------------------------------------------------------------
# NHS number (UK)
# ---------------------------------------------------------------------------
# 10 digits with optional single spaces after every 3rd digit.

NHS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b\d{3}[\s]?\d{3}[\s]?\d{4}\b"),
]

# ---------------------------------------------------------------------------
# Driver's licence
# ---------------------------------------------------------------------------

DRIVERS_LICENCE_PATTERNS: list[re.Pattern[str]] = [
    # UK DVLA: SURNAME(5) YEAR(2) MONTH(2) DAY(2+1) INITIAL(2) CHECK(2) + optional digit
    re.compile(r"\b[A-Z]{2,5}\d{6}[A-Z]{2}\d[A-Z]{2}\b", re.IGNORECASE),
    # US formats (simplified — alphanumeric 6–10 chars).
    # Common: letter(s) + digits, e.g. A1234567 (CA), D1234-56789-01234 (IL-ish).
    re.compile(r"\b[A-Z]\d{7}\b"),           # 1 letter + 7 digits (e.g. FL, TX)
    re.compile(r"\b[A-Z]\d{3}[\s\-]\d{3}[\s\-]\d{3}[\s\-]\d{3}\b"),  # IL-style
    re.compile(r"\b\d{3}[\s\-]\d{3}[\s\-]\d{3}\b"),                   # WI-style
    re.compile(r"\b[A-Z]{2}\d{6}\b"),        # VA, etc.
    re.compile(r"\b\d{9}\b"),                # numeric-only 9-digit (some states)
]

# ---------------------------------------------------------------------------
# IP address
# ---------------------------------------------------------------------------

IP_ADDRESS_PATTERNS: list[re.Pattern[str]] = [
    # IPv4 — strict octet ranges 0-255
    re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    # IPv6 — simplified (full, compressed, IPv4-mapped)
    re.compile(
        r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"                          # full
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:\b"                                       # trailing ::
        r"|\b:(?::[0-9A-Fa-f]{1,4}){1,7}\b"                                       # leading ::
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b"                      # one gap
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}\b"
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}\b"
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}\b"
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}\b"
        r"|\b[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}\b"
        r"|::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b"
        r"|\b::1\b"
    ),
]

# ---------------------------------------------------------------------------
# Date of birth — context-sensitive
# ---------------------------------------------------------------------------
# Only flag dates that appear near a DOB keyword within the same pattern.
# This avoids tagging every date in the text (timestamps, report dates, etc.).

_DOB_KEYWORD = r"(?:born(?:\s+on)?|d\.?o\.?b\.?|date\s+of\s+birth)\s*:?\s*"

DATE_OF_BIRTH_PATTERNS: list[re.Pattern[str]] = [
    # Keyword followed by  DD/MM/YYYY  or  MM/DD/YYYY  or  YYYY-MM-DD
    re.compile(
        _DOB_KEYWORD + r"\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}",
        re.IGNORECASE,
    ),
    # Keyword followed by  Month DD, YYYY  or  DD Month YYYY
    re.compile(
        _DOB_KEYWORD
        + r"(?:\d{1,2}\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|"
          r"May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|"
          r"Nov(?:ember)?|Dec(?:ember)?)"
        + r"(?:\s+\d{1,2},?)?\s+\d{2,4}",
        re.IGNORECASE,
    ),
    # ISO date following keyword
    re.compile(
        _DOB_KEYWORD + r"\d{4}-\d{2}-\d{2}",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------------------
# UK National Insurance number (NINO)
# ---------------------------------------------------------------------------
# Format: two prefix letters + six digits + one suffix letter (A–D), printed
# with or without single spaces between the groups (e.g. "AA 10 10 10 A" or
# "AA101010A").  The prefix excludes the invalid first/second letters per
# HMRC rules (D, F, I, Q, U, V never as either prefix letter; O never second);
# the suffix is A–D.  Distinctive enough to match on a lone cell without a
# proximity keyword.

NATIONAL_INSURANCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)"
        r"[ABCEGHJ-PRSTW-Z][ABCEGHJ-NPRSTW-Z]"  # 2 valid prefix letters
        r"[\s]?\d{2}[\s]?\d{2}[\s]?\d{2}[\s]?"   # 6 digits (optional spaces)
        r"[A-D]\b",                               # suffix A-D
        re.IGNORECASE,
    ),
]

# ---------------------------------------------------------------------------
# UK postal address — anchored on the postcode (the address's identifying core)
# ---------------------------------------------------------------------------
# A UK postcode (e.g. "SW1A 1AA", "M1 2WD", "BS1 4ST") is the re-identifying
# core of a postal address; flagging it catches the whole address cell.  The
# outward code is 2–4 chars (letter(s)+digit(s), optional trailing letter), a
# space (optional in storage), then the inward code (digit + 2 letters).

POSTAL_ADDRESS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b[A-Z]{1,2}\d[A-Z\d]?[\s]?\d[A-Z]{2}\b",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------------------
# Registry — maps PiiType string key to its pattern list
# (imported by detector.py to keep coupling explicit)
# ---------------------------------------------------------------------------

PATTERN_REGISTRY: dict[str, list[re.Pattern[str]]] = {
    "SSN":                  SSN_PATTERNS,
    "CREDIT_CARD":          CREDIT_CARD_PATTERNS,
    "EMAIL":                EMAIL_PATTERNS,
    "PHONE":                PHONE_PATTERNS,
    "IBAN":                 IBAN_PATTERNS,
    "PASSPORT":             PASSPORT_PATTERNS,
    "NHS_NUMBER":           NHS_PATTERNS,
    "DRIVERS_LICENCE":      DRIVERS_LICENCE_PATTERNS,
    "IP_ADDRESS":           IP_ADDRESS_PATTERNS,
    "DATE_OF_BIRTH":        DATE_OF_BIRTH_PATTERNS,
    "NATIONAL_INSURANCE":   NATIONAL_INSURANCE_PATTERNS,
    "POSTAL_ADDRESS":       POSTAL_ADDRESS_PATTERNS,
}
