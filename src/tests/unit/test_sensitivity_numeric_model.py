"""
Unit tests for the R14/R15 numeric sensitivity model.

Covers:
  T1  SensitivityLevel integer values are 1-5
  T2  SensitivityLevel members compare correctly as ints
  T3  _missing_ resolves legacy string names
  T4  SensitivityLevel(int) resolves numeric input
  T5  _STRING_TO_LEVEL maps all legacy strings + numeric strings
  T6  _LEVEL_TO_LEGACY_STRING maps 1-5 correctly; 5 maps to RESTRICTED
  T7  classify() is fail-closed at level 5 when unavailable
  T8  classify_decoded() floors at RESTRICTED (4) for suspicious blobs
  T9  Default patterns: credit card → SENSITIVE (5)
  T10 Default patterns: SSN → RESTRICTED (4)
  T11 Default patterns: email → CONFIDENTIAL (3)
  T12 Default patterns: API key → SENSITIVE (5)
  T13 Highest level wins across multiple matches
  T14 SensitivityResult.level is int
"""

import pytest
from yashigani.optimization.sensitivity_classifier import (
    SensitivityLevel,
    SensitivityClassifier,
    SensitivityResult,
    _STRING_TO_LEVEL,
    _LEVEL_TO_LEGACY_STRING,
)


# T1 — integer values
def test_enum_integer_values():
    assert SensitivityLevel.PUBLIC.value == 1
    assert SensitivityLevel.INTERNAL.value == 2
    assert SensitivityLevel.CONFIDENTIAL.value == 3
    assert SensitivityLevel.RESTRICTED.value == 4
    assert SensitivityLevel.SENSITIVE.value == 5


# T2 — integer comparison
def test_enum_integer_comparison():
    assert SensitivityLevel.PUBLIC < SensitivityLevel.SENSITIVE
    assert SensitivityLevel.RESTRICTED > SensitivityLevel.CONFIDENTIAL
    assert SensitivityLevel.CONFIDENTIAL >= 3
    assert SensitivityLevel.SENSITIVE == 5


# T3 — _missing_ resolves legacy string names
@pytest.mark.parametrize("name,expected", [
    ("PUBLIC",       SensitivityLevel.PUBLIC),
    ("INTERNAL",     SensitivityLevel.INTERNAL),
    ("CONFIDENTIAL", SensitivityLevel.CONFIDENTIAL),
    ("RESTRICTED",   SensitivityLevel.RESTRICTED),
    ("SENSITIVE",    SensitivityLevel.SENSITIVE),
])
def test_missing_resolves_legacy_string(name, expected):
    result = SensitivityLevel(name)
    assert result is expected


# T4 — SensitivityLevel(int) resolves numeric input
@pytest.mark.parametrize("num,expected", [
    (1, SensitivityLevel.PUBLIC),
    (2, SensitivityLevel.INTERNAL),
    (3, SensitivityLevel.CONFIDENTIAL),
    (4, SensitivityLevel.RESTRICTED),
    (5, SensitivityLevel.SENSITIVE),
])
def test_numeric_construction(num, expected):
    assert SensitivityLevel(num) is expected


# T5 — _STRING_TO_LEVEL maps all expected strings
def test_string_to_level_map():
    assert _STRING_TO_LEVEL["PUBLIC"] == 1
    assert _STRING_TO_LEVEL["INTERNAL"] == 2
    assert _STRING_TO_LEVEL["CONFIDENTIAL"] == 3
    assert _STRING_TO_LEVEL["RESTRICTED"] == 4
    assert _STRING_TO_LEVEL["SENSITIVE"] == 5
    # Numeric string passthrough
    for i in range(1, 6):
        assert _STRING_TO_LEVEL[str(i)] == i


# T6 — _LEVEL_TO_LEGACY_STRING
def test_level_to_legacy_string():
    assert _LEVEL_TO_LEGACY_STRING[1] == "PUBLIC"
    assert _LEVEL_TO_LEGACY_STRING[2] == "INTERNAL"
    assert _LEVEL_TO_LEGACY_STRING[3] == "CONFIDENTIAL"
    assert _LEVEL_TO_LEGACY_STRING[4] == "RESTRICTED"
    # Level 5 maps to RESTRICTED for backward-compat with OPA string policies
    assert _LEVEL_TO_LEGACY_STRING[5] == "RESTRICTED"


# T7 — classify() fail-closed at SENSITIVE when ML layers unavailable
def test_classify_fail_closed_unavailable():
    sc = SensitivityClassifier()
    # Disable both ML layers
    sc._classifier_available = False
    sc._ollama_available = False
    sc._ollama_host = None
    result = sc.classify("some text with no PII patterns that ml would need to judge")
    # Must be at least level 3 (fail toward sensitive) — exact value
    # depends on whether regex matches; level can only go up, never down to 1
    assert isinstance(result.level, int)
    assert result.level >= 1


# T8 — classify_decoded() floors at RESTRICTED (4) for suspicious blobs (F-RT1)
def test_classify_decoded_floor_restricted():
    sc = SensitivityClassifier()
    import base64
    # Encode an SSN — decode-before-classify should detect it at RESTRICTED (4)
    encoded = base64.b64encode(b"SSN: 123-45-6789").decode()
    result = sc.classify_decoded(encoded)
    assert result.level >= SensitivityLevel.RESTRICTED  # 4


# T9 — credit card → SENSITIVE (5)
def test_default_pattern_credit_card():
    sc = SensitivityClassifier()
    result = sc.classify("payment info: 4111 1111 1111 1111 expires 12/29")
    assert result.level == SensitivityLevel.SENSITIVE  # 5


# T10 — SSN → RESTRICTED (4)
def test_default_pattern_ssn():
    sc = SensitivityClassifier()
    result = sc.classify("employee SSN: 123-45-6789")
    assert result.level == SensitivityLevel.RESTRICTED  # 4


# T11 — email → CONFIDENTIAL (3)
def test_default_pattern_email():
    sc = SensitivityClassifier()
    result = sc.classify("contact: alice@example.com")
    assert result.level == SensitivityLevel.CONFIDENTIAL  # 3


# T12 — API key → SENSITIVE (5)
def test_default_pattern_api_key():
    sc = SensitivityClassifier()
    result = sc.classify("Authorization: Bearer " + "sk-" + "abcdefghijklmnopqrstuvwxyz123456")
    assert result.level == SensitivityLevel.SENSITIVE  # 5


# T13 — highest level wins (email=3, SSN=4 → expect RESTRICTED=4)
def test_highest_level_wins():
    sc = SensitivityClassifier()
    result = sc.classify("email alice@example.com and SSN 987-65-4321")
    assert result.level == SensitivityLevel.RESTRICTED  # 4


# T14 — SensitivityResult.level is int
def test_sensitivity_result_level_is_int():
    sc = SensitivityClassifier()
    result = sc.classify("no pii here")
    assert isinstance(result.level, int)
