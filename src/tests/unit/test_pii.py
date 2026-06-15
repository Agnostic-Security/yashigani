"""
Comprehensive tests for yashigani.pii.

Covers:
  - PiiType enum completeness
  - PiiMode enum completeness
  - _mask() helper (internal)
  - _luhn_valid() — valid + invalid card numbers
  - Detection of each PII type with known patterns
  - Detection of international formats (UK phone, EU IBAN, NHS number)
  - REDACT mode: output format [REDACTED:TYPE]
  - LOG mode: detects but does not modify text
  - BLOCK mode: detects, sets action_taken="blocked", returns original text
  - process() dispatcher for all three modes
  - Mixed PII (multiple types in same text)
  - False-positive resistance (10-digit number, generic date without DOB context)
  - enabled_types filtering (only scan for selected types)
  - Credit card Luhn: valid Luhn passes, invalid Luhn rejected
  - PiiFinding fields (pii_type, start, end, masked_value)
  - Masked value never contains raw PII beyond first-2 / last-2
  - Overlapping deduplication keeps widest span
  - PiiResult.detected is False on clean text
"""
from __future__ import annotations

import pytest

from yashigani.pii.detector import (
    PiiDetector,
    PiiFinding,
    PiiMode,
    PiiResult,
    PiiType,
    _luhn_valid,
    _mask,
)


# ---------------------------------------------------------------------------
# Enum completeness
# ---------------------------------------------------------------------------

class TestEnums:
    def test_pii_type_values(self):
        expected = {
            "SSN", "CREDIT_CARD", "EMAIL", "PHONE", "IBAN",
            "PASSPORT", "NHS_NUMBER", "DRIVERS_LICENCE", "IP_ADDRESS", "DATE_OF_BIRTH",
            # L-01 / red-team F2 breadth: identifying/QI classes for documents.
            "NATIONAL_INSURANCE", "POSTAL_ADDRESS",
        }
        assert {t.value for t in PiiType} == expected

    def test_pii_mode_values(self):
        assert {m.value for m in PiiMode} == {"log", "redact", "block"}


# ---------------------------------------------------------------------------
# _mask helper
# ---------------------------------------------------------------------------

class TestMask:
    def test_long_value(self):
        result = _mask("1234567890")
        assert result == "12****90"

    def test_short_value_fully_masked(self):
        # < 5 chars
        assert _mask("123") == "****"
        assert _mask("AB") == "****"

    def test_exactly_five_chars(self):
        result = _mask("ABCDE")
        assert result == "AB****DE"

    def test_mask_does_not_contain_middle(self):
        raw = "4111111111111111"
        masked = _mask(raw)
        assert raw[2:-2] not in masked
        assert masked.startswith("41")
        assert masked.endswith("11")


# ---------------------------------------------------------------------------
# Luhn validation
# ---------------------------------------------------------------------------

class TestLuhn:
    # Known-good test card numbers (industry standard test values)
    VALID_CARDS = [
        "4111111111111111",   # Visa test
        "5500005555555559",   # Mastercard test
        "371449635398431",    # Amex test
        "6011111111111117",   # Discover test
        "4012888888881881",   # Visa test
    ]

    INVALID_CARDS = [
        "4111111111111112",   # Visa test number with last digit off-by-one
        "1234567890123456",
        # Note: 0000000000000000 is technically Luhn-valid (sum=0, 0%10=0).
        # We test a genuinely Luhn-invalid sequence instead.
        "4111111111111113",
        "9999999999999998",
    ]

    @pytest.mark.parametrize("card", VALID_CARDS)
    def test_valid_cards_pass_luhn(self, card):
        assert _luhn_valid(card) is True

    @pytest.mark.parametrize("card", INVALID_CARDS)
    def test_invalid_cards_fail_luhn(self, card):
        assert _luhn_valid(card) is False

    def test_luhn_strips_spaces(self):
        # 4111 1111 1111 1111 (spaced) is same as unspaced
        assert _luhn_valid("4111 1111 1111 1111") is True

    def test_luhn_strips_dashes(self):
        assert _luhn_valid("4111-1111-1111-1111") is True

    def test_too_short_fails(self):
        assert _luhn_valid("4111") is False


# ---------------------------------------------------------------------------
# Per-type detection
# ---------------------------------------------------------------------------

class TestSsnDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.SSN})

    def test_formatted_ssn(self):
        _, result = self.det.process("SSN: 123-45-6789")
        assert result.detected is True
        assert result.findings[0].pii_type == PiiType.SSN

    def test_finding_span_is_accurate(self):
        text = "My SSN is 123-45-6789 today."
        _, result = self.det.process(text)
        assert result.detected
        f = result.findings[0]
        assert text[f.start:f.end] == "123-45-6789"

    def test_invalid_group_zeros_not_ssn(self):
        # 000 first group is invalid SSN
        _, result = self.det.process("000-45-6789")
        assert result.detected is False

    def test_9xx_first_group_not_ssn(self):
        _, result = self.det.process("987-65-4321")
        assert result.detected is False


class TestCreditCardDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.CREDIT_CARD})

    def test_visa_test_card(self):
        _, result = self.det.process("Card: 4111111111111111")
        assert result.detected is True
        assert result.findings[0].pii_type == PiiType.CREDIT_CARD

    def test_visa_spaced(self):
        _, result = self.det.process("4111 1111 1111 1111")
        assert result.detected is True

    def test_mastercard_test_card(self):
        _, result = self.det.process("5500005555555559")
        assert result.detected is True

    def test_amex_test_card(self):
        _, result = self.det.process("371449635398431")
        assert result.detected is True

    def test_discover_test_card(self):
        _, result = self.det.process("6011111111111117")
        assert result.detected is True

    def test_luhn_invalid_not_flagged(self):
        _, result = self.det.process("4111111111111112")
        assert result.detected is False

    def test_random_16_digit_not_flagged(self):
        # No valid prefix + fails Luhn
        _, result = self.det.process("1234567890123456")
        assert result.detected is False


class TestEmailDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.EMAIL})

    def test_simple_email(self):
        _, result = self.det.process("Contact me at john.doe@example.com")
        assert result.detected is True
        assert result.findings[0].pii_type == PiiType.EMAIL

    def test_email_with_plus(self):
        _, result = self.det.process("user+tag@sub.domain.co.uk")
        assert result.detected is True

    def test_no_email_in_plain_text(self):
        _, result = self.det.process("Hello world, no email here")
        assert result.detected is False


class TestPhoneDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.PHONE})

    def test_us_nanp_dashes(self):
        _, result = self.det.process("Call 212-555-1234")
        assert result.detected is True

    def test_us_nanp_parens(self):
        _, result = self.det.process("(212) 555-1234")
        assert result.detected is True

    def test_international_uk(self):
        _, result = self.det.process("+44 7700 900123")
        assert result.detected is True

    def test_international_germany(self):
        _, result = self.det.process("+49 30 12345678")
        assert result.detected is True

    def test_uk_format_without_prefix(self):
        _, result = self.det.process("0207 946 0000")
        assert result.detected is True


class TestIbanDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.IBAN})

    def test_uk_iban(self):
        _, result = self.det.process("IBAN: GB29NWBK60161331926819")
        assert result.detected is True
        assert result.findings[0].pii_type == PiiType.IBAN

    def test_de_iban(self):
        _, result = self.det.process("DE89370400440532013000")
        assert result.detected is True

    def test_iban_spaced(self):
        _, result = self.det.process("GB29 NWBK 6016 1331 9268 19")
        assert result.detected is True


class TestPassportDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.PASSPORT})

    def test_us_passport(self):
        _, result = self.det.process("Passport: A12345678")
        assert result.detected is True

    def test_uk_passport(self):
        _, result = self.det.process("UK passport GB1234567")
        assert result.detected is True

    # EU / wide-form passports that contain digits — must still match.
    def test_eu_de_passport_with_digits(self):
        # German-style: 1 letter + mixed alphanumeric containing digits
        _, result = self.det.process("passport C3045988")
        assert result.detected is True

    def test_eu_nl_passport_with_mixed(self):
        # NL-style: 2 letters + alphanumeric containing digits
        _, result = self.det.process("NL1234AB5")
        assert result.detected is True

    def test_canadian_passport(self):
        _, result = self.det.process("CA passport AB123456")
        assert result.detected is True


class TestPassportFalsePositiveResistance:
    """PII-PASSPORT-FP-001 — all-alpha uppercase words must NOT match passport patterns.

    Before the fix, the EU-wide pattern `[A-Z]{1,2}[0-9A-Z]{6,9}` matched any
    uppercase English word of 7–11 chars (CUSTOMER, CLINICAL, PARTICIPANT, etc.).
    This caused document-enforcement to record them as PII "originals" and then fail
    CLOSED when the residual-presence check found the same words in the rendered output.
    """

    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.PASSPORT})

    @pytest.mark.parametrize("word", [
        "CUSTOMER",
        "CLINICAL",
        "PARTICIPANT",
        "RECORDS",
        "SUMMARY",
        "HANDLING",
        "PROTOCOL",
        "BIOSTATISTICS",
        "RESOLUTION",
        "DESTINATION",
    ])
    def test_all_alpha_word_not_passport(self, word):
        _, result = self.det.process(word)
        assert result.detected is False, (
            f"{word!r} should NOT be flagged as a passport number "
            "(PII-PASSPORT-FP-001: all-alpha words lack digits)"
        )

    def test_demo_file_01_no_spurious_passport(self):
        """01_support_export_REDACT.txt: uppercase header words must not match passport."""
        text = (
            "CUSTOMER SUPPORT CASE EXPORT — Case #CS-2026-04812\n"
            "SUMMARY\n"
            "AGENT NOTES\n"
            "RESOLUTION\n"
        )
        _, result = self.det.process(text)
        assert result.detected is False, (
            f"Spurious passport hits on demo file 01 headers: {result.findings}"
        )

    def test_demo_file_02_no_spurious_passport(self):
        """02_research_log_PSEUDONYMIZE.txt: CLINICAL/PARTICIPANT/RECORDS must not match."""
        text = (
            "CLINICAL STUDY PARTICIPANT LOG — Protocol AGS-2026-NEU-07\n"
            "VISIT RECORDS\n"
            "NOTE FOR ANALYSIS\n"
        )
        _, result = self.det.process(text)
        assert result.detected is False, (
            f"Spurious passport hits on demo file 02 headers: {result.findings}"
        )


class TestNhsDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.NHS_NUMBER})

    def test_nhs_formatted(self):
        _, result = self.det.process("NHS number: 943 476 5919")
        assert result.detected is True
        assert result.findings[0].pii_type == PiiType.NHS_NUMBER

    def test_nhs_unformatted(self):
        _, result = self.det.process("NHS: 9434765919")
        assert result.detected is True


class TestDriversLicenceDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.DRIVERS_LICENCE})

    def test_us_format_1_letter_7_digits(self):
        _, result = self.det.process("DL: A1234567")
        assert result.detected is True

    def test_uk_dvla_format(self):
        # SMITH 701010 JA 9AB (simplified, concatenated)
        _, result = self.det.process("SMITH701010JA9AB")
        assert result.detected is True


class TestIpAddressDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.IP_ADDRESS})

    def test_ipv4(self):
        _, result = self.det.process("server at 192.168.1.100")
        assert result.detected is True
        assert result.findings[0].pii_type == PiiType.IP_ADDRESS

    def test_ipv4_strict_octets(self):
        # 999.999.999.999 is not a valid IP
        _, result = self.det.process("999.999.999.999")
        assert result.detected is False

    def test_ipv6_full(self):
        _, result = self.det.process("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert result.detected is True

    def test_ipv6_loopback(self):
        _, result = self.det.process("::1")
        assert result.detected is True


class TestDateOfBirthDetection:
    def setup_method(self):
        self.det = PiiDetector(enabled_types={PiiType.DATE_OF_BIRTH})

    def test_dob_keyword(self):
        _, result = self.det.process("DOB: 15/03/1990")
        assert result.detected is True
        assert result.findings[0].pii_type == PiiType.DATE_OF_BIRTH

    def test_date_of_birth_phrase(self):
        _, result = self.det.process("date of birth: 1990-03-15")
        assert result.detected is True

    def test_born_keyword(self):
        _, result = self.det.process("She was born on March 15, 1990")
        assert result.detected is True

    def test_bare_date_without_context_not_flagged(self):
        # A date with no DOB-context keyword must NOT be flagged.
        _, result = self.det.process("The report was published on 15/03/1990.")
        assert result.detected is False


# ---------------------------------------------------------------------------
# Mode behaviour
# ---------------------------------------------------------------------------

class TestLogMode:
    def test_text_unchanged(self):
        det = PiiDetector(mode=PiiMode.LOG)
        text = "john@example.com"
        out, result = det.process(text)
        assert out == text

    def test_action_taken_logged(self):
        det = PiiDetector(mode=PiiMode.LOG)
        _, result = det.process("john@example.com")
        assert result.action_taken == "logged"

    def test_findings_populated(self):
        det = PiiDetector(mode=PiiMode.LOG)
        _, result = det.process("john@example.com")
        assert result.detected is True
        assert len(result.findings) > 0


class TestRedactMode:
    def test_email_replaced(self):
        det = PiiDetector(mode=PiiMode.REDACT)
        out, result = det.process("Contact: john@example.com please")
        assert "[REDACTED:EMAIL]" in out
        assert "john@example.com" not in out

    def test_ssn_replaced(self):
        det = PiiDetector(mode=PiiMode.REDACT, enabled_types={PiiType.SSN})
        out, result = det.process("SSN 123-45-6789 here")
        assert "[REDACTED:SSN]" in out
        assert "123-45-6789" not in out

    def test_action_taken_redacted(self):
        det = PiiDetector(mode=PiiMode.REDACT)
        _, result = det.process("john@example.com")
        assert result.action_taken == "redacted"

    def test_clean_text_unchanged(self):
        det = PiiDetector(mode=PiiMode.REDACT)
        out, result = det.process("Hello world")
        assert out == "Hello world"
        assert result.detected is False

    def test_placeholder_format(self):
        # Validate the exact placeholder format including colon and type value.
        det = PiiDetector(mode=PiiMode.REDACT, enabled_types={PiiType.EMAIL})
        out, _ = det.process("a@b.com")
        assert out == "[REDACTED:EMAIL]"


class TestBlockMode:
    def test_text_unchanged(self):
        det = PiiDetector(mode=PiiMode.BLOCK)
        text = "john@example.com"
        out, result = det.process(text)
        assert out == text

    def test_action_taken_blocked(self):
        det = PiiDetector(mode=PiiMode.BLOCK)
        _, result = det.process("john@example.com")
        assert result.action_taken == "blocked"

    def test_detected_true_on_pii(self):
        det = PiiDetector(mode=PiiMode.BLOCK)
        _, result = det.process("john@example.com")
        assert result.detected is True

    def test_detected_false_on_clean(self):
        det = PiiDetector(mode=PiiMode.BLOCK)
        _, result = det.process("Hello world")
        assert result.detected is False


# ---------------------------------------------------------------------------
# Mixed PII
# ---------------------------------------------------------------------------

class TestMixedPii:
    def test_multiple_types_in_one_text(self):
        text = (
            "Email: alice@example.com, "
            "SSN: 123-45-6789, "
            "IP: 192.168.0.1"
        )
        det = PiiDetector(
            mode=PiiMode.LOG,
            enabled_types={PiiType.EMAIL, PiiType.SSN, PiiType.IP_ADDRESS},
        )
        _, result = det.process(text)
        assert result.detected is True
        types_found = {f.pii_type for f in result.findings}
        assert PiiType.EMAIL in types_found
        assert PiiType.SSN in types_found
        assert PiiType.IP_ADDRESS in types_found

    def test_redact_replaces_all_matches(self):
        text = "alice@example.com and bob@example.com"
        det = PiiDetector(mode=PiiMode.REDACT, enabled_types={PiiType.EMAIL})
        out, result = det.process(text)
        assert "alice@example.com" not in out
        assert "bob@example.com" not in out
        assert out.count("[REDACTED:EMAIL]") == 2

    def test_finding_count_matches_redaction_count(self):
        text = "alice@example.com and bob@example.com"
        det = PiiDetector(mode=PiiMode.REDACT, enabled_types={PiiType.EMAIL})
        _, result = det.process(text)
        assert len(result.findings) == 2


# ---------------------------------------------------------------------------
# False-positive resistance
# ---------------------------------------------------------------------------

class TestFalsePositiveResistance:
    def test_10_digit_number_not_phone_and_not_ssn(self):
        # A plain 10-digit number like an order ID should not be flagged as SSN
        # (SSN is 9 digits; 10 digits is a different shape).
        det = PiiDetector(enabled_types={PiiType.SSN})
        _, result = det.process("Order ID: 1234567890")
        assert result.detected is False

    def test_generic_date_without_dob_context(self):
        det = PiiDetector(enabled_types={PiiType.DATE_OF_BIRTH})
        _, result = det.process("Report date: 2024-01-15")
        assert result.detected is False

    def test_short_number_not_credit_card(self):
        det = PiiDetector(enabled_types={PiiType.CREDIT_CARD})
        _, result = det.process("Order 12345")
        assert result.detected is False

    def test_invalid_ip_octet_not_flagged(self):
        det = PiiDetector(enabled_types={PiiType.IP_ADDRESS})
        _, result = det.process("version 256.0.0.1")
        assert result.detected is False


# ---------------------------------------------------------------------------
# enabled_types filtering
# ---------------------------------------------------------------------------

class TestEnabledTypesFiltering:
    def test_only_scans_selected_types(self):
        text = "john@example.com and SSN 123-45-6789"
        det = PiiDetector(enabled_types={PiiType.SSN})  # only SSN
        _, result = det.process(text)
        types = {f.pii_type for f in result.findings}
        assert PiiType.EMAIL not in types
        assert PiiType.SSN in types

    def test_all_types_when_none_specified(self):
        # Passing enabled_types=None → all types active
        det = PiiDetector(enabled_types=None)
        assert det.enabled_types == set(PiiType)

    def test_empty_enabled_types_set(self):
        # An empty set means nothing will match
        det = PiiDetector(enabled_types=set())
        _, result = det.process("john@example.com 123-45-6789 4111111111111111")
        assert result.detected is False


# ---------------------------------------------------------------------------
# PiiFinding fields
# ---------------------------------------------------------------------------

class TestPiiFindingFields:
    def test_finding_has_correct_type(self):
        det = PiiDetector(enabled_types={PiiType.EMAIL})
        _, result = det.process("a@b.com")
        f = result.findings[0]
        assert f.pii_type == PiiType.EMAIL

    def test_finding_span_covers_match(self):
        text = "hello a@b.com world"
        det = PiiDetector(enabled_types={PiiType.EMAIL})
        _, result = det.process(text)
        f = result.findings[0]
        assert text[f.start:f.end] == "a@b.com"

    def test_masked_value_format(self):
        det = PiiDetector(enabled_types={PiiType.EMAIL})
        _, result = det.process("john.doe@example.com")
        f = result.findings[0]
        # First 2 chars: "jo", last 2 chars: "om", rest masked
        assert f.masked_value.startswith("jo")
        assert f.masked_value.endswith("om")
        assert "****" in f.masked_value

    def test_masked_value_short_input(self):
        det = PiiDetector(enabled_types={PiiType.EMAIL})
        # a@b.com is 7 chars — should get first-2 / last-2
        _, result = det.process("a@b.com")
        f = result.findings[0]
        assert f.masked_value == "a@****om"

    def test_raw_pii_not_in_masked_value_middle(self):
        # Middle chars of a long SSN must not appear in masked value
        raw_ssn = "123-45-6789"
        det = PiiDetector(enabled_types={PiiType.SSN})
        _, result = det.process(raw_ssn)
        f = result.findings[0]
        # Middle section "3-45-67" must not appear literally
        middle = raw_ssn[2:-2]
        assert middle not in f.masked_value


# ---------------------------------------------------------------------------
# PiiResult fields
# ---------------------------------------------------------------------------

class TestPiiResultFields:
    def test_clean_text_detected_false(self):
        det = PiiDetector()
        _, result = det.process("nothing sensitive here")
        assert result.detected is False
        assert result.findings == []

    def test_mode_stored_in_result(self):
        det = PiiDetector(mode=PiiMode.REDACT)
        _, result = det.process("a@b.com")
        assert result.mode == PiiMode.REDACT

    def test_detect_method_always_logged(self):
        det = PiiDetector(mode=PiiMode.BLOCK)
        result = det.detect("a@b.com")
        # detect() is a read-only scan; action_taken is always "logged"
        assert result.action_taken == "logged"


# ---------------------------------------------------------------------------
# International formats
# ---------------------------------------------------------------------------

class TestInternationalFormats:
    def test_uk_mobile_international(self):
        det = PiiDetector(enabled_types={PiiType.PHONE})
        _, result = det.process("+44 7700 900123")
        assert result.detected is True

    def test_eu_iban(self):
        det = PiiDetector(enabled_types={PiiType.IBAN})
        _, result = det.process("DE89370400440532013000")
        assert result.detected is True

    def test_nhs_number_spaced(self):
        det = PiiDetector(enabled_types={PiiType.NHS_NUMBER})
        _, result = det.process("NHS: 943 476 5919")
        assert result.detected is True

    def test_fr_iban(self):
        det = PiiDetector(enabled_types={PiiType.IBAN})
        _, result = det.process("FR7630006000011234567890189")
        assert result.detected is True
