import os
import sys
import pytest

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend.models.schemas import PIICategory, CustomRegexRule
from backend.core.pii_engine import (
    validate_verhoeff_checksum,
    HybridPIIEngine,
    GOVERNMENT_OFFICIAL_WHITELIST,
)
from backend.core.ocr_engine import OCRWordToken


def test_verhoeff_checksum():
    # Valid Aadhaar numbers with valid Verhoeff checksum
    valid_aadhaar_1 = "294718273645"
    assert validate_verhoeff_checksum(valid_aadhaar_1) is True

    # Corrupting last digit should fail checksum
    invalid_aadhaar = "294718273640"
    assert validate_verhoeff_checksum(invalid_aadhaar) is False

    # Non-12-digit string
    assert validate_verhoeff_checksum("12345") is False


def test_aadhaar_detection_and_checksum():
    engine = HybridPIIEngine()
    text = "Citizen Aadhaar number is 2947 1827 3645 for verification."
    tokens = [
        OCRWordToken("Citizen", 10, 10, 50, 20, 0.99, 1),
        OCRWordToken("Aadhaar", 60, 10, 100, 20, 0.99, 1),
        OCRWordToken("2947", 110, 10, 140, 20, 0.99, 1),
        OCRWordToken("1827", 150, 10, 180, 20, 0.99, 1),
        OCRWordToken("3645", 190, 10, 220, 20, 0.99, 1),
    ]

    entities = engine.detect_pii(text, tokens)
    aadhaar_ents = [e for e in entities if e.category == PIICategory.AADHAAR]
    assert len(aadhaar_ents) == 1
    assert "2947 1827 3645" in aadhaar_ents[0].text
    assert aadhaar_ents[0].validation_status == "VALID"
    assert aadhaar_ents[0].confidence > 0.9


def test_pan_card_detection():
    engine = HybridPIIEngine()
    text = "Assessee PAN is ABCPV1234F registered with Income Tax Department."
    tokens = [
        OCRWordToken("Assessee", 10, 10, 50, 20, 0.99, 1),
        OCRWordToken("PAN", 60, 10, 80, 20, 0.99, 1),
        OCRWordToken("ABCPV1234F", 90, 10, 150, 20, 0.99, 1),
    ]

    entities = engine.detect_pii(text, tokens)
    pan_ents = [e for e in entities if e.category == PIICategory.PAN]
    assert len(pan_ents) == 1
    assert pan_ents[0].text == "ABCPV1234F"
    assert pan_ents[0].confidence >= 0.95


def test_voter_id_and_phone():
    engine = HybridPIIEngine()
    text = "Voter ID: WBG1234567 and Mobile: +91 9876543210"
    tokens = [
        OCRWordToken("WBG1234567", 10, 10, 60, 20, 0.99, 1),
        OCRWordToken("+91", 70, 10, 90, 20, 0.99, 1),
        OCRWordToken("9876543210", 100, 10, 160, 20, 0.99, 1),
    ]

    entities = engine.detect_pii(text, tokens)
    categories = {e.category for e in entities}
    assert PIICategory.VOTER_ID in categories
    assert PIICategory.PHONE in categories


def test_banking_pii_ifsc_upi():
    engine = HybridPIIEngine()
    text = "Refund to Account No: 9123456789012 with IFSC SBIN0001234 and UPI ID amitabh@oksbi."
    tokens = [
        OCRWordToken("Account", 10, 10, 40, 20, 0.99, 1),
        OCRWordToken("No:", 45, 10, 60, 20, 0.99, 1),
        OCRWordToken("9123456789012", 65, 10, 120, 20, 0.99, 1),
        OCRWordToken("SBIN0001234", 130, 10, 180, 20, 0.99, 1),
        OCRWordToken("amitabh@oksbi", 190, 10, 240, 20, 0.99, 1),
    ]

    entities = engine.detect_pii(text, tokens)
    categories = {e.category for e in entities}
    assert PIICategory.BANK_ACCOUNT in categories
    assert PIICategory.IFSC in categories
    assert PIICategory.UPI in categories


def test_government_official_whitelist():
    engine = HybridPIIEngine()
    text = "Issued by GOVERNMENT OF INDIA, Ministry of Finance, Tahsildar Office."
    tokens = [
        OCRWordToken("GOVERNMENT", 10, 10, 50, 20, 0.99, 1),
        OCRWordToken("OF", 55, 10, 65, 20, 0.99, 1),
        OCRWordToken("INDIA", 70, 10, 95, 20, 0.99, 1),
        OCRWordToken("Tahsildar", 100, 10, 140, 20, 0.99, 1),
    ]

    entities = engine.detect_pii(text, tokens)
    # Whitelisted government entities should not be flagged as citizen names
    for e in entities:
        assert e.text.upper() not in GOVERNMENT_OFFICIAL_WHITELIST


def test_custom_rule_injection():
    engine = HybridPIIEngine()
    custom_rule = CustomRegexRule(
        name="State Ration ID",
        category="CUSTOM",
        pattern=r"\bRAT-[0-9]{6}\b",
        description="State ration card pattern"
    )
    engine.add_custom_rule(custom_rule)

    text = "Beneficiary ration card is RAT-889900."
    tokens = [OCRWordToken("RAT-889900", 10, 10, 60, 20, 0.99, 1)]

    entities = engine.detect_pii(text, tokens)
    custom_ents = [e for e in entities if e.category == PIICategory.CUSTOM]
    assert len(custom_ents) == 1
    assert custom_ents[0].text == "RAT-889900"
    assert custom_ents[0].rule_triggered == "State Ration ID"
