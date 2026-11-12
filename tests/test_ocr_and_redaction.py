import os
import sys
import numpy as np
import pytest

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend.models.schemas import PIICategory, RedactionStyle, BoundingBox, DetectedPII
from backend.core.redactor import redact_image, redact_pdf_document
from backend.core.audit import create_audit_certificate, generate_pdf_certificate_bytes
from backend.assets.generator import generate_aadhaar_card_image, generate_tax_assessment_notice_pdf


def test_redact_image_styles():
    # Base white canvas
    img = np.ones((400, 400, 3), dtype=np.uint8) * 255
    bbox = BoundingBox(x0=50, y0=50, x1=200, y1=100, page_number=1)
    boxes = [(bbox, "AADHAAR REDACTED")]

    # Test Blackout
    redacted_black = redact_image(img, boxes, style=RedactionStyle.BLACKOUT)
    # Area inside box should be solid black (0, 0, 0)
    assert np.all(redacted_black[60:90, 60:180] == 0)

    # Test Pixelate
    redacted_pixel = redact_image(img, boxes, style=RedactionStyle.PIXELATE)
    assert redacted_pixel.shape == img.shape

    # Test Blur
    redacted_blur = redact_image(img, boxes, style=RedactionStyle.BLUR)
    assert redacted_blur.shape == img.shape

    # Test Badge Label
    redacted_badge = redact_image(img, boxes, style=RedactionStyle.MASK_LABEL)
    assert redacted_badge.shape == img.shape


def test_redact_pdf_document():
    pdf_bytes = generate_tax_assessment_notice_pdf()
    ent = DetectedPII(
        id="test_pan",
        category=PIICategory.PAN,
        text="ABCPV1234F",
        masked_text="ABXXXXX4F",
        confidence=0.98,
        bbox=BoundingBox(x0=65, y0=215, x1=200, y1=235, page_number=1),
        rule_triggered="PAN Regex",
        page_number=1,
    )

    sanitized_bytes, rendered_pages = redact_pdf_document(
        pdf_bytes,
        [ent],
        style=RedactionStyle.BLACKOUT,
        target_dpi=200
    )

    assert len(sanitized_bytes) > 0
    assert sanitized_bytes[:4] == b"%PDF"
    assert len(rendered_pages) == 1
    assert rendered_pages[0] is not None


def test_audit_certificate_generation():
    ent = DetectedPII(
        id="ent1",
        category=PIICategory.AADHAAR,
        text="2947 1827 3645",
        masked_text="XXXX XXXX 3645",
        confidence=0.98,
        bbox=BoundingBox(x0=10, y0=10, x1=100, y1=30, page_number=1),
        rule_triggered="Aadhaar",
        page_number=1,
    )

    cert = create_audit_certificate(
        document_id="DOC-12345",
        original_filename="sample.pdf",
        sha256_original="abc1234567890",
        sha256_sanitized="def9876543210",
        all_detected_entities=[ent],
        redacted_entities=[ent],
        style=RedactionStyle.BLACKOUT,
    )

    assert cert.document_id == "DOC-12345"
    assert cert.total_entities_detected == 1
    assert cert.total_entities_redacted == 1
    assert cert.status == "VERIFIED_COMPLIANT"

    # Test PDF rendering
    pdf_bytes = generate_pdf_certificate_bytes(cert, [ent])
    assert len(pdf_bytes) > 0
    assert pdf_bytes[:4] == b"%PDF"
