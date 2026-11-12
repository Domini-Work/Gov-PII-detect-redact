import os
import sys
import numpy as np
import cv2
import pytest

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend.core.preprocessing import (
    compute_sha256,
    deskew_image,
    enhance_contrast_clahe,
    extract_pages_from_document,
    load_image_from_bytes,
)
from backend.assets.generator import generate_aadhaar_card_image, generate_tax_assessment_notice_pdf


def test_compute_sha256():
    sample_data = b"Government Document PII Test Data"
    hash_str = compute_sha256(sample_data)
    assert len(hash_str) == 64
    assert isinstance(hash_str, str)
    # Idempotent
    assert compute_sha256(sample_data) == hash_str


def test_deskew_image_synthetic():
    # Create an image with tilted black horizontal lines
    img = np.ones((300, 300, 3), dtype=np.uint8) * 255
    # Draw tilted line
    cv2.line(img, (20, 80), (280, 120), (0, 0, 0), 4)
    cv2.line(img, (20, 140), (280, 180), (0, 0, 0), 4)

    deskewed, angle = deskew_image(img)
    assert deskewed.shape == img.shape
    assert isinstance(angle, float)


def test_enhance_contrast_clahe():
    img = np.ones((100, 100, 3), dtype=np.uint8) * 128
    enhanced = enhance_contrast_clahe(img)
    assert enhanced.shape == img.shape


def test_extract_pages_from_image():
    aadhaar_bytes = generate_aadhaar_card_image()
    pages = extract_pages_from_document(aadhaar_bytes, "Sample_Aadhaar.png")
    assert len(pages) == 1
    img_bgr, dims = pages[0]
    assert dims[0] == 900.0
    assert dims[1] == 560.0
    assert img_bgr.shape[0] == 560
    assert img_bgr.shape[1] == 900


def test_extract_pages_from_pdf():
    pdf_bytes = generate_tax_assessment_notice_pdf()
    pages = extract_pages_from_document(pdf_bytes, "Sample_Notice.pdf", target_dpi=200)
    assert len(pages) == 1
    img_bgr, dims = pages[0]
    assert dims[0] > 0
    assert dims[1] > 0
    assert img_bgr is not None
