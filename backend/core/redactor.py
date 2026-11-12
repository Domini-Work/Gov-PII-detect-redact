"""
Visual Document Redaction Engine.
Supports Image & PDF redaction with Blackout, Pixelate, Blur, and Badge Masking styles.
"""

import io
import math
from typing import List, Dict, Any, Tuple, Optional
import numpy as np
import cv2
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import fitz  # PyMuPDF

from backend.models.schemas import (
    BoundingBox,
    DetectedPII,
    RedactionStyle,
    RedactionRequest,
)
from backend.core.preprocessing import compute_sha256, numpy_to_pil, pil_to_bytes, load_image_from_bytes


def apply_pixelation(image_bgr: np.ndarray, x0: int, y0: int, x1: int, y1: int, blocks: int = 10) -> np.ndarray:
    """Applies mosaic pixelation effect over the rectangular region."""
    h, w = image_bgr.shape[:2]
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(w, x1), min(h, y1)
    
    if x1 <= x0 or y1 <= y0:
        return image_bgr
    
    roi = image_bgr[y0:y1, x0:x1]
    roi_h, roi_w = roi.shape[:2]
    
    # Resize down then resize up with nearest neighbor
    small_w = max(1, roi_w // blocks)
    small_h = max(1, roi_h // blocks)
    
    small = cv2.resize(roi, (small_w, small_h), interpolation=cv2.INTER_LINEAR)
    pixelated = cv2.resize(small, (roi_w, roi_h), interpolation=cv2.INTER_NEAREST)
    image_bgr[y0:y1, x0:x1] = pixelated
    return image_bgr


def apply_blur(image_bgr: np.ndarray, x0: int, y0: int, x1: int, y1: int, ksize: int = 25) -> np.ndarray:
    """Applies heavy Gaussian blur over the rectangular region."""
    h, w = image_bgr.shape[:2]
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(w, x1), min(h, y1)
    
    if x1 <= x0 or y1 <= y0:
        return image_bgr
    
    if ksize % 2 == 0:
        ksize += 1
    
    roi = image_bgr[y0:y1, x0:x1]
    blurred = cv2.GaussianBlur(roi, (ksize, ksize), 0)
    image_bgr[y0:y1, x0:x1] = blurred
    return image_bgr


def redact_image(
    image_bgr: np.ndarray,
    boxes: List[Tuple[BoundingBox, Optional[str]]],
    style: RedactionStyle = RedactionStyle.BLACKOUT,
    blur_radius: int = 21
) -> np.ndarray:
    """
    Redacts specified bounding boxes on an OpenCV BGR image.
    boxes is a list of (BoundingBox, label_text).
    """
    output_img = image_bgr.copy()
    h, w = output_img.shape[:2]

    for bbox, label in boxes:
        x0 = int(round(max(0, bbox.x0)))
        y0 = int(round(max(0, bbox.y0)))
        x1 = int(round(min(w, bbox.x1)))
        y1 = int(round(min(h, bbox.y1)))

        if x1 <= x0 or y1 <= y0:
            continue

        if style == RedactionStyle.BLACKOUT:
            # Solid black rectangle
            cv2.rectangle(output_img, (x0, y0), (x1, y1), (0, 0, 0), -1)
            
        elif style == RedactionStyle.PIXELATE:
            output_img = apply_pixelation(output_img, x0, y0, x1, y1, blocks=8)
            # Outline border
            cv2.rectangle(output_img, (x0, y0), (x1, y1), (40, 40, 40), 1)

        elif style == RedactionStyle.BLUR:
            output_img = apply_blur(output_img, x0, y0, x1, y1, ksize=blur_radius)
            cv2.rectangle(output_img, (x0, y0), (x1, y1), (80, 80, 80), 1)

        elif style == RedactionStyle.MASK_LABEL:
            # Black background box
            cv2.rectangle(output_img, (x0, y0), (x1, y1), (15, 15, 15), -1)
            cv2.rectangle(output_img, (x0, y0), (x1, y1), (220, 50, 50), 1)  # Security red border
            
            # Badge text
            badge_text = label if label else "REDACTED"
            font_scale = max(0.3, min(0.6, (y1 - y0) / 35.0))
            thickness = 1
            text_size = cv2.getTextSize(badge_text, cv2.FONT_HERSHEY_SIMPLEX, font_scale, thickness)[0]
            
            text_x = x0 + max(2, (x1 - x0 - text_size[0]) // 2)
            text_y = y0 + max(text_size[1] + 2, (y1 - y0 + text_size[1]) // 2)
            
            if text_x < x1 and text_y < y1:
                cv2.putText(
                    output_img,
                    badge_text,
                    (text_x, text_y),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    font_scale,
                    (255, 255, 255),
                    thickness,
                    cv2.LINE_AA
                )

    return output_img


def redact_pdf_document(
    pdf_bytes: bytes,
    entities_to_redact: List[DetectedPII],
    style: RedactionStyle = RedactionStyle.BLACKOUT,
    target_dpi: int = 200
) -> Tuple[bytes, List[np.ndarray]]:
    """
    Redacts sensitive content from PDF files.
    Applies native PyMuPDF vector redactions to permanently scrub text streams and metadata.
    Also produces rendered sanitized page images for UI visualization.
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    scale_from_pixels = 72.0 / target_dpi
    rendered_sanitized_pages: List[np.ndarray] = []

    # Group entities by page
    page_entity_map: Dict[int, List[DetectedPII]] = {}
    for ent in entities_to_redact:
        page_num = ent.page_number
        if page_num not in page_entity_map:
            page_entity_map[page_num] = []
        page_entity_map[page_num].append(ent)

    for page_idx in range(len(doc)):
        page = doc[page_idx]
        page_num = page_idx + 1
        page_entities = page_entity_map.get(page_num, [])

        for ent in page_entities:
            # Convert pixel coords to PDF point coords
            rx0 = ent.bbox.x0 * scale_from_pixels
            ry0 = ent.bbox.y0 * scale_from_pixels
            rx1 = ent.bbox.x1 * scale_from_pixels
            ry1 = ent.bbox.y1 * scale_from_pixels
            
            rect = fitz.Rect(rx0, ry0, rx1, ry1)
            
            # Add redaction annotation (solid black)
            page.add_redact_annot(
                rect,
                text=f" [{ent.category.value}] " if style == RedactionStyle.MASK_LABEL else "",
                fill=(0, 0, 0),
                text_color=(1, 1, 1),
            )

        # Apply vector redactions to scrub text and rasterize covered area
        page.apply_redactions()

        # Render sanitized page for preview
        zoom = target_dpi / 72.0
        mat = fitz.Matrix(zoom, zoom)
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img_np = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
        if pix.n == 3:
            img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
        else:
            img_bgr = cv2.cvtColor(img_np, cv2.COLOR_GRAY2BGR)
        
        rendered_sanitized_pages.append(img_bgr)

    # Save sanitized PDF bytes
    sanitized_pdf_bytes = doc.tobytes(garbage=4, deflate=True)
    doc.close()

    return sanitized_pdf_bytes, rendered_sanitized_pages
