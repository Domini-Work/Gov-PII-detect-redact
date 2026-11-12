"""
Document Ingestion & Preprocessing Module.
Handles file ingestion, PDF page rendering, deskewing, noise reduction, and contrast enhancement.
"""

import io
import math
import hashlib
from typing import List, Tuple, Optional, Union
import numpy as np
import cv2
from PIL import Image
import fitz  # PyMuPDF


def compute_sha256(data: bytes) -> str:
    """Computes SHA-256 cryptographic hash of byte array."""
    return hashlib.sha256(data).hexdigest()


def load_image_from_bytes(data: bytes) -> np.ndarray:
    """Decodes image bytes into BGR OpenCV numpy array."""
    nparr = np.frombuffer(data, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        # Fallback to PIL decode
        pil_img = Image.open(io.BytesIO(data)).convert("RGB")
        img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
    return img


def numpy_to_pil(img_bgr: np.ndarray) -> Image.Image:
    """Converts BGR numpy image to PIL Image RGB."""
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    return Image.fromarray(img_rgb)


def pil_to_bytes(pil_img: Image.Image, format: str = "PNG") -> bytes:
    """Encodes PIL image to byte stream."""
    buffer = io.BytesIO()
    pil_img.save(buffer, format=format)
    return buffer.getvalue()


def deskew_image(image_bgr: np.ndarray) -> Tuple[np.ndarray, float]:
    """
    Detects skew angle in degrees and rotates the image to straighten text.
    Returns (deskewed_image_bgr, angle_corrected).
    """
    gray = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2GRAY)
    
    # Invert binary image so text pixels are white
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]
    
    # Find all coordinates of non-zero pixels
    coords = np.column_stack(np.where(thresh > 0))
    if len(coords) < 50:
        return image_bgr, 0.0
    
    # Compute minAreaRect
    angle = cv2.minAreaRect(coords)[-1]
    
    # OpenCV minAreaRect angle normalization
    if angle < -45:
        angle = -(90 + angle)
    elif angle > 45:
        angle = 90 - angle
    else:
        angle = -angle

    # Only deskew if skew is noticeable and realistic (between 0.5 and 45 degrees)
    if abs(angle) < 0.5 or abs(angle) > 45:
        return image_bgr, 0.0

    (h, w) = image_bgr.shape[:2]
    center = (w // 2, h // 2)
    m = cv2.getRotationMatrix2D(center, angle, 1.0)
    rotated = cv2.warpAffine(
        image_bgr, m, (w, h),
        flags=cv2.INTER_CUBIC,
        borderMode=cv2.BORDER_REPLICATE
    )
    return rotated, angle


def enhance_contrast_clahe(image_bgr: np.ndarray) -> np.ndarray:
    """
    Applies Contrast Limited Adaptive Histogram Equalization (CLAHE) on LAB color space.
    Enhances readability of faded government seals and stamps.
    """
    lab = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2LAB)
    l, a, b = cv2.split(lab)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    cl = clahe.apply(l)
    limg = cv2.merge((cl, a, b))
    return cv2.cvtColor(limg, cv2.COLOR_LAB2BGR)


def preprocess_for_ocr(image_bgr: np.ndarray, apply_deskew: bool = True) -> np.ndarray:
    """
    Full preprocessing pipeline for OCR:
    1. Deskew
    2. CLAHE contrast enhancement
    3. Bilateral filter denoising (preserves sharp text edges)
    """
    processed = image_bgr.copy()
    if apply_deskew:
        processed, _ = deskew_image(processed)
    
    enhanced = enhance_contrast_clahe(processed)
    denoised = cv2.bilateralFilter(enhanced, 7, 50, 50)
    return denoised


def extract_pages_from_document(
    file_bytes: bytes,
    filename: str,
    target_dpi: int = 200
) -> List[Tuple[np.ndarray, Tuple[float, float]]]:
    """
    Extracts all pages as (image_bgr, (page_width, page_height)).
    Supports PDF and standard image formats (PNG, JPG, TIFF, WEBP).
    """
    is_pdf = filename.lower().endswith(".pdf") or file_bytes[:4] == b"%PDF"
    pages: List[Tuple[np.ndarray, Tuple[float, float]]] = []

    if is_pdf:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        for page_idx in range(len(doc)):
            page = doc[page_idx]
            rect = page.rect  # PDF points (72 DPI)
            zoom = target_dpi / 72.0
            mat = fitz.Matrix(zoom, zoom)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            
            # Convert PyMuPDF pixmap to numpy BGR image
            img_np = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
            if pix.n == 3:
                img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
            elif pix.n == 1:
                img_bgr = cv2.cvtColor(img_np, cv2.COLOR_GRAY2BGR)
            else:
                img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGBA2BGR)
            
            # Record page image and dimensions (in target pixel coordinates)
            pages.append((img_bgr, (float(pix.width), float(pix.height))))
        doc.close()
    else:
        img_bgr = load_image_from_bytes(file_bytes)
        h, w = img_bgr.shape[:2]
        pages.append((img_bgr, (float(w), float(h))))

    return pages
