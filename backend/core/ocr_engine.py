"""
OCR & Coordinate Extraction Engine.
Extracts text with word-level and block-level bounding box coordinates from PDFs and raster images.
"""

import os
import shutil
import string
from typing import List, Dict, Any, Tuple, Optional
import numpy as np
import cv2
from PIL import Image
import pytesseract
from pytesseract import Output
import fitz  # PyMuPDF

from backend.models.schemas import BoundingBox


# Possible default installation locations for Tesseract on Windows/Linux
TESSERACT_PATHS = [
    "tesseract",
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    r"C:\Users\DOMINEER\AppData\Local\Programs\Tesseract-OCR\tesseract.exe",
]


def check_and_configure_tesseract() -> bool:
    """Configures pytesseract command path if found on system."""
    for p in TESSERACT_PATHS:
        if shutil.which(p) or os.path.exists(p):
            pytesseract.pytesseract.tesseract_cmd = p
            return True
    return False


TESSERACT_AVAILABLE = check_and_configure_tesseract()


class OCRWordToken:
    """Represents a single detected word token with geometry."""
    def __init__(
        self,
        text: str,
        x0: float,
        y0: float,
        x1: float,
        y1: float,
        confidence: float,
        page_number: int,
        block_num: int = 0,
        line_num: int = 0,
    ):
        self.text = text
        self.x0 = float(x0)
        self.y0 = float(y0)
        self.x1 = float(x1)
        self.y1 = float(y1)
        self.confidence = float(confidence)
        self.page_number = int(page_number)
        self.block_num = int(block_num)
        self.line_num = int(line_num)

    def to_bbox(self) -> BoundingBox:
        return BoundingBox(
            x0=self.x0,
            y0=self.y0,
            x1=self.x1,
            y1=self.y1,
            page_number=self.page_number,
            confidence=self.confidence,
        )

    def __repr__(self) -> str:
        return f"<Token '{self.text}' [{self.x0:.1f}, {self.y0:.1f}, {self.x1:.1f}, {self.y1:.1f}] conf={self.confidence:.2f}>"


def extract_tokens_from_pdf_native(
    pdf_bytes: bytes,
    target_dpi: int = 200
) -> List[OCRWordToken]:
    """
    Extracts word tokens with bounding boxes directly from vector PDF structure using PyMuPDF.
    Scales coordinates from 72 DPI points to target pixel resolution.
    """
    scale = target_dpi / 72.0
    tokens: List[OCRWordToken] = []
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")

    for page_idx in range(len(doc)):
        page = doc[page_idx]
        page_num = page_idx + 1
        words = page.get_text("words")  # (x0, y0, x1, y1, word, block_no, line_no, word_no)
        for w in words:
            word_text = str(w[4]).strip()
            if not word_text:
                continue
            x0 = float(w[0]) * scale
            y0 = float(w[1]) * scale
            x1 = float(w[2]) * scale
            y1 = float(w[3]) * scale
            block_no = int(w[5])
            line_no = int(w[6])
            tokens.append(
                OCRWordToken(
                    text=word_text,
                    x0=x0,
                    y0=y0,
                    x1=x1,
                    y1=y1,
                    confidence=0.99,
                    page_number=page_num,
                    block_num=block_no,
                    line_num=line_no,
                )
            )
    doc.close()
    return tokens


def extract_tokens_from_image_tesseract(
    image_bgr: np.ndarray,
    page_number: int = 1
) -> List[OCRWordToken]:
    """Extracts word tokens using Tesseract OCR with bounding boxes."""
    tokens: List[OCRWordToken] = []
    if not TESSERACT_AVAILABLE:
        return tokens

    try:
        rgb_img = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
        data = pytesseract.image_to_data(
            rgb_img,
            output_type=Output.DICT,
            config="--oem 3 --psm 6"
        )
        n_boxes = len(data["text"])
        for i in range(n_boxes):
            word_text = data["text"][i].strip()
            if not word_text:
                continue
            try:
                conf = float(data["conf"][i])
                if conf < 0:
                    conf = 60.0
                conf_norm = max(0.1, min(1.0, conf / 100.0))
            except Exception:
                conf_norm = 0.8

            x = float(data["left"][i])
            y = float(data["top"][i])
            w = float(data["width"][i])
            h = float(data["height"][i])
            block_no = int(data["block_num"][i])
            line_no = int(data["line_num"][i])

            tokens.append(
                OCRWordToken(
                    text=word_text,
                    x0=x,
                    y0=y,
                    x1=x + w,
                    y1=y + h,
                    confidence=conf_norm,
                    page_number=page_number,
                    block_num=block_no,
                    line_num=line_no,
                )
            )
    except Exception as e:
        print(f"[OCR Warning] Tesseract execution encountered: {e}")
    return tokens


def extract_document_tokens(
    file_bytes: bytes,
    filename: str,
    page_images: List[Tuple[np.ndarray, Tuple[float, float]]],
    target_dpi: int = 200
) -> List[OCRWordToken]:
    """
    Unified extraction pipeline:
    1. If PDF has native vector text streams, extracts with pixel-perfect geometry.
    2. If Tesseract is available, runs OCR on image scans.
    3. Returns full ordered list of word tokens.
    """
    is_pdf = filename.lower().endswith(".pdf") or file_bytes[:4] == b"%PDF"
    all_tokens: List[OCRWordToken] = []

    if is_pdf:
        native_tokens = extract_tokens_from_pdf_native(file_bytes, target_dpi=target_dpi)
        if len(native_tokens) > 5:
            return native_tokens

    # Raster image or scanned PDF requiring OCR
    for page_idx, (page_img, _) in enumerate(page_images):
        page_num = page_idx + 1
        page_tokens = extract_tokens_from_image_tesseract(page_img, page_number=page_num)
        all_tokens.extend(page_tokens)

    return all_tokens
