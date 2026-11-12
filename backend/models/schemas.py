"""
Pydantic Schemas and Data Models for PS13 Government Document PII Detector.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class PIICategory(str, Enum):
    AADHAAR = "AADHAAR"
    PAN = "PAN"
    VOTER_ID = "VOTER_ID"
    PASSPORT = "PASSPORT"
    DRIVING_LICENSE = "DRIVING_LICENSE"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    UPI = "UPI"
    GSTIN = "GSTIN"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    IFSC = "IFSC"
    PERSON_NAME = "PERSON_NAME"
    ADDRESS = "ADDRESS"
    CUSTOM = "CUSTOM"


class RedactionStyle(str, Enum):
    BLACKOUT = "BLACKOUT"      # Solid black rectangle
    PIXELATE = "PIXELATE"      # Pixelated mosaic
    BLUR = "BLUR"              # Gaussian blur
    MASK_LABEL = "MASK_LABEL"  # Black box with white badge text e.g. [REDACTED AADHAAR]


class BoundingBox(BaseModel):
    x0: float = Field(..., description="Left X coordinate")
    y0: float = Field(..., description="Top Y coordinate")
    x1: float = Field(..., description="Right X coordinate")
    y1: float = Field(..., description="Bottom Y coordinate")
    page_number: int = Field(default=1, description="1-indexed page number")
    width: Optional[float] = Field(default=None, description="Box width")
    height: Optional[float] = Field(default=None, description="Box height")

    def model_post_init(self, __context: Any) -> None:
        if self.width is None:
            self.width = max(0.0, self.x1 - self.x0)
        if self.height is None:
            self.height = max(0.0, self.y1 - self.y0)


class DetectedPII(BaseModel):
    id: str = Field(..., description="Unique entity UUID or key")
    category: PIICategory = Field(..., description="Category of the detected PII")
    text: str = Field(..., description="Raw detected text string")
    masked_text: str = Field(..., description="Masked/anonymized representation")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    bbox: BoundingBox = Field(..., description="Geometric bounding box for redaction")
    rule_triggered: str = Field(default="", description="Name of regex/NER rule triggered")
    page_number: int = Field(default=1, description="Page number where entity was found")
    selected_for_redaction: bool = Field(default=True, description="HITL toggle state")
    validation_status: str = Field(default="VALID", description="Checksum/rule verification status")


class PageDimension(BaseModel):
    page_number: int
    width: float
    height: float


class DocumentAnalysisResult(BaseModel):
    document_id: str
    filename: str
    file_type: str
    file_size_bytes: int
    total_pages: int
    page_dimensions: List[PageDimension]
    detected_entities: List[DetectedPII]
    full_text: str
    execution_time_ms: float
    sha256_original: str
    tesseract_available: bool = True


class RedactionRequest(BaseModel):
    document_id: str
    selected_entity_ids: Optional[List[str]] = Field(default=None, description="Entity IDs to redact")
    custom_boxes: Optional[List[BoundingBox]] = Field(default=None, description="Manual HITL bounding boxes")
    redaction_style: RedactionStyle = Field(default=RedactionStyle.BLACKOUT)
    blur_radius: int = Field(default=15, ge=3, le=50)
    export_format: str = Field(default="SAME_AS_INPUT", description="PDF, PNG, JPEG, or SAME_AS_INPUT")


class AuditCertificate(BaseModel):
    certificate_id: str
    document_id: str
    original_filename: str
    timestamp_iso: str
    sha256_original: str
    sha256_sanitized: str
    total_entities_detected: int
    total_entities_redacted: int
    redacted_categories: Dict[str, int]
    human_in_loop_overrides: int
    redaction_style_applied: str
    compliance_standard: str = "Digital Personal Data Protection (DPDP) Act 2023 & Aadhaar Act 2016"
    status: str = "VERIFIED_COMPLIANT"


class RedactionResult(BaseModel):
    document_id: str
    sanitized_filename: str
    sanitized_file_base64: Optional[str] = None
    audit_certificate: AuditCertificate
    execution_time_ms: float
    redacted_pages_count: int


class CustomRegexRule(BaseModel):
    name: str
    category: str
    pattern: str
    description: str
    example: Optional[str] = None
    enabled: bool = True
