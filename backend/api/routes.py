"""
FastAPI REST API Routes for Document Analysis, PII Detection, Redaction, and Compliance Audit.
"""

import io
import os
import time
import uuid
import base64
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, File, UploadFile, Form, HTTPException, Response
from fastapi.responses import JSONResponse, StreamingResponse

from backend.models.schemas import (
    PIICategory,
    RedactionStyle,
    BoundingBox,
    DetectedPII,
    DocumentAnalysisResult,
    RedactionRequest,
    RedactionResult,
    AuditCertificate,
    CustomRegexRule,
    PageDimension,
)
from backend.core.preprocessing import (
    compute_sha256,
    extract_pages_from_document,
    load_image_from_bytes,
    numpy_to_pil,
    pil_to_bytes,
)
from backend.core.ocr_engine import (
    extract_document_tokens,
    TESSERACT_AVAILABLE,
)
from backend.core.pii_engine import (
    HybridPIIEngine,
    INDIAN_PII_PATTERNS,
)
from backend.core.redactor import (
    redact_image,
    redact_pdf_document,
)
from backend.core.audit import (
    create_audit_certificate,
    generate_pdf_certificate_bytes,
)
from backend.assets.generator import (
    generate_aadhaar_card_image,
    generate_pan_card_image,
    generate_driving_license_image,
    generate_tax_assessment_notice_pdf,
)

router = APIRouter(prefix="/api", tags=["PII Detector & Redactor"])

# Global In-Memory Document Store
DOCUMENT_CACHE: Dict[str, Dict[str, Any]] = {}
GLOBAL_PII_ENGINE = HybridPIIEngine()


@router.get("/health")
def health_check():
    """Returns system health, OCR engine availability, and active rules count."""
    return {
        "status": "HEALTHY",
        "service": "PS13 Government Document PII Detector & Redactor",
        "tesseract_ocr_available": TESSERACT_AVAILABLE,
        "active_regex_rules": len(INDIAN_PII_PATTERNS) + len(GLOBAL_PII_ENGINE.custom_rules),
        "cached_documents_count": len(DOCUMENT_CACHE),
    }


@router.get("/samples")
def list_sample_documents():
    """Lists available synthetic government documents for instant 1-click testing."""
    return {
        "samples": [
            {
                "id": "sample_aadhaar",
                "name": "Sample_Aadhaar_Card.png",
                "description": "Indian Aadhaar Card containing 12-digit Aadhaar (Verhoeff checksum), Citizen Name, Address, Phone, Email",
                "format": "image/png"
            },
            {
                "id": "sample_pan",
                "name": "Sample_PAN_Card.png",
                "description": "Income Tax PAN Card with alphanumeric PAN Number, Father's Name, DOB, Photo badge",
                "format": "image/png"
            },
            {
                "id": "sample_dl",
                "name": "Sample_Driving_License.png",
                "description": "Union of India Driving License with DL Number, Blood Group, Address, DOB",
                "format": "image/png"
            },
            {
                "id": "sample_tax_notice",
                "name": "Sample_Income_Tax_Notice.pdf",
                "description": "Official Ministry of Finance Assessment Notice with PAN, Bank Account, IFSC, UPI ID, Phone, and Official Whitelist Signatures",
                "format": "application/pdf"
            },
        ]
    }


@router.get("/samples/{sample_id}")
def get_sample_document(sample_id: str):
    """Retrieves bytes of a specific synthetic sample document."""
    if sample_id == "sample_aadhaar":
        data = generate_aadhaar_card_image()
        return Response(content=data, media_type="image/png")
    elif sample_id == "sample_pan":
        data = generate_pan_card_image()
        return Response(content=data, media_type="image/png")
    elif sample_id == "sample_dl":
        data = generate_driving_license_image()
        return Response(content=data, media_type="image/png")
    elif sample_id == "sample_tax_notice":
        data = generate_tax_assessment_notice_pdf()
        return Response(content=data, media_type="application/pdf")
    else:
        raise HTTPException(status_code=404, detail="Sample not found")


@router.post("/analyze", response_model=DocumentAnalysisResult)
async def analyze_document(
    file: UploadFile = File(...),
):
    """
    Ingests PDF or image document, performs OCR coordinate extraction,
    executes hybrid Indian PII detection, and returns structured analysis.
    """
    start_time = time.time()
    file_bytes = await file.read()
    filename = file.filename or "uploaded_document"
    file_size = len(file_bytes)

    if file_size > 15 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File exceeds maximum size limit of 15MB.")

    sha256_orig = compute_sha256(file_bytes)
    doc_id = str(uuid.uuid4())[:12]

    # Extract pages and dimensions
    try:
        pages_info = extract_pages_from_document(file_bytes, filename, target_dpi=200)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to process document: {str(e)}")

    if not pages_info:
        raise HTTPException(status_code=422, detail="No readable pages found in document.")

    # OCR / Vector Token Extraction
    tokens = extract_document_tokens(file_bytes, filename, pages_info, target_dpi=200)

    # Build full document text stream
    full_text = " ".join([t.text for t in tokens])

    # Hybrid PII Detection
    detected_entities = GLOBAL_PII_ENGINE.detect_pii(full_text, tokens)

    # Build Page Dimensions
    page_dims = [
        PageDimension(page_number=idx + 1, width=dims[0], height=dims[1])
        for idx, (_, dims) in enumerate(pages_info)
    ]

    exec_time = (time.time() - start_time) * 1000.0

    # Cache state for redaction
    DOCUMENT_CACHE[doc_id] = {
        "file_bytes": file_bytes,
        "filename": filename,
        "pages_info": pages_info,
        "tokens": tokens,
        "detected_entities": detected_entities,
        "sha256_original": sha256_orig,
        "page_dimensions": page_dims,
    }

    return DocumentAnalysisResult(
        document_id=doc_id,
        filename=filename,
        file_type="PDF" if filename.lower().endswith(".pdf") else "IMAGE",
        file_size_bytes=file_size,
        total_pages=len(pages_info),
        page_dimensions=page_dims,
        detected_entities=detected_entities,
        full_text=full_text,
        execution_time_ms=round(exec_time, 2),
        sha256_original=sha256_orig,
        tesseract_available=TESSERACT_AVAILABLE,
    )


@router.post("/redact", response_model=RedactionResult)
def redact_document(req: RedactionRequest):
    """
    Applies redactions based on HITL selections, generates sanitized document,
    and produces cryptographic compliance audit certificate.
    """
    start_time = time.time()
    doc_id = req.document_id
    if doc_id not in DOCUMENT_CACHE:
        raise HTTPException(status_code=404, detail="Document ID not found in session cache.")

    cached = DOCUMENT_CACHE[doc_id]
    file_bytes = cached["file_bytes"]
    filename = cached["filename"]
    pages_info = cached["pages_info"]
    all_entities: List[DetectedPII] = cached["detected_entities"]
    sha256_orig = cached["sha256_original"]

    # Filter entities selected for redaction (Human-in-the-Loop selection)
    if req.selected_entity_ids is not None:
        selected_set = set(req.selected_entity_ids)
        entities_to_redact = [e for e in all_entities if e.id in selected_set]
    else:
        entities_to_redact = [e for e in all_entities if e.selected_for_redaction]

    # Add custom manual boxes if provided
    if req.custom_boxes:
        for cb in req.custom_boxes:
            custom_ent = DetectedPII(
                id=str(uuid.uuid4())[:8],
                category=PIICategory.CUSTOM,
                text="[MANUAL_SELECTION]",
                masked_text="[MANUAL_REDACTED]",
                confidence=1.0,
                bbox=cb,
                rule_triggered="HITL Manual Bounding Box",
                page_number=cb.page_number,
                selected_for_redaction=True,
            )
            entities_to_redact.append(custom_ent)

    is_pdf = filename.lower().endswith(".pdf") or file_bytes[:4] == b"%PDF"
    sanitized_bytes: bytes = b""
    rendered_sanitized_images: List[np.ndarray] = []

    if is_pdf:
        sanitized_bytes, rendered_sanitized_images = redact_pdf_document(
            file_bytes,
            entities_to_redact,
            style=req.redaction_style,
            target_dpi=200
        )
        sanitized_filename = f"Sanitized_{filename}"
    else:
        # Single or multi-page raster image
        page_img, _ = pages_info[0]
        boxes_with_labels = [
            (e.bbox, f"REDACTED {e.category.value}") for e in entities_to_redact
        ]
        redacted_bgr = redact_image(
            page_img,
            boxes_with_labels,
            style=req.redaction_style,
            blur_radius=req.blur_radius
        )
        rendered_sanitized_images = [redacted_bgr]
        pil_redacted = numpy_to_pil(redacted_bgr)
        sanitized_bytes = pil_to_bytes(pil_redacted, format="PNG")
        sanitized_filename = f"Sanitized_{os.path.splitext(filename)[0]}.png"

    sha256_sanitized = compute_sha256(sanitized_bytes)

    # Generate Audit Certificate
    audit_cert = create_audit_certificate(
        document_id=doc_id,
        original_filename=filename,
        sha256_original=sha256_orig,
        sha256_sanitized=sha256_sanitized,
        all_detected_entities=all_entities,
        redacted_entities=entities_to_redact,
        style=req.redaction_style,
    )

    pdf_cert_bytes = generate_pdf_certificate_bytes(audit_cert, entities_to_redact)

    # Save to cached result
    cached["sanitized_bytes"] = sanitized_bytes
    cached["sanitized_filename"] = sanitized_filename
    cached["sanitized_images"] = rendered_sanitized_images
    cached["audit_cert"] = audit_cert
    cached["pdf_cert_bytes"] = pdf_cert_bytes

    exec_time = (time.time() - start_time) * 1000.0

    return RedactionResult(
        document_id=doc_id,
        sanitized_filename=sanitized_filename,
        sanitized_file_base64=base64.b64encode(sanitized_bytes).decode("utf-8"),
        audit_certificate=audit_cert,
        execution_time_ms=round(exec_time, 2),
        redacted_pages_count=len(pages_info),
    )


@router.get("/download/{document_id}/sanitized")
def download_sanitized_document(document_id: str):
    """Downloads the sanitized redacted PDF or Image file."""
    if document_id not in DOCUMENT_CACHE or "sanitized_bytes" not in DOCUMENT_CACHE[document_id]:
        raise HTTPException(status_code=404, detail="Sanitized document not available.")

    cached = DOCUMENT_CACHE[document_id]
    data = cached["sanitized_bytes"]
    filename = cached["sanitized_filename"]
    media_type = "application/pdf" if filename.lower().endswith(".pdf") else "image/png"

    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/download/{document_id}/certificate")
def download_audit_certificate_pdf(document_id: str):
    """Downloads the official PDF Compliance Certificate."""
    if document_id not in DOCUMENT_CACHE or "pdf_cert_bytes" not in DOCUMENT_CACHE[document_id]:
        raise HTTPException(status_code=404, detail="Audit Certificate not available.")

    cached = DOCUMENT_CACHE[document_id]
    data = cached["pdf_cert_bytes"]
    filename = f"Compliance_Certificate_{document_id}.pdf"

    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/download/{document_id}/audit-json")
def download_audit_json(document_id: str):
    """Downloads the structured JSON audit report."""
    if document_id not in DOCUMENT_CACHE or "audit_cert" not in DOCUMENT_CACHE[document_id]:
        raise HTTPException(status_code=404, detail="Audit data not available.")

    cert: AuditCertificate = DOCUMENT_CACHE[document_id]["audit_cert"]
    return JSONResponse(
        content=cert.model_dump(),
        headers={"Content-Disposition": f'attachment; filename="Audit_Report_{document_id}.json"'}
    )


@router.post("/rules/custom")
def add_custom_rule(rule: CustomRegexRule):
    """Registers a dynamic custom regex rule at runtime without code changes."""
    GLOBAL_PII_ENGINE.add_custom_rule(rule)
    return {"message": f"Rule '{rule.name}' added successfully", "total_custom_rules": len(GLOBAL_PII_ENGINE.custom_rules)}


@router.get("/rules")
def get_all_rules():
    """Lists all standard Indian context rules + custom rules."""
    rules = [
        {"name": r["name"], "category": r["category"].value, "pattern": r["pattern"], "type": "STANDARD_INDIAN_RULE"}
        for r in INDIAN_PII_PATTERNS
    ]
    for cr in GLOBAL_PII_ENGINE.custom_rules:
        rules.append({
            "name": cr.name,
            "category": cr.category,
            "pattern": cr.pattern,
            "type": "CUSTOM_USER_RULE"
        })
    return {"rules": rules}
