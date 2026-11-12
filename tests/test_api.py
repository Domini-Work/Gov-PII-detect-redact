import os
import sys
import io
import pytest

# Ensure repository root is on sys.path regardless of execution CWD
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fastapi.testclient import TestClient
from backend.main import app
from backend.assets.generator import generate_aadhaar_card_image, generate_tax_assessment_notice_pdf

client = TestClient(app)


def test_api_root_and_health():
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["status"] == "ONLINE"

    res_h = client.get("/api/health")
    assert res_h.status_code == 200
    assert res_h.json()["status"] == "HEALTHY"


def test_api_samples():
    res = client.get("/api/samples")
    assert res.status_code == 200
    samples = res.json()["samples"]
    assert len(samples) >= 4

    # Test downloading sample aadhaar
    res_sample = client.get("/api/samples/sample_aadhaar")
    assert res_sample.status_code == 200
    assert res_sample.headers["content-type"] == "image/png"


def test_api_analyze_and_redact_flow():
    # 1. Analyze PDF
    pdf_bytes = generate_tax_assessment_notice_pdf()
    files = {"file": ("Tax_Notice.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
    res_analyze = client.post("/api/analyze", files=files)
    assert res_analyze.status_code == 200
    data = res_analyze.json()
    doc_id = data["document_id"]
    assert len(data["detected_entities"]) > 0
    assert data["file_type"] == "PDF"

    # 2. Redact with selected entities
    redact_payload = {
        "document_id": doc_id,
        "selected_entity_ids": [e["id"] for e in data["detected_entities"]],
        "redaction_style": "BLACKOUT",
        "export_format": "SAME_AS_INPUT"
    }
    res_redact = client.post("/api/redact", json=redact_payload)
    assert res_redact.status_code == 200
    redact_data = res_redact.json()
    assert redact_data["document_id"] == doc_id
    assert redact_data["audit_certificate"]["status"] == "VERIFIED_COMPLIANT"

    # 3. Download Sanitized File
    res_down = client.get(f"/api/download/{doc_id}/sanitized")
    assert res_down.status_code == 200
    assert len(res_down.content) > 0

    # 4. Download PDF Certificate
    res_cert = client.get(f"/api/download/{doc_id}/certificate")
    assert res_cert.status_code == 200
    assert res_cert.content[:4] == b"%PDF"

    # 5. Download JSON Audit
    res_json = client.get(f"/api/download/{doc_id}/audit-json")
    assert res_json.status_code == 200
    assert res_json.json()["document_id"] == doc_id
