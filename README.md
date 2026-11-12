# 🛡️ PS13: National Government Document PII Detector & Redaction Portal

[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141-green.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.63-red.svg)](https://streamlit.io/)
[![Compliance](https://img.shields.io/badge/Compliance-DPDP%20Act%202023-orange.svg)](https://www.meity.gov.in/)
[![Tests](https://img.shields.io/badge/Tests-18%20Passed%20(100%25)-brightgreen.svg)](file:///tests)

An enterprise-grade, high-precision Government Document Personally Identifiable Information (PII) Detection, Redaction, and Compliance Audit System specifically engineered for the **Indian Government domain**. 

The system complies with the **Digital Personal Data Protection (DPDP) Act, 2023** and the **Aadhaar Act, 2016**, featuring cryptographic SHA-256 tamper verification, a Human-in-the-Loop (HITL) review matrix, vector PDF text scrubbing, and interactive side-by-side comparative inspection.

---

## System Architecture


A[Citizen / Admin Uploads Document] -->|PDF, PNG, JPG, TIFF| B[Ingestion & Preprocessing Module]
B -->|OpenCV Deskew, CLAHE, Bilateral Denoise| C[OCR & Geometry Engine]
C -->|PyMuPDF Vector Layout / Tesseract OCR| D[Word Tokens & Bounding Boxes]
D --> E[Hybrid PII Detection Brain]

subgraph E [Hybrid PII Detection Engine]
    E1[Indian Regex Suite: PAN, Voter ID, DL, Passport, Phone, UPI, GSTIN]
    E2[Aadhaar Checksum Engine: Verhoeff Algorithm D5/P8 Matrices]
    E3[Contextual NER: Names, Addresses, Bank Accounts, IFSC]
    E4[Government Whitelist Filter: Rejects Statutory Titles & Org Names]
end

E --> F[Human-in-the-Loop HITL Matrix]
F -->|Review & Toggle Checkboxes| G[Visual Redaction Engine]

subgraph G [Redaction Modes]
    G1[Solid Blackout]
    G2[Mosaic Pixelation]
    G3[Gaussian Blur]
    G4[Security Badge Label]
end

G --> H[Sanitized Document Export]
G --> I[ReportLab Cryptographic Audit Certificate PDF]
G --> J[JSON Compliance Audit Log]

---

## 🇮🇳 Indian Context PII Capabilities Matrix

| PII Entity Category | Detection Methodology | Validation & Format | Anonymized Output |
| :--- | :--- | :--- | :--- |
| **Aadhaar Number** | Rule-Based Regex + Verhoeff Algorithm | `\b[2-9]{1}\d{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b` (Checksum Verified) | `XXXX XXXX 3645` |
| **PAN Card** | 10-Digit Alphanumeric Regex | `\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b` (4th Char Status Check) | `ABXXXXX4F` |
| **Voter ID (EPIC)** | Election Commission Regex | `\b[A-Z]{3}[0-9]{7}\b` & State Assembly Formats | `WBGXXXX567` |
| **Passport Number** | Ministry of External Affairs Regex | `\b[A-PR-WYa-pr-wy][1-9][0-9]\s?[0-9]{4}[1-9]\b` | `KXXXXXX8` |
| **Driving License** | MoRTH State Format Regex | `\b[A-Z]{2}[-\s]?[0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{7}\b` | `KA01XXXXXXXX65` |
| **Mobile / Phone** | Indian Telecom Prefix Regex | `\b(?:\+91[\-\s]?\|91[\-\s]?\|0)?[6789]\d{9}\b` | `+91 XXXXX-3210` |
| **UPI ID** | VPA Banking Regex | `[a-zA-Z0-9.\-_]+@(okaxis\|okhdfcbank\|oksbi\|paytm\|ybl\|apl\|upi)` | `am***@oksbi` |
| **GSTIN** | 15-Digit GST Regex | `\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b` | `29XXXXXXXXXX1Z5` |
| **Bank IFSC** | RBI Standard Regex | `\b[A-Z]{4}0[A-Z0-9]{6}\b` (5th Char Zero) | `SBIN0XXXXXX` |
| **Bank Account No** | Contextual Keywords + Numeric Sequence | Keyword Context (`A/C No`, `Account Number`) + 9-18 digits | `XXXXXX89012` |
| **Citizen Names** | Contextual Honorific NER | Prefixes (`Shri`, `Smt`, `Kumari`, `Dr`, `Mr`, `Name:`, `S/O`) | `R*** S***` |
| **Address Lines** | Geographic & Keyword NER | Keywords (`H.No`, `Street`, `Colony`, `Nagar`, `PIN:`) | `[REDACTED ADDRESS]` |
| **Official Whitelist** | False-Positive Exclusion Filter | Excludes "Government of India", "Tahsildar", "UIDAI", "Collector", etc. | *Preserved as Public Info* |

---

## Quick Start & Installation

### 1. Prerequisites
- **Python 3.11+** installed
- Optional: **Tesseract OCR** (System includes native PyMuPDF vector fallback if Tesseract binary is absent)

### 2. Local Setup
```bash
# Clone or navigate to the repository
cd TechUtsav_GovPII

# Install all dependencies
pip install -r requirements.txt
```

### 3. Running the Backend API
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
- API Swagger Documentation: **http://localhost:8000/docs**
- Health Check: **http://localhost:8000/api/health**

### 4. Running the Interactive Streamlit UI
```bash
python -m streamlit run frontend/app.py --server.port 8501
```
- Web Application Dashboard: **http://localhost:8501**

---

## Docker Deployment

To spin up the entire application inside a production container:
```bash
# Build and start via Docker Compose
docker-compose up --build
```
- Access Frontend UI at `http://localhost:8501`
- Access Backend API at `http://localhost:8000`

---

## Automated Testing

Run the complete 18-test suite covering regex engines, Verhoeff checksums, coordinate mappings, PDF redaction, and API endpoints:
```bash
python -m pytest -v --tb=short tests/
```

Test coverage includes:
- `test_pii_engine.py`: Aadhaar Verhoeff checksum validation, PAN, Voter ID, DL, UPI, Whitelist rejection, and Custom Rules.
- `test_preprocessing.py`: SHA-256 cryptographic hashing, OpenCV deskewing, and CLAHE enhancement.
- `test_ocr_and_redaction.py`: Blackout, Pixelate, Blur, Mask Badge, Vector PDF redactions, and ReportLab PDF certificate generation.
- `test_api.py`: FastAPI endpoints (`/api/health`, `/api/samples`, `/api/analyze`, `/api/redact`, and download streams).

---

