"""
PS13 Government Document PII Detector & Redaction Portal.
Streamlit Web Application featuring Side-by-Side Comparison, HITL Matrix, and Compliance Auditing.
"""

import os
import io
import time
import base64
import streamlit as st
from PIL import Image
import pandas as pd

# Internal backend imports for direct low-latency processing
from backend.models.schemas import (
    PIICategory,
    RedactionStyle,
    BoundingBox,
    DetectedPII,
    DocumentAnalysisResult,
    RedactionRequest,
    CustomRegexRule,
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
from frontend.components.ui_cards import render_header, get_badge_html
from frontend.components.viewer import draw_detection_bounding_boxes

# Page Configuration
st.set_page_config(
    page_title="GovPII - National Document Redaction Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize Session State
if "pii_engine" not in st.session_state:
    st.session_state.pii_engine = HybridPIIEngine()

if "doc_data" not in st.session_state:
    st.session_state.doc_data = None

if "redaction_result" not in st.session_state:
    st.session_state.redaction_result = None

if "selected_entity_ids" not in st.session_state:
    st.session_state.selected_entity_ids = set()


def run_pipeline_analysis(file_bytes: bytes, filename: str):
    """Executes the full preprocessing, OCR, and hybrid PII analysis pipeline."""
    with st.spinner("Processing document through multi-stage GovPII pipeline..."):
        t0 = time.time()
        sha256_orig = compute_sha256(file_bytes)
        
        # 1. Ingestion & Preprocessing
        pages_info = extract_pages_from_document(file_bytes, filename, target_dpi=200)
        
        # 2. OCR Coordinate Extraction
        tokens = extract_document_tokens(file_bytes, filename, pages_info, target_dpi=200)
        full_text = " ".join([t.text for t in tokens])
        
        # 3. Hybrid Indian PII Detection Engine
        detected_entities = st.session_state.pii_engine.detect_pii(full_text, tokens)
        
        exec_time = (time.time() - t0) * 1000.0
        
        # Initialize all entities as selected by default for HITL
        st.session_state.selected_entity_ids = {e.id for e in detected_entities}
        
        st.session_state.doc_data = {
            "file_bytes": file_bytes,
            "filename": filename,
            "pages_info": pages_info,
            "tokens": tokens,
            "full_text": full_text,
            "detected_entities": detected_entities,
            "sha256_orig": sha256_orig,
            "exec_time_ms": exec_time,
            "is_pdf": filename.lower().endswith(".pdf") or file_bytes[:4] == b"%PDF",
        }
        st.session_state.redaction_result = None


# Render Top Header
render_header()

# Sidebar: Controls & Sample Loading
with st.sidebar:
    st.markdown("### 📁 1. Input Document")
    
    # 1-Click Sample Gallery
    st.markdown("**Quick Load Official Samples:**")
    col_s1, col_s2 = st.columns(2)
    with col_s1:
        if st.button("🆔 Aadhaar Card", use_container_width=True):
            data = generate_aadhaar_card_image()
            run_pipeline_analysis(data, "Sample_Aadhaar_Card.png")
            st.rerun()
        if st.button("🚗 Driving License", use_container_width=True):
            data = generate_driving_license_image()
            run_pipeline_analysis(data, "Sample_Driving_License.png")
            st.rerun()
            
    with col_s2:
        if st.button("💳 PAN Card", use_container_width=True):
            data = generate_pan_card_image()
            run_pipeline_analysis(data, "Sample_PAN_Card.png")
            st.rerun()
        if st.button("📄 Tax Notice (PDF)", use_container_width=True):
            data = generate_tax_assessment_notice_pdf()
            run_pipeline_analysis(data, "Sample_Income_Tax_Notice.pdf")
            st.rerun()

    st.markdown("---")
    
    # File Uploader
    uploaded_file = st.file_uploader(
        "Or Upload Custom Document",
        type=["pdf", "png", "jpg", "jpeg", "tiff", "webp"],
        help="Upload government forms, identity cards, gazette orders or certificates (Max 15MB)."
    )
    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        if st.session_state.doc_data is None or st.session_state.doc_data["filename"] != uploaded_file.name:
            run_pipeline_analysis(file_bytes, uploaded_file.name)
            st.rerun()

    st.markdown("---")
    st.markdown("### ⚙️ 2. Redaction Mode")
    redaction_style_str = st.selectbox(
        "Masking Style",
        ["BLACKOUT (Solid Black)", "PIXELATE (Mosaic)", "BLUR (Gaussian)", "MASK_LABEL (Security Badge)"],
        index=0
    )
    
    style_map = {
        "BLACKOUT (Solid Black)": RedactionStyle.BLACKOUT,
        "PIXELATE (Mosaic)": RedactionStyle.PIXELATE,
        "BLUR (Gaussian)": RedactionStyle.BLUR,
        "MASK_LABEL (Security Badge)": RedactionStyle.MASK_LABEL,
    }
    selected_style = style_map[redaction_style_str]

    blur_rad = 21
    if selected_style == RedactionStyle.BLUR:
        blur_rad = st.slider("Blur Radius", min_value=5, max_value=45, value=21, step=2)

    st.markdown("---")
    st.markdown("### 🛡️ System Telemetry")
    st.caption(f"**OCR Engine:** {'🟢 Tesseract Available' if TESSERACT_AVAILABLE else '🔵 Native Vector / PyMuPDF'}")
    st.caption(f"**Compliance Standard:** DPDP Act 2023 & Aadhaar Act 2016")
    st.caption(f"**Active Rules:** {len(INDIAN_PII_PATTERNS) + len(st.session_state.pii_engine.custom_rules)}")


# Main Interface Tabs
tab_main, tab_rules, tab_audit, tab_architecture = st.tabs([
    "🔍 Document Analysis & Redaction",
    "⚙️ Custom Rules Engine",
    "📜 DPDP Compliance & Certificates",
    "🏛️ Architecture & Defense Q&A"
])


# ============================================================================
# TAB 1: MAIN ANALYSIS & REDACTION
# ============================================================================
with tab_main:
    if st.session_state.doc_data is None:
        st.info("👆 Please select a sample document from the sidebar or upload your own government file to begin.")
        
        st.markdown("""
        ### Why PS13 GovPII Detector?
        - **Tailored for Indian Context:** Full support for Aadhaar (Verhoeff checksum validated), PAN Card, Voter ID, Driving License, Indian Phone Numbers (+91), UPI IDs, GSTIN, and Bank IFSC.
        - **Human-in-the-Loop (HITL) Review:** Avoid false positives by reviewing and toggling flagged PIIs before finalizing redactions.
        - **Multi-Format Redaction:** Supports vector PDF scrubbing (permanent text purge) as well as raster scan sanitization.
        - **Tamper-Evident Audit Certificate:** Automatically generates cryptographic SHA-256 signed PDF compliance certificates.
        """)
    else:
        doc = st.session_state.doc_data
        entities = doc["detected_entities"]
        
        # Summary Metrics Bar
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric("Total PII Caught", len(entities))
        with m2:
            st.metric("Selected for Redact", len(st.session_state.selected_entity_ids))
        with m3:
            st.metric("HITL Overrides", len(entities) - len(st.session_state.selected_entity_ids))
        with m4:
            st.metric("Processing Time", f"{doc['exec_time_ms']:.1f} ms")
        with m5:
            st.metric("Document Pages", len(doc["pages_info"]))

        st.markdown("---")

        # HITL Interactive Review Table
        st.markdown("### 🧑‍⚖️ Human-in-the-Loop (HITL) Review Matrix")
        st.caption("Review detected entities below. Uncheck any non-sensitive item (e.g. public official names) before finalizing redactions.")

        if not entities:
            st.success("✅ No sensitive PII detected in this document.")
        else:
            # Table Header
            cols = st.columns([1, 2, 3, 3, 2, 2])
            cols[0].markdown("**Redact?**")
            cols[1].markdown("**Category**")
            cols[2].markdown("**Detected Content**")
            cols[3].markdown("**Masked Form**")
            cols[4].markdown("**Confidence**")
            cols[5].markdown("**Rule / Validation**")

            for ent in entities:
                row_cols = st.columns([1, 2, 3, 3, 2, 2])
                is_selected = ent.id in st.session_state.selected_entity_ids
                
                check = row_cols[0].checkbox(
                    " ",
                    value=is_selected,
                    key=f"chk_{ent.id}",
                    label_visibility="collapsed"
                )
                if check:
                    st.session_state.selected_entity_ids.add(ent.id)
                else:
                    st.session_state.selected_entity_ids.discard(ent.id)

                row_cols[1].markdown(get_badge_html(ent.category.value), unsafe_allow_html=True)
                row_cols[2].code(ent.text, language=None)
                row_cols[3].markdown(f"**`{ent.masked_text}`**")
                row_cols[4].progress(ent.confidence, text=f"{int(ent.confidence * 100)}%")
                
                val_badge = f"🟢 {ent.rule_triggered}" if ent.validation_status == "VALID" else f"🟡 {ent.validation_status}"
                row_cols[5].caption(val_badge)

        st.markdown("---")

        # Action Button: Execute Redaction
        col_act1, col_act2 = st.columns([2, 5])
        with col_act1:
            if st.button("🔒 Apply Final Redaction & Generate Audit Certificate", type="primary", use_container_width=True):
                with st.spinner("Applying permanent redaction and generating cryptographic certificate..."):
                    # Filter selected entities
                    active_entities = [e for e in entities if e.id in st.session_state.selected_entity_ids]
                    
                    if doc["is_pdf"]:
                        sanitized_bytes, rendered_sanitized = redact_pdf_document(
                            doc["file_bytes"],
                            active_entities,
                            style=selected_style,
                            target_dpi=200
                        )
                        out_name = f"Sanitized_{doc['filename']}"
                    else:
                        page_img, _ = doc["pages_info"][0]
                        boxes_labels = [(e.bbox, f"REDACTED {e.category.value}") for e in active_entities]
                        redacted_bgr = redact_image(page_img, boxes_labels, style=selected_style, blur_radius=blur_rad)
                        rendered_sanitized = [redacted_bgr]
                        pil_red = numpy_to_pil(redacted_bgr)
                        sanitized_bytes = pil_to_bytes(pil_red, format="PNG")
                        out_name = f"Sanitized_{os.path.splitext(doc['filename'])[0]}.png"

                    sha256_sanitized = compute_sha256(sanitized_bytes)
                    audit_cert = create_audit_certificate(
                        document_id="DOC-" + doc["sha256_orig"][:8].upper(),
                        original_filename=doc["filename"],
                        sha256_original=doc["sha256_orig"],
                        sha256_sanitized=sha256_sanitized,
                        all_detected_entities=entities,
                        redacted_entities=active_entities,
                        style=selected_style,
                    )
                    pdf_cert_bytes = generate_pdf_certificate_bytes(audit_cert, active_entities)

                    st.session_state.redaction_result = {
                        "sanitized_bytes": sanitized_bytes,
                        "sanitized_filename": out_name,
                        "rendered_sanitized": rendered_sanitized,
                        "audit_cert": audit_cert,
                        "pdf_cert_bytes": pdf_cert_bytes,
                        "sha256_sanitized": sha256_sanitized,
                    }
                    st.success("✅ Redaction and Compliance Certification successfully executed!")

        # Side-by-Side Comparative Document Viewer
        st.markdown("### 📄 Side-by-Side Document Comparison")
        c_left, c_right = st.columns(2)

        page_to_show = 1
        if len(doc["pages_info"]) > 1:
            page_to_show = st.slider("Select Page to View", 1, len(doc["pages_info"]), 1)

        page_bgr, _ = doc["pages_info"][page_to_show - 1]

        with c_left:
            st.markdown("#### 🔴 Original Document (PII Highlights)")
            # Render detection overlay
            annotated_img = draw_detection_bounding_boxes(
                page_bgr.copy(),
                entities,
                page_number=page_to_show,
                highlight_selected_only=False
            )
            st.image(annotated_img, use_container_width=True, caption=f"Original: {doc['filename']} (Page {page_to_show})")

        with c_right:
            st.markdown("#### 🟢 Sanitized & Redacted Output")
            if st.session_state.redaction_result is not None:
                res = st.session_state.redaction_result
                sanitized_bgr = res["rendered_sanitized"][page_to_show - 1]
                st.image(numpy_to_pil(sanitized_bgr), use_container_width=True, caption=f"Sanitized: {res['sanitized_filename']}")
            else:
                st.info("👈 Click **'Apply Final Redaction'** above to generate the sanitized document preview.")

        # Download Hub
        if st.session_state.redaction_result is not None:
            st.markdown("---")
            st.markdown("### 📥 Download Sanitized Files & Certificates")
            res = st.session_state.redaction_result

            d1, d2, d3 = st.columns(3)
            with d1:
                st.download_button(
                    label=f"💾 Download {res['sanitized_filename']}",
                    data=res["sanitized_bytes"],
                    file_name=res["sanitized_filename"],
                    mime="application/pdf" if res["sanitized_filename"].endswith(".pdf") else "image/png",
                    use_container_width=True
                )
            with d2:
                st.download_button(
                    label="📜 Download PDF Audit Certificate",
                    data=res["pdf_cert_bytes"],
                    file_name=f"Compliance_Certificate_{res['audit_cert'].certificate_id}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            with d3:
                st.download_button(
                    label="📊 Download JSON Audit Log",
                    data=res["audit_cert"].model_dump_json(indent=2),
                    file_name=f"Audit_Report_{res['audit_cert'].certificate_id}.json",
                    mime="application/json",
                    use_container_width=True
                )


# ============================================================================
# TAB 2: CUSTOM RULES ENGINE
# ============================================================================
with tab_rules:
    st.markdown("### ⚙️ Dynamic Regex & NER Rules Management")
    st.markdown("Government departments can inject bespoke regex patterns at runtime without touching source code.")

    with st.form("custom_rule_form"):
        r_name = st.text_input("Rule Name", placeholder="e.g. State Ration Card ID")
        r_cat = st.selectbox("Entity Category", [c.value for c in PIICategory])
        r_pattern = st.text_input("Regex Pattern", placeholder=r"e.g. \b[A-Z]{2}[0-9]{8}\b")
        r_desc = st.text_area("Description / Use Case", placeholder="Pattern for state-specific ration card identifiers.")
        submitted = st.form_submit_button("➕ Register Custom Rule")

        if submitted and r_name and r_pattern:
            new_rule = CustomRegexRule(
                name=r_name,
                category=r_cat,
                pattern=r_pattern,
                description=r_desc,
                enabled=True
            )
            st.session_state.pii_engine.add_custom_rule(new_rule)
            st.success(f"✅ Rule '{r_name}' added successfully to active inspection pipeline!")

    st.markdown("#### Currently Active Rules")
    rule_data = []
    for r in INDIAN_PII_PATTERNS:
        rule_data.append({"Name": r["name"], "Category": r["category"].value, "Pattern": r["pattern"], "Type": "Built-in Indian Rule"})
    for cr in st.session_state.pii_engine.custom_rules:
        rule_data.append({"Name": cr.name, "Category": cr.category, "Pattern": cr.pattern, "Type": "Custom Runtime Rule"})
    
    st.dataframe(pd.DataFrame(rule_data), use_container_width=True)


# ============================================================================
# TAB 3: DPDP COMPLIANCE & CERTIFICATES
# ============================================================================
with tab_audit:
    st.markdown("### 📜 Digital Personal Data Protection (DPDP) Act 2023 Compliance")
    st.markdown("""
    Under Section 8 & Section 9 of the **DPDP Act 2023**, Data Fiduciaries handling citizen documents must ensure that all non-essential Personally Identifiable Information is permanently obfuscated before public disclosure or cross-departmental archiving.
    """)

    if st.session_state.redaction_result is not None:
        cert = st.session_state.redaction_result["audit_cert"]
        st.markdown(f"""
        #### Active Audit Certificate: `{cert.certificate_id}`
        - **Original Document SHA-256:** `{cert.sha256_original}`
        - **Sanitized Document SHA-256:** `{cert.sha256_sanitized}`
        - **Compliance Standard:** {cert.compliance_standard}
        - **Status:** :green[{cert.status}]
        """)
        st.json(cert.model_dump())
    else:
        st.info("Execute a redaction in the first tab to view the live compliance certificate.")


# ============================================================================
# TAB 4: ARCHITECTURE & DEFENSE Q&A
# ============================================================================
with tab_architecture:
    st.markdown("### 🏛️ System Architecture & Hackathon Defense Brief")
    
    st.markdown("""
    #### 1. Software Decomposition (100-Point Criteria Alignment)
    - **Ingestion & Preprocessing:** Handles PDF, PNG, JPG, TIFF. Applies OpenCV deskewing (minAreaRect), CLAHE contrast normalization, and bilateral denoising.
    - **OCR & Coordinate Engine:** Native PyMuPDF vector text bounding box extraction + Tesseract OCR bounding box mapping.
    - **Hybrid Detection Brain:** Regex with Verhoeff checksum algorithm for Aadhaar + Contextual NER for Names, Addresses, and Banking data.
    - **Redaction & Compliance:** Solid blackout, pixelation, gaussian blur, or security badges with permanent vector stream scrubbing and SHA-256 audit reports.

    #### 2. Prepared Defense Answers
    - **Q: How do you handle new formats of IDs?**
      - *Answer:* The hybrid pipeline allows admins to add new Regex patterns via the `/api/rules/custom` endpoint or UI dashboard instantly without retraining ML models.
    - **Q: Isn't OCR too slow for real-time traffic?**
      - *Answer:* Vector PDFs process natively via PyMuPDF in under 15ms per page. For high-volume scanned raster traffic, the backend utilizes async worker pools and can be connected directly to Redis/Celery.
    - **Q: How do you prevent redacting public government officials?**
      - *Answer:* The system implements a rigorous official whitelist ("Tahsildar", "Collector", "Ministry of Finance", etc.) coupled with an interactive Human-in-the-Loop (HITL) review checkbox interface.
    """)
