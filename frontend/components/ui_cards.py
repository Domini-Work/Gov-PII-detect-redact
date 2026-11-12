"""
UI Cards and Components for Streamlit GovPII Application.
"""

import streamlit as st


def render_header():
    """Renders the top GovTech header badge and navigation banner."""
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0369a1 100%);
        padding: 24px;
        border-radius: 14px;
        color: white;
        margin-bottom: 24px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
    }
    .gov-badge {
        background: rgba(14, 165, 233, 0.2);
        border: 1px solid #38bdf8;
        color: #38bdf8;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        display: inline-block;
        margin-bottom: 8px;
    }
    .stat-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 16px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        text-align: center;
    }
    .stat-val {
        font-size: 1.75rem;
        font-weight: 800;
        color: #0f172a;
    }
    .stat-label {
        font-size: 0.8rem;
        color: #64748b;
        text-transform: uppercase;
        font-weight: 600;
    }
    .entity-badge-aadhaar { background-color: #fee2e2; color: #991b1b; border: 1px solid #f87171; border-radius: 6px; padding: 2px 8px; font-weight: 700; font-size: 0.8rem; }
    .entity-badge-pan { background-color: #e0f2fe; color: #075985; border: 1px solid #38bdf8; border-radius: 6px; padding: 2px 8px; font-weight: 700; font-size: 0.8rem; }
    .entity-badge-phone { background-color: #fef3c7; color: #92400e; border: 1px solid #fcd34d; border-radius: 6px; padding: 2px 8px; font-weight: 700; font-size: 0.8rem; }
    .entity-badge-bank { background-color: #dcfce7; color: #166534; border: 1px solid #4ade80; border-radius: 6px; padding: 2px 8px; font-weight: 700; font-size: 0.8rem; }
    .entity-badge-name { background-color: #f3e8ff; color: #6b21a8; border: 1px solid #c084fc; border-radius: 6px; padding: 2px 8px; font-weight: 700; font-size: 0.8rem; }
    .entity-badge-generic { background-color: #f1f5f9; color: #334155; border: 1px solid #94a3b8; border-radius: 6px; padding: 2px 8px; font-weight: 700; font-size: 0.8rem; }
    </style>
    <div class="main-header">
        <div class="gov-badge">🇮🇳 National AI GovTech Portal &bull; PS13 Edition</div>
        <h1 style="margin: 0; font-size: 2.1rem; font-weight: 800; color: #ffffff;">Government Document PII Detector & Redactor</h1>
        <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 1.0rem;">
            Automated Indian Context Sensitive Data Detection, High-Precision Redaction & DPDP Act 2023 Compliance Auditing.
        </p>
    </div>
    """, unsafe_allow_html=True)


def get_badge_html(category: str) -> str:
    """Returns styled HTML badge for entity category."""
    c = category.upper()
    if "AADHAAR" in c:
        return f'<span class="entity-badge-aadhaar">🆔 {c}</span>'
    elif "PAN" in c:
        return f'<span class="entity-badge-pan">💳 {c}</span>'
    elif "PHONE" in c or "MOBILE" in c:
        return f'<span class="entity-badge-phone">📱 {c}</span>'
    elif "BANK" in c or "IFSC" in c or "UPI" in c:
        return f'<span class="entity-badge-bank">🏦 {c}</span>'
    elif "NAME" in c or "PERSON" in c:
        return f'<span class="entity-badge-name">👤 {c}</span>'
    else:
        return f'<span class="entity-badge-generic">🔒 {c}</span>'
