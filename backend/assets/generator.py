"""
Synthetic Government Document Generator.
Generates realistic Indian government sample documents (Aadhaar, PAN, DL, Tax Notice, Office Order)
for automated testing, demo presentation, and evaluation.
"""

import os
import io
from PIL import Image, ImageDraw, ImageFont
import fitz  # PyMuPDF


def generate_aadhaar_card_image() -> bytes:
    """Generates a realistic synthetic Indian Aadhaar Card image."""
    w, h = 900, 560
    img = Image.new("RGB", (w, h), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Tricolor Header Bar
    draw.rectangle([(0, 0), (w, 18)], fill=(255, 153, 51))   # Saffron
    draw.rectangle([(0, 18), (w, 36)], fill=(255, 255, 255)) # White
    draw.rectangle([(0, 36), (w, 54)], fill=(19, 136, 8))    # Green

    # Government Title
    draw.text((60, 65), "भारत सरकार / Government of India", fill=(0, 51, 102))
    draw.text((60, 95), "Unique Identification Authority of India", fill=(100, 100, 100))

    # Outer Frame Border
    draw.rectangle([(20, 20), (w - 20, h - 20)], outline=(180, 180, 180), width=2)

    # Photo Box Mock
    draw.rectangle([(60, 140), (220, 340)], fill=(230, 235, 245), outline=(120, 140, 180), width=2)
    draw.text((105, 225), "PHOTO", fill=(120, 140, 180))

    # Citizen Details (PII to be detected & redacted)
    draw.text((270, 140), "Name : Shri Rajesh Kumar Sharma", fill=(20, 20, 20))
    draw.text((270, 180), "DOB : 15/08/1988  |  Gender : Male", fill=(20, 20, 20))
    draw.text((270, 220), "Address : Flat 402, Lotus Towers, Outer Ring Road", fill=(20, 20, 20))
    draw.text((270, 250), "Bangalore South, Karnataka, PIN : 560001", fill=(20, 20, 20))
    draw.text((270, 285), "Phone : +91 9876543210", fill=(20, 20, 20))
    draw.text((270, 320), "Email : rajesh.sharma.blr@gmail.com", fill=(20, 20, 20))

    # Large Aadhaar Number Bar (Valid Verhoeff checksum)
    draw.rectangle([(60, 380), (w - 60, 460)], fill=(245, 247, 250), outline=(200, 200, 200), width=1)
    draw.text((230, 400), "मेरा आधार, मेरी पहचान", fill=(100, 100, 100))
    # 2947 1827 3645 has valid Verhoeff checksum
    draw.text((260, 425), "2947  1827  3645", fill=(180, 30, 30))

    # QR Code Mock Placeholder
    draw.rectangle([(w - 220, 140), (w - 60, 300)], fill=(240, 240, 240), outline=(100, 100, 100), width=1)
    draw.text((w - 180, 210), "[QR CODE]", fill=(100, 100, 100))

    # Bottom Helpline Bar
    draw.rectangle([(20, h - 50), (w - 20, h - 20)], fill=(0, 51, 102))
    draw.text((180, h - 42), "Toll Free: 1947 | help@uidai.gov.in | www.uidai.gov.in", fill=(255, 255, 255))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_pan_card_image() -> bytes:
    """Generates a realistic synthetic Indian Income Tax PAN Card image."""
    w, h = 900, 560
    img = Image.new("RGB", (w, h), color=(220, 238, 248))  # Classic PAN card cyan tint
    draw = ImageDraw.Draw(img)

    # Frame Border
    draw.rectangle([(15, 15), (w - 15, h - 15)], outline=(0, 90, 140), width=3)

    # Header
    draw.text((50, 40), "आयकर विभाग / INCOME TAX DEPARTMENT", fill=(0, 45, 90))
    draw.text((50, 70), "भारत सरकार / GOVT. OF INDIA", fill=(0, 45, 90))

    # Photo Box
    draw.rectangle([(50, 120), (210, 320)], fill=(240, 240, 240), outline=(0, 45, 90), width=2)
    draw.text((95, 210), "PHOTO", fill=(100, 100, 100))

    # PAN Holder Details
    draw.text((250, 120), "Permanent Account Number Card", fill=(120, 50, 0))
    draw.text((250, 155), "Name : AMITABH ANAND VERMA", fill=(0, 0, 0))
    draw.text((250, 195), "Father's Name : SURESH KUMAR VERMA", fill=(0, 0, 0))
    draw.text((250, 235), "Date of Birth : 24/11/1985", fill=(0, 0, 0))

    # PAN Number (High visibility)
    draw.rectangle([(250, 275), (650, 335)], fill=(255, 255, 255), outline=(0, 45, 90), width=1)
    draw.text((270, 290), "PAN : ABCPV1234F", fill=(180, 0, 0))

    # Signature Mock
    draw.rectangle([(50, 360), (250, 440)], fill=(255, 255, 255), outline=(150, 150, 150), width=1)
    draw.text((70, 390), "Amitabh Verma (Sign)", fill=(0, 0, 150))

    # QR Code Mock
    draw.rectangle([(w - 200, 140), (w - 50, 290)], fill=(255, 255, 255), outline=(0, 45, 90), width=1)
    draw.text((w - 165, 205), "[QR CODE]", fill=(100, 100, 100))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_tax_assessment_notice_pdf() -> bytes:
    """Generates a realistic multi-PII Government Income Tax Assessment Notice in PDF format."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4 size

    # Header
    page.insert_text((50, 50), "GOVERNMENT OF INDIA", fontsize=14, fontname="helv", color=(0, 0, 0))
    page.insert_text((50, 70), "MINISTRY OF FINANCE - INCOME TAX DEPARTMENT", fontsize=11, fontname="helv", color=(0.1, 0.3, 0.6))
    page.insert_text((50, 85), "Office of the Income Tax Officer, Ward 12(3), New Delhi", fontsize=9, fontname="helv", color=(0.3, 0.3, 0.3))

    # Divider line
    page.draw_line((50, 100), (545, 100), color=(0.1, 0.3, 0.6), width=1.5)

    # Notice Reference
    page.insert_text((50, 125), "Notice Under Section 143(1) of the Income-tax Act, 1961", fontsize=11, fontname="helv", color=(0.7, 0.1, 0.1))
    page.insert_text((50, 145), "Assessment Year: 2024-25 | Date of Issue: 12-09-2026", fontsize=9, fontname="helv", color=(0.2, 0.2, 0.2))

    # Citizen Details Table Box
    page.draw_rect((50, 165, 545, 330), color=(0.7, 0.7, 0.7), width=1)
    page.insert_text((65, 190), "Assessee Name : Shri Amitabh Anand Verma", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text((65, 215), "PAN Number : ABCPV1234F", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text((65, 240), "Aadhaar Linked : 2947 1827 3645", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text((65, 265), "Mobile Number : +91 9812345678", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text((65, 290), "Email ID : amitabh.v@gmail.com", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text((65, 315), "Residential Address : House No 88, Sector 15, Gurgaon, PIN : 122001", fontsize=10, fontname="helv", color=(0, 0, 0))

    # Bank Refund Details
    page.insert_text((50, 360), "Bank Account Details for Direct Benefit Transfer / Refund:", fontsize=11, fontname="helv", color=(0, 0, 0))
    page.draw_rect((50, 375, 545, 455), color=(0.7, 0.7, 0.7), width=1)
    page.insert_text((65, 395), "Bank Name : State Bank of India", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text((65, 415), "Bank Account No : 9123456789012", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text((65, 435), "IFSC Code : SBIN0001234  |  UPI ID : amitabh.v@oksbi", fontsize=10, fontname="helv", color=(0, 0, 0))

    # Official Order Text
    order_body = """
    Please take notice that the Income Tax Return filed by the assessee for Assessment Year 2024-25 has been processed. 
    A net refund amount of Rs. 42,500/- has been approved and scheduled for electronic transfer.
    
    This notice is electronically verified under Digital Signature of the Assessing Officer.
    """
    page.insert_textbox((50, 480, 545, 600), order_body.strip(), fontsize=9.5, fontname="helv", color=(0.1, 0.1, 0.1))

    # Official Signatory (Whitelist item)
    page.insert_text((350, 680), "Authorized Signatory,", fontsize=9, fontname="helv", color=(0.3, 0.3, 0.3))
    page.insert_text((350, 700), "Assistant Commissioner of Income Tax,", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text((350, 715), "Circle 12(1), Government of India", fontsize=9, fontname="helv", color=(0, 0, 0))

    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def generate_driving_license_image() -> bytes:
    """Generates synthetic Indian Driving License Card image."""
    w, h = 900, 560
    img = Image.new("RGB", (w, h), color=(250, 245, 235))
    draw = ImageDraw.Draw(img)

    # Frame
    draw.rectangle([(15, 15), (w - 15, h - 15)], outline=(120, 80, 20), width=3)
    draw.text((60, 40), "UNION OF INDIA - DRIVING LICENCE", fill=(100, 40, 10))
    draw.text((60, 70), "TRANSPORT DEPARTMENT - KARNATAKA", fill=(80, 80, 80))

    # Photo Box
    draw.rectangle([(50, 120), (210, 320)], fill=(230, 230, 230), outline=(100, 40, 10), width=2)
    draw.text((95, 210), "PHOTO", fill=(100, 100, 100))

    # Details
    draw.text((250, 120), "DL No : KA-0120150098765", fill=(180, 0, 0))
    draw.text((250, 160), "Name : VIKRAM RAO", fill=(0, 0, 0))
    draw.text((250, 200), "S/O : MANOHAR RAO", fill=(0, 0, 0))
    draw.text((250, 240), "DOB : 10/05/1992  |  Blood Group : O+", fill=(0, 0, 0))
    draw.text((250, 280), "Address : Door No 45, 3rd Main, Indiranagar, Bangalore", fill=(0, 0, 0))
    draw.text((250, 320), "PIN Code : 560038  |  Phone : 9845012345", fill=(0, 0, 0))

    # Chip Mock
    draw.rectangle([(w - 180, 140), (w - 60, 240)], fill=(220, 190, 100), outline=(150, 120, 40), width=2)
    draw.text((w - 145, 180), "CHIP", fill=(50, 40, 10))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def create_all_sample_assets(output_dir: str):
    """Saves all synthetic sample documents into target assets folder."""
    os.makedirs(output_dir, exist_ok=True)
    
    samples = {
        "Sample_Aadhaar_Card.png": generate_aadhaar_card_image(),
        "Sample_PAN_Card.png": generate_pan_card_image(),
        "Sample_Driving_License.png": generate_driving_license_image(),
        "Sample_Income_Tax_Notice.pdf": generate_tax_assessment_notice_pdf(),
    }

    for fname, data in samples.items():
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "wb") as f:
            f.write(data)
    print(f"[Assets] Generated {len(samples)} sample government documents in {output_dir}")
