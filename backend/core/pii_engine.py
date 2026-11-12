"""
Hybrid PII Detection Engine for Indian Government Documents.
Combines rule-based Regex suite (Aadhaar with Verhoeff checksum, PAN, Voter ID, Passport, DL, UPI, GSTIN, Phone, IFSC)
with Contextual Pattern & NER analysis for Names, Addresses, and Financial accounts.
"""

import re
import uuid
from typing import List, Dict, Any, Tuple, Optional, Set
from backend.models.schemas import PIICategory, DetectedPII, BoundingBox, CustomRegexRule
from backend.core.ocr_engine import OCRWordToken


# ============================================================================
# VERHOEFF ALGORITHM (Aadhaar Checksum Validation)
# ============================================================================
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff_checksum(num_str: str) -> bool:
    """Validates 12-digit number against Verhoeff checksum equation."""
    clean = re.sub(r"\D", "", num_str)
    if len(clean) != 12:
        return False
    c = 0
    reversed_digits = [int(d) for d in reversed(clean)]
    for i, digit in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


# ============================================================================
# OFFICIAL WHITELIST (Prevents False Positives on Government Titles/Org Names)
# ============================================================================
GOVERNMENT_OFFICIAL_WHITELIST = {
    "GOVERNMENT OF INDIA", "GOVT OF INDIA", "STATE GOVERNMENT",
    "MINISTRY OF FINANCE", "MINISTRY OF HOME AFFAIRS", "MINISTRY OF ELECTRONICS",
    "UNIQUE IDENTIFICATION AUTHORITY OF INDIA", "UIDAI",
    "INCOME TAX DEPARTMENT", "ELECTION COMMISSION OF INDIA",
    "TRANSPORT DEPARTMENT", "REVENUE DEPARTMENT", "DISTRICT COLLECTORATE",
    "TAHSILDAR", "COLLECTOR", "SUB-REGISTRAR", "DEPUTY COMMISSIONER",
    "AUTHORIZED SIGNATORY", "SIGNATURE OF OFFICER", "NOTARY PUBLIC",
    "GOVERNMENT OF MAHARASHTRA", "GOVERNMENT OF KARNATAKA", "GOVERNMENT OF TAMIL NADU",
    "GOVERNMENT OF TELANGANA", "GOVERNMENT OF ANDHRA PRADESH", "GOVERNMENT OF DELHI",
    "GOVERNMENT OF UTTAR PRADESH", "DIGILOCKER", "E-OFFICE"
}


def _mask_aadhaar(t: str) -> str:
    clean = re.sub(r"[\s\-]", "", t)
    return f"XXXX XXXX {clean[-4:]}" if len(clean) >= 4 else "XXXX XXXX XXXX"


def _mask_pan(t: str) -> str:
    return f"{t[:2]}XXXXX{t[-1]}" if len(t) == 10 else "XXXXXXXXXX"


def _mask_voter(t: str) -> str:
    return f"{t[:3]}XXXX{t[-3:]}" if len(t) >= 6 else "XXXXXX"


def _mask_passport(t: str) -> str:
    return f"{t[0]}XXXXXX{t[-1]}" if len(t) >= 2 else "XXXXXXXX"


def _mask_dl(t: str) -> str:
    return f"{t[:4]}XXXXXXXX{t[-2:]}" if len(t) >= 6 else "XXXXXXXXXXXX"


def _mask_phone(t: str) -> str:
    clean = re.sub(r"\D", "", t)
    return f"+91 XXXXX-{clean[-4:]}" if len(clean) >= 4 else "XXXXXXXXXX"


def _mask_upi(t: str) -> str:
    parts = t.split("@")
    return f"{parts[0][:2]}***@{parts[-1]}" if len(parts) == 2 else "[REDACTED UPI]"


def _mask_gstin(t: str) -> str:
    return f"{t[:2]}XXXXXXXXXX{t[-3:]}" if len(t) >= 5 else "XXXXXXXXXXXXXXX"


def _mask_ifsc(t: str) -> str:
    return f"{t[:4]}0XXXXXX" if len(t) >= 5 else "XXXXXXXXXXX"


def _mask_email(t: str) -> str:
    parts = t.split("@")
    return f"{parts[0][0]}***@{parts[-1]}" if len(parts) == 2 else "[REDACTED EMAIL]"


# ============================================================================
# INDIAN CONTEXT REGEX DEFINITIONS
# ============================================================================
INDIAN_PII_PATTERNS: List[Dict[str, Any]] = [
    {
        "category": PIICategory.AADHAAR,
        "name": "Indian Aadhaar Number",
        "pattern": r"\b([2-9]{1}\d{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})\b",
        "confidence": 0.98,
        "mask": _mask_aadhaar,
        "validator": validate_verhoeff_checksum,
    },
    {
        "category": PIICategory.PAN,
        "name": "Permanent Account Number (PAN)",
        "pattern": r"\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b",
        "confidence": 0.96,
        "mask": _mask_pan,
        "validator": lambda t: t[3] in "PCHFATBLJG",  # 4th char is entity status
    },
    {
        "category": PIICategory.VOTER_ID,
        "name": "Indian Voter ID (EPIC)",
        "pattern": r"\b([A-Z]{3}[0-9]{7})\b|\b([A-Z]{2}\/[0-9]{2,3}\/[0-9]{3}\/[0-9]{6})\b",
        "confidence": 0.94,
        "mask": _mask_voter,
        "validator": None,
    },
    {
        "category": PIICategory.PASSPORT,
        "name": "Indian Passport Number",
        "pattern": r"\b([A-PR-WYa-pr-wy][1-9][0-9]\s?[0-9]{4}[1-9])\b",
        "confidence": 0.92,
        "mask": _mask_passport,
        "validator": None,
    },
    {
        "category": PIICategory.DRIVING_LICENSE,
        "name": "Indian Driving License",
        "pattern": r"\b([A-Z]{2}[-\s]?[0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{7})\b|\b([A-Z]{2}[0-9]{13,15})\b",
        "confidence": 0.93,
        "mask": _mask_dl,
        "validator": None,
    },
    {
        "category": PIICategory.PHONE,
        "name": "Indian Mobile/Phone Number",
        "pattern": r"\b(?:\+91[\-\s]?|91[\-\s]?|0)?[6789]\d{9}\b",
        "confidence": 0.90,
        "mask": _mask_phone,
        "validator": None,
    },
    {
        "category": PIICategory.UPI,
        "name": "Unified Payments Interface (UPI ID)",
        "pattern": r"\b([a-zA-Z0-9.\-_]{2,256}@(okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|apl|axl|ibl|upi|[a-zA-Z]{2,64}))\b",
        "confidence": 0.95,
        "mask": _mask_upi,
        "validator": None,
    },
    {
        "category": PIICategory.GSTIN,
        "name": "Goods & Services Tax Identification Number (GSTIN)",
        "pattern": r"\b([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1})\b",
        "confidence": 0.96,
        "mask": _mask_gstin,
        "validator": None,
    },
    {
        "category": PIICategory.IFSC,
        "name": "Bank IFSC Code",
        "pattern": r"\b([A-Z]{4}0[A-Z0-9]{6})\b",
        "confidence": 0.92,
        "mask": _mask_ifsc,
        "validator": None,
    },
    {
        "category": PIICategory.EMAIL,
        "name": "Email Address",
        "pattern": r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b",
        "confidence": 0.94,
        "mask": _mask_email,
        "validator": None,
    },
]


# ============================================================================
# CONTEXTUAL PATTERNS (Names, Bank Accounts, Addresses)
# ============================================================================
NAME_PREFIX_REGEX = re.compile(
    r"(?:Shri|Smt|Kumari|Dr|Mr|Mrs|Ms|Sri|Late|Name\s*:\s*|Father's\s*Name\s*:\s*|Applicant\s*:\s*|Beneficiary\s*:\s*|Husband's\s*Name\s*:\s*|Child's\s*Name\s*:\s*)\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
    re.IGNORECASE
)

BANK_ACCOUNT_REGEX = re.compile(
    r"(?:A\/C\s*(?:No\.?|Number)?|Account\s*(?:No\.?|Number)?|Acc\s*No\.?|Saving\s*A\/C|Current\s*A\/C)\s*[:\-]?\s*([0-9]{9,18})",
    re.IGNORECASE
)

ADDRESS_KEYWORD_REGEX = re.compile(
    r"(?:S\/O|D\/O|W\/O|H\.No|Door\s*No|Plot\s*No|House\s*No|Flat\s*No|Street|Nagar|Colony|Enclave|Village|Taluk|Mandal|District|PIN\s*Code|PIN\s*:)\s*[:\-]?\s*([^\n\r,]+(?:,\s*[^\n\r,]+){1,3})",
    re.IGNORECASE
)


class HybridPIIEngine:
    """
    Hybrid PII Engine executing Regex, Checksums, and Contextual NER.
    Maps detected entities to coordinate bounding boxes from OCR word tokens.
    """

    def __init__(self, custom_rules: Optional[List[CustomRegexRule]] = None):
        self.custom_rules = custom_rules or []

    def add_custom_rule(self, rule: CustomRegexRule):
        self.custom_rules.append(rule)

    def detect_pii(
        self,
        full_text: str,
        tokens: List[OCRWordToken]
    ) -> List[DetectedPII]:
        """
        Runs hybrid detection pipeline on extracted text and maps detected spans
        to geometric bounding boxes across pages.
        """
        detected_list: List[DetectedPII] = []
        covered_spans: Set[Tuple[int, int]] = set()

        # 1. Indian-Context Regex Rules
        for rule_def in INDIAN_PII_PATTERNS:
            cat = rule_def["category"]
            name = rule_def["name"]
            pat = rule_def["pattern"]
            conf = rule_def["confidence"]
            mask_fn = rule_def["mask"]
            validator = rule_def.get("validator")

            for match in re.finditer(pat, full_text, re.IGNORECASE):
                span = match.span()
                raw_match_text = match.group(0).strip()
                
                # Check whitelist
                if raw_match_text.upper() in GOVERNMENT_OFFICIAL_WHITELIST:
                    continue

                # Run validation check if provided (e.g. Verhoeff algorithm for Aadhaar)
                val_status = "VALID"
                if validator:
                    is_valid = validator(raw_match_text)
                    if not is_valid:
                        # Demote confidence if checksum fails or mark invalid
                        conf = max(0.4, conf - 0.4)
                        val_status = "CHECKSUM_FAILED"

                # Find token bounding box spanning this text
                bbox, page_num = self._map_text_to_bbox(raw_match_text, tokens)
                if bbox is None:
                    # Synthetic coordinate fallback if token mapping fails
                    bbox = BoundingBox(x0=50.0, y0=50.0, x1=200.0, y1=80.0, page_number=1)
                    page_num = 1

                masked = mask_fn(raw_match_text) if mask_fn else f"[{cat.value}-REDACTED]"

                entity = DetectedPII(
                    id=str(uuid.uuid4())[:8],
                    category=cat,
                    text=raw_match_text,
                    masked_text=masked,
                    confidence=conf,
                    bbox=bbox,
                    rule_triggered=name,
                    page_number=page_num,
                    selected_for_redaction=True,
                    validation_status=val_status,
                )
                detected_list.append(entity)

        # 2. Contextual Bank Accounts
        for match in BANK_ACCOUNT_REGEX.finditer(full_text):
            ac_num = match.group(1).strip()
            bbox, page_num = self._map_text_to_bbox(ac_num, tokens)
            if bbox:
                masked_ac = f"XXXXXX{ac_num[-4:]}" if len(ac_num) >= 4 else "XXXXXXXX"
                detected_list.append(
                    DetectedPII(
                        id=str(uuid.uuid4())[:8],
                        category=PIICategory.BANK_ACCOUNT,
                        text=ac_num,
                        masked_text=masked_ac,
                        confidence=0.91,
                        bbox=bbox,
                        rule_triggered="Bank Account Regex (Contextual)",
                        page_number=page_num,
                        selected_for_redaction=True,
                    )
                )

        # 3. Contextual Person Names
        for match in NAME_PREFIX_REGEX.finditer(full_text):
            name_text = match.group(1).strip()
            # Verify not in government whitelist
            if name_text.upper() in GOVERNMENT_OFFICIAL_WHITELIST or "GOVERNMENT" in name_text.upper():
                continue
            bbox, page_num = self._map_text_to_bbox(name_text, tokens)
            if bbox:
                detected_list.append(
                    DetectedPII(
                        id=str(uuid.uuid4())[:8],
                        category=PIICategory.PERSON_NAME,
                        text=name_text,
                        masked_text=f"{name_text[0]}*** ***",
                        confidence=0.88,
                        bbox=bbox,
                        rule_triggered="Person Name Pattern (Contextual)",
                        page_number=page_num,
                        selected_for_redaction=True,
                    )
                )

        # 4. Contextual Addresses
        for match in ADDRESS_KEYWORD_REGEX.finditer(full_text):
            addr_text = match.group(1).strip()
            if len(addr_text) > 4:
                bbox, page_num = self._map_text_to_bbox(addr_text, tokens)
                if bbox:
                    detected_list.append(
                        DetectedPII(
                            id=str(uuid.uuid4())[:8],
                            category=PIICategory.ADDRESS,
                            text=addr_text,
                            masked_text="[REDACTED ADDRESS]",
                            confidence=0.85,
                            bbox=bbox,
                            rule_triggered="Address Pattern (Contextual)",
                            page_number=page_num,
                            selected_for_redaction=True,
                        )
                    )

        # 5. User-Defined Custom Rules
        for custom_rule in self.custom_rules:
            if not custom_rule.enabled:
                continue
            try:
                for match in re.finditer(custom_rule.pattern, full_text, re.IGNORECASE):
                    matched_text = match.group(0).strip()
                    bbox, page_num = self._map_text_to_bbox(matched_text, tokens)
                    if bbox:
                        detected_list.append(
                            DetectedPII(
                                id=str(uuid.uuid4())[:8],
                                category=PIICategory.CUSTOM,
                                text=matched_text,
                                masked_text="[CUSTOM-REDACTED]",
                                confidence=0.90,
                                bbox=bbox,
                                rule_triggered=custom_rule.name,
                                page_number=page_num,
                                selected_for_redaction=True,
                            )
                        )
            except Exception as e:
                print(f"[Custom Rule Error] {custom_rule.name}: {e}")

        # Deduplicate overlapping entities with same category and overlapping bbox
        return self._deduplicate_entities(detected_list)

    def _map_text_to_bbox(
        self,
        target_text: str,
        tokens: List[OCRWordToken]
    ) -> Tuple[Optional[BoundingBox], int]:
        """
        Maps a search text string to the combined bounding box of its matching OCR tokens.
        Handles multi-word phrases and fuzzy whitespace.
        """
        clean_target = re.sub(r"[^a-zA-Z0-9]", "", target_text).lower()
        if not clean_target or not tokens:
            return None, 1

        # Search for consecutive tokens matching target
        n = len(tokens)
        for i in range(n):
            accumulated_str = ""
            matched_tokens = []
            for j in range(i, min(n, i + 8)):
                token_clean = re.sub(r"[^a-zA-Z0-9]", "", tokens[j].text).lower()
                accumulated_str += token_clean
                matched_tokens.append(tokens[j])

                if clean_target in accumulated_str or accumulated_str in clean_target:
                    if accumulated_str == clean_target:
                        # Found exact sequence match! Calculate bounding envelope
                        x0 = min(t.x0 for t in matched_tokens)
                        y0 = min(t.y0 for t in matched_tokens)
                        x1 = max(t.x1 for t in matched_tokens)
                        y1 = max(t.y1 for t in matched_tokens)
                        page = matched_tokens[0].page_number
                        avg_conf = sum(t.confidence for t in matched_tokens) / len(matched_tokens)
                        return BoundingBox(
                            x0=x0 - 3,
                            y0=y0 - 2,
                            x1=x1 + 3,
                            y1=y1 + 2,
                            page_number=page,
                            confidence=avg_conf
                        ), page

        # Fallback substring token search
        for t in tokens:
            token_clean = re.sub(r"[^a-zA-Z0-9]", "", t.text).lower()
            if token_clean and (token_clean in clean_target or clean_target in token_clean):
                return BoundingBox(
                    x0=t.x0 - 2,
                    y0=t.y0 - 2,
                    x1=t.x1 + 2,
                    y1=t.y1 + 2,
                    page_number=t.page_number,
                    confidence=t.confidence
                ), t.page_number

        return None, 1

    def _deduplicate_entities(self, entities: List[DetectedPII]) -> List[DetectedPII]:
        """Removes duplicate or heavily overlapping detected entities."""
        unique_entities: List[DetectedPII] = []
        seen_keys = set()

        for ent in entities:
            # Key based on category, normalized text, and page
            norm_text = re.sub(r"[\s\-]", "", ent.text).upper()
            key = (ent.category, norm_text, ent.page_number)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            unique_entities.append(ent)

        return unique_entities
