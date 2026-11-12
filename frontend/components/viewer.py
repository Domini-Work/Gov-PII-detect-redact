"""
Visual Document Comparison and Bounding Box Overlay Component.
"""

from typing import List, Tuple, Optional
import numpy as np
import cv2
from PIL import Image
from backend.models.schemas import DetectedPII, BoundingBox
from backend.core.preprocessing import numpy_to_pil


# Category color palette for bounding box overlays (BGR)
CATEGORY_COLORS = {
    "AADHAAR": (40, 40, 230),         # Vibrant Red
    "PAN": (230, 120, 20),             # Sky Blue
    "VOTER_ID": (20, 160, 230),        # Orange
    "PASSPORT": (180, 50, 180),        # Purple
    "DRIVING_LICENSE": (30, 180, 80),  # Green
    "PHONE": (0, 200, 240),            # Yellow/Amber
    "EMAIL": (200, 140, 0),            # Dark Blue
    "UPI": (0, 140, 200),              # Bronze
    "GSTIN": (120, 100, 220),          # Pink
    "BANK_ACCOUNT": (50, 150, 30),     # Forest Green
    "IFSC": (100, 150, 50),            # Olive
    "PERSON_NAME": (160, 40, 140),     # Violet
    "ADDRESS": (100, 100, 100),        # Slate Gray
    "CUSTOM": (0, 0, 255),             # Pure Red
}


def draw_detection_bounding_boxes(
    image_bgr: np.ndarray,
    entities: List[DetectedPII],
    page_number: int = 1,
    highlight_selected_only: bool = False
) -> Image.Image:
    """
    Renders semi-transparent highlight rectangles and category labels
    over detected PII entities on the original document image.
    """
    overlay = image_bgr.copy()
    h, w = overlay.shape[:2]

    for ent in entities:
        if ent.page_number != page_number:
            continue
        if highlight_selected_only and not ent.selected_for_redaction:
            continue

        bbox = ent.bbox
        x0 = int(round(max(0, bbox.x0)))
        y0 = int(round(max(0, bbox.y0)))
        x1 = int(round(min(w, bbox.x1)))
        y1 = int(round(min(h, bbox.y1)))

        if x1 <= x0 or y1 <= y0:
            continue

        cat_name = ent.category.value
        color = CATEGORY_COLORS.get(cat_name, (50, 50, 200))

        # Filled translucent rectangle
        cv2.rectangle(overlay, (x0, y0), (x1, y1), color, -1)
        # Sharp border
        cv2.rectangle(image_bgr, (x0, y0), (x1, y1), color, 2)

        # Label tag above bounding box
        label = f"{cat_name} ({int(ent.confidence * 100)}%)"
        font_scale = 0.4
        thickness = 1
        t_size = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, font_scale, thickness)[0]
        
        tag_y0 = max(0, y0 - t_size[1] - 4)
        tag_y1 = y0
        cv2.rectangle(image_bgr, (x0, tag_y0), (x0 + t_size[0] + 6, tag_y1), color, -1)
        cv2.putText(
            image_bgr,
            label,
            (x0 + 3, tag_y1 - 2),
            cv2.FONT_HERSHEY_SIMPLEX,
            font_scale,
            (255, 255, 255),
            thickness,
            cv2.LINE_AA
        )

    # Alpha blend overlay with 35% opacity
    alpha = 0.35
    blended = cv2.addWeighted(overlay, alpha, image_bgr, 1 - alpha, 0)
    return numpy_to_pil(blended)
