"""
quality_filters.py
--------------------
Modular false-positive reduction layer for the crop/weed/disease pipeline.

Addresses the debris-misclassified-as-disease failure mode by adding:
  1. A pre-processing vegetation mask (ExG/Otsu) that gates crop detections
     before they ever reach the disease classifier.
  2. Post-processing filters (geometric plausibility, weed-cluster suppression,
     softmax confidence-margin) applied after classification.
  3. Focal loss + inverse-frequency class weighting for retraining the CNN
     once a Background/Debris class is added to disease_data/.
  4. Duplicate/overlap resolution (NMS-style dedup + weed-vs-crop overlap
     resolution) and an absolute pixel-size floor, addressing overlapping
     disease boxes, duplicate detections, and weeds boxed on top of crops.

Imported by disease_classifier.py, backend/app.py, and train_disease_classifier.py.
No GPU dependency — everything here runs on CPU, most of it in well under a
millisecond per call at 512x512 resolution.
"""

from __future__ import annotations

from typing import Sequence

import cv2
import numpy as np
import torch
import torch.nn.functional as F

BACKGROUND_DEBRIS_LABEL = "Background/Debris"


def compute_exg(image_rgb: np.ndarray) -> np.ndarray:
    r = image_rgb[..., 0].astype(np.float32)
    g = image_rgb[..., 1].astype(np.float32)
    b = image_rgb[..., 2].astype(np.float32)
    total = r + g + b + 1e-6
    rn, gn, bn = r / total, g / total, b / total
    return 2 * gn - rn - bn


def vegetation_mask(image_rgb: np.ndarray, min_component_area: int = 40) -> np.ndarray:
    exg = compute_exg(image_rgb)
    exg_u8 = cv2.normalize(exg, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    _, mask = cv2.threshold(exg_u8, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((3, 3), np.uint8))
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((5, 5), np.uint8))
    num, labels, stats, _ = cv2.connectedComponentsWithStats(mask, connectivity=8)
    clean = np.zeros_like(mask)
    for i in range(1, num):
        if stats[i, cv2.CC_STAT_AREA] >= min_component_area:
            clean[labels == i] = 255
    return clean


def vegetation_coverage(box: Sequence[float], mask: np.ndarray) -> float:
    x1, y1, x2, y2 = [int(v) for v in box]
    region = mask[max(0, y1):y2, max(0, x1):x2]
    if region.size == 0:
        return 0.0
    return float(np.count_nonzero(region)) / region.size


def gate_crop_detection(box: Sequence[float], mask: np.ndarray, veg_threshold: float = 0.35) -> bool:
    return vegetation_coverage(box, mask) >= veg_threshold


def is_geometrically_plausible(box: Sequence[float], img_w: int, img_h: int,
                                min_ar: float = 0.25, max_ar: float = 4.0,
                                max_area_frac: float = 0.35, min_dim_px: float = 8.0) -> bool:
    x1, y1, x2, y2 = box
    w, h = x2 - x1, y2 - y1
    if w <= 0 or h <= 0:
        return False
    if w < min_dim_px or h < min_dim_px:
        return False
    ar = w / h
    area_frac = (w * h) / (img_w * img_h)
    return min_ar <= ar <= max_ar and area_frac <= max_area_frac


def iou(box_a: Sequence[float], box_b: Sequence[float]) -> float:
    xa1, ya1, xa2, ya2 = box_a
    xb1, yb1, xb2, yb2 = box_b
    ix1, iy1 = max(xa1, xb1), max(ya1, yb1)
    ix2, iy2 = min(xa2, xb2), min(ya2, yb2)
    iw, ih = max(0, ix2 - ix1), max(0, iy2 - iy1)
    inter = iw * ih
    area_a = (xa2 - xa1) * (ya2 - ya1)
    area_b = (xb2 - xb1) * (yb2 - yb1)
    return inter / (area_a + area_b - inter + 1e-6)


def suppress_near_weed_cluster(disease_box: Sequence[float], weed_boxes: Sequence[Sequence[float]],
                                iou_thresh: float = 0.15, cluster_min: int = 3) -> bool:
    overlaps = sum(1 for wb in weed_boxes if iou(disease_box, wb) > iou_thresh)
    return overlaps < cluster_min


def passes_confidence_margin(softmax_scores: Sequence[float], min_margin: float = 0.15) -> bool:
    if len(softmax_scores) < 2:
        return True
    sorted_scores = sorted(softmax_scores, reverse=True)
    return (sorted_scores[0] - sorted_scores[1]) >= min_margin


def compute_class_weights(class_counts: Sequence[int]) -> torch.Tensor:
    counts = torch.tensor(class_counts, dtype=torch.float32)
    weights = 1.0 / torch.sqrt(counts + 1.0)
    return weights / weights.sum() * len(counts)


def focal_loss(logits: torch.Tensor, targets: torch.Tensor,
                class_weights: torch.Tensor | None = None, gamma: float = 2.0,
                label_smoothing: float = 0.0) -> torch.Tensor:
    ce = F.cross_entropy(logits, targets, weight=class_weights, reduction="none",
                          label_smoothing=label_smoothing)
    pt = torch.exp(-ce)
    return ((1 - pt) ** gamma * ce).mean()


def suppress_duplicate_boxes(boxes: Sequence[dict], iou_thresh: float = 0.5,
                              conf_key: str = "detection_confidence") -> tuple[list[dict], int]:
    """Greedy same-class NMS over the final box list (dicts with x1/y1/x2/y2/class_name/
    conf_key). Keeps the highest-confidence box in each overlapping cluster and drops the
    rest — this is what actually removes duplicate/overlapping disease boxes that survive
    the detector's own internal NMS (which only dedupes within a single detector's raw
    output, not after our downstream class reassignment to crop_healthy/crop_diseased/debris)."""
    by_class: dict[str, list[int]] = {}
    for i, b in enumerate(boxes):
        by_class.setdefault(b["class_name"], []).append(i)

    keep_flags = [True] * len(boxes)
    for _, idxs in by_class.items():
        ordered = sorted(idxs, key=lambda i: boxes[i][conf_key], reverse=True)
        for a_pos in range(len(ordered)):
            a = ordered[a_pos]
            if not keep_flags[a]:
                continue
            box_a = (boxes[a]["x1"], boxes[a]["y1"], boxes[a]["x2"], boxes[a]["y2"])
            for b_pos in range(a_pos + 1, len(ordered)):
                b_idx = ordered[b_pos]
                if not keep_flags[b_idx]:
                    continue
                box_b = (boxes[b_idx]["x1"], boxes[b_idx]["y1"], boxes[b_idx]["x2"], boxes[b_idx]["y2"])
                if iou(box_a, box_b) > iou_thresh:
                    keep_flags[b_idx] = False

    kept = [b for b, flag in zip(boxes, keep_flags) if flag]
    suppressed_count = len(boxes) - len(kept)
    return kept, suppressed_count


def resolve_weed_crop_overlap(boxes: Sequence[dict], iou_thresh: float = 0.45,
                               conf_key: str = "detection_confidence") -> tuple[list[dict], int]:
    """Weed boxes that heavily overlap a crop box are almost always a spurious weed
    detection on crop canopy rather than a real weed underneath the plant — this is the
    'weed detection overlaps with sesame plants' failure mode. Resolve by keeping only
    the higher-confidence interpretation for that region instead of drawing both."""
    weed_idxs = [i for i, b in enumerate(boxes) if b["class_name"] == "weed"]
    crop_idxs = [i for i, b in enumerate(boxes) if b["class_name"] in ("crop_healthy", "crop_diseased")]

    drop = set()
    for wi in weed_idxs:
        wbox = (boxes[wi]["x1"], boxes[wi]["y1"], boxes[wi]["x2"], boxes[wi]["y2"])
        for ci in crop_idxs:
            cbox = (boxes[ci]["x1"], boxes[ci]["y1"], boxes[ci]["x2"], boxes[ci]["y2"])
            if iou(wbox, cbox) > iou_thresh:
                if boxes[wi][conf_key] >= boxes[ci][conf_key] + 0.15:
                    drop.add(ci)
                else:
                    drop.add(wi)

    kept = [b for i, b in enumerate(boxes) if i not in drop]
    return kept, len(drop)
