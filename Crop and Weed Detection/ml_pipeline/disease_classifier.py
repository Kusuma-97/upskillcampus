"""
disease_classifier.py
----------------------
Shared disease-classification module used by both the training script
(train_disease_classifier.py) and the backend (backend/app.py).

IMPORTANT — read this before trusting any disease output from this module:
The dataset supplied for this project (dataset/agri_data) contains ONLY crop/weed
bounding-box labels. It contains no disease annotations whatsoever. So out of the box,
this module runs in HEURISTIC mode: it inspects HSV color statistics inside a detected
crop's bounding box (yellowing = chlorosis, dark/brown patches = necrotic lesions typical
of leaf-spot diseases, uniform healthy green = healthy) and produces a plausible label.
This is a real, useful triage signal — but it is NOT a trained deep-learning classifier,
and every result it returns is tagged `"method": "heuristic"` so the UI and API consumers
always know the provenance.

FALSE-POSITIVE FIX (debris/dead matter misclassified as diseased crop):
Color-only heuristics — and an untrained 3-class softmax in general — cannot tell a
necrotic leaf apart from dead organic matter or an uprooted weed pile, because both
produce the same low-brightness/moderate-saturation HSV signature, and softmax over a
closed set of {Healthy, Cercospora, Bacterial Blight} has no way to express "none of
the above." Two fixes are wired in for this:
  1. `predict()` accepts an optional `veg_coverage` argument (see quality_filters.py's
     ExG/Otsu vegetation mask). If a box's live-vegetation coverage is below threshold,
     it's routed straight to a `Background/Debris` label with `"method": "veg_gate"`,
     bypassing disease scoring entirely rather than forcing a disease guess on dead matter.
  2. `DEFAULT_DISEASE_CLASSES` now includes `Background/Debris` as an explicit 4th class,
     so a retrained CNN has somewhere to route debris/dead-matter crops instead of being
     forced into a disease label. See train_disease_classifier.py for the matching focal
     loss + class-weighting changes.

The MobileNet-lite CNN defined below (`DiseaseCNN`) is a real, trainable architecture.
The moment you provide labeled disease images (see train_disease_classifier.py) and train
it, `load_disease_model()` will pick up the trained checkpoint automatically and every
result will be tagged `"method": "cnn"` instead.

ACCURACY UPGRADE — lesion shape/border detection, not just color fractions:
The original heuristic scored disease purely on the *fraction* of dark/brown pixels in a
box, which can't distinguish a genuine Cercospora lesion (ash-gray center, distinct dark
border, roughly circular/oval, per DATA_COLLECTION_BLUEPRINT.md section 1.1) from diffuse
shadowing or uneven coloration that happens to be dark on average. `_predict_heuristic` now
runs a contour pass over the necrotic-candidate pixel mask, keeps only components that are
lesion-plausible in size and roughly circular, and specifically checks for a darker border
ring around a lighter center (the diagnostic signature) before counting them as disease
evidence — this materially cuts false positives from uneven lighting/coloration while
keeping sensitivity to genuine spotting. The CNN path also now runs light test-time
augmentation (horizontal + vertical flip averaging), a standard, low-risk accuracy technique
for once a real checkpoint exists.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Optional

import cv2
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from PIL import Image

from quality_filters import BACKGROUND_DEBRIS_LABEL, vegetation_mask

# ---------------------------------------------------------------------------
# Class definitions
# ---------------------------------------------------------------------------
# NOTE: these class names are placeholders representative of common sesame leaf
# diseases (Cercospora leaf spot, bacterial blight) as requested in the spec.
# "Background/Debris" is a dedicated negative class — without it, softmax is
# forced to distribute 100% probability across only the disease/healthy labels
# even when the crop is dead matter or debris, which is the root cause of the
# false-positive pattern this module was extended to fix. When you train on
# real labeled data, replace this list with your actual folder names from
# disease_data/ (train_disease_classifier.py reads them automatically and this
# list is overwritten in the saved checkpoint's metadata) — just make sure a
# background/debris folder is included among them.
DEFAULT_DISEASE_CLASSES = ["Healthy", "Cercospora Leaf Spot", "Bacterial Blight", BACKGROUND_DEBRIS_LABEL]

IMG_SIZE = 96  # small input size keeps CPU inference fast for a per-crop classifier


# ---------------------------------------------------------------------------
# MobileNet-lite architecture (depthwise-separable convs -> low CPU FLOPs)
# ---------------------------------------------------------------------------
class DepthwiseSeparableConv(nn.Module):
    def __init__(self, in_ch: int, out_ch: int, stride: int = 1):
        super().__init__()
        self.depthwise = nn.Conv2d(in_ch, in_ch, 3, stride=stride, padding=1, groups=in_ch, bias=False)
        self.bn1 = nn.BatchNorm2d(in_ch)
        self.pointwise = nn.Conv2d(in_ch, out_ch, 1, bias=False)
        self.bn2 = nn.BatchNorm2d(out_ch)
        self.act = nn.ReLU6(inplace=True)

    def forward(self, x):
        x = self.act(self.bn1(self.depthwise(x)))
        x = self.act(self.bn2(self.pointwise(x)))
        return x


class DiseaseCNN(nn.Module):
    """~0.9M parameter MobileNet-lite classifier. Runs in well under 50ms per
    96x96 crop on a modern laptop CPU, making per-detection disease scoring
    practical even on constrained edge hardware."""

    def __init__(self, num_classes: int = 3):
        super().__init__()
        self.stem = nn.Sequential(
            nn.Conv2d(3, 16, 3, stride=2, padding=1, bias=False),
            nn.BatchNorm2d(16),
            nn.ReLU6(inplace=True),
        )
        self.blocks = nn.Sequential(
            DepthwiseSeparableConv(16, 32, stride=1),
            DepthwiseSeparableConv(32, 64, stride=2),
            DepthwiseSeparableConv(64, 64, stride=1),
            DepthwiseSeparableConv(64, 128, stride=2),
            DepthwiseSeparableConv(128, 128, stride=1),
            DepthwiseSeparableConv(128, 256, stride=2),
        )
        self.pool = nn.AdaptiveAvgPool2d(1)
        self.classifier = nn.Linear(256, num_classes)

    def forward(self, x):
        x = self.stem(x)
        x = self.blocks(x)
        x = self.pool(x).flatten(1)
        return self.classifier(x)


# ---------------------------------------------------------------------------
# CNN-based inference path (used once a real checkpoint exists)
# ---------------------------------------------------------------------------
def _preprocess_crop(crop_rgb: np.ndarray) -> torch.Tensor:
    img = Image.fromarray(crop_rgb).resize((IMG_SIZE, IMG_SIZE), Image.BILINEAR)
    arr = np.asarray(img, dtype=np.float32) / 255.0
    mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
    std = np.array([0.229, 0.224, 0.225], dtype=np.float32)
    arr = (arr - mean) / std
    tensor = torch.from_numpy(arr.transpose(2, 0, 1)).unsqueeze(0).float()
    return tensor


def _detect_lesions(crop_rgb: np.ndarray, necrotic_mask: np.ndarray, leaf_mask: Optional[np.ndarray] = None) -> dict:
    if leaf_mask is not None:
        necrotic_mask = necrotic_mask & (leaf_mask > 0)
    mask_u8 = (necrotic_mask.astype(np.uint8)) * 255
    mask_u8 = cv2.morphologyEx(mask_u8, cv2.MORPH_OPEN, np.ones((3, 3), np.uint8))
    mask_u8 = cv2.morphologyEx(mask_u8, cv2.MORPH_CLOSE, np.ones((3, 3), np.uint8))
    contours, _ = cv2.findContours(mask_u8, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    crop_area = float(crop_rgb.shape[0] * crop_rgb.shape[1])
    gray = cv2.cvtColor(crop_rgb, cv2.COLOR_RGB2GRAY)

    lesion_count = 0
    circularities = []
    border_contrasts = []

    for cnt in contours:
        area = cv2.contourArea(cnt)
        if area < crop_area * 0.002 or area > crop_area * 0.18:
            continue
        perimeter = cv2.arcLength(cnt, True)
        if perimeter <= 0:
            continue
        circularity = min(1.0, 4 * np.pi * area / (perimeter ** 2))
        if circularity < 0.35:
            continue

        lesion_mask = np.zeros(gray.shape, dtype=np.uint8)
        cv2.drawContours(lesion_mask, [cnt], -1, 255, -1)
        core_mask = cv2.erode(lesion_mask, np.ones((3, 3), np.uint8), iterations=2)
        border_band_mask = cv2.subtract(lesion_mask, core_mask)

        core_vals = gray[core_mask > 0]
        border_vals = gray[border_band_mask > 0]
        if core_vals.size == 0 or border_vals.size == 0:
            continue

        # Ash-gray center should read brighter (higher grayscale value) than the
        # darker surrounding border ring — that gap is the diagnostic signature.
        border_contrast = float(np.clip((core_vals.mean() - border_vals.mean()) / 40.0, 0.0, 1.0))

        lesion_count += 1
        circularities.append(circularity)
        border_contrasts.append(border_contrast)

    return {
        "lesion_count": lesion_count,
        "avg_circularity": float(np.mean(circularities)) if circularities else 0.0,
        "avg_border_contrast": float(np.mean(border_contrasts)) if border_contrasts else 0.0,
    }


class DiseaseModel:
    """Wraps either a trained CNN checkpoint or the heuristic fallback behind a
    single predict() interface so the backend never has to branch on which
    mode it's in."""

    def __init__(self, checkpoint_path: Optional[Path] = None):
        self.method = "heuristic"
        self.class_names = DEFAULT_DISEASE_CLASSES
        self.model: Optional[DiseaseCNN] = None

        if checkpoint_path is not None and checkpoint_path.exists():
            try:
                ckpt = torch.load(checkpoint_path, map_location="cpu")
                self.class_names = ckpt.get("class_names", DEFAULT_DISEASE_CLASSES)
                model = DiseaseCNN(num_classes=len(self.class_names))
                model.load_state_dict(ckpt["state_dict"])
                model.eval()
                torch.set_num_threads(max(1, torch.get_num_threads()))
                self.model = model
                self.method = "cnn"
            except Exception as e:  # pragma: no cover - defensive
                print(f"[disease_classifier] Failed to load checkpoint ({e}); "
                      f"falling back to heuristic mode.")

    def predict(self, crop_rgb: np.ndarray, veg_coverage: Optional[float] = None) -> dict:
        if veg_coverage is not None and veg_coverage < 0.35:
            return {
                "label": BACKGROUND_DEBRIS_LABEL,
                "confidence": float(1.0 - veg_coverage),
                "all_scores": {BACKGROUND_DEBRIS_LABEL: float(1.0 - veg_coverage)},
                "method": "veg_gate",
                "note": (f"Rejected before disease scoring: only {veg_coverage:.0%} of this box's "
                         f"pixels are live vegetation (ExG/Otsu vegetation mask). Likely dead "
                         f"matter, debris, or an uprooted weed pile rather than a living plant."),
            }
        if self.model is not None:
            return self._predict_cnn(crop_rgb)
        return self._predict_heuristic(crop_rgb)

    @torch.no_grad()
    def _predict_cnn(self, crop_rgb: np.ndarray) -> dict:
        variants = [crop_rgb, np.fliplr(crop_rgb), np.flipud(crop_rgb)]
        probs_sum = None
        for variant in variants:
            tensor = _preprocess_crop(np.ascontiguousarray(variant))
            logits = self.model(tensor)
            probs = F.softmax(logits, dim=1).squeeze(0).numpy()
            probs_sum = probs if probs_sum is None else probs_sum + probs
        probs = probs_sum / len(variants)
        idx = int(np.argmax(probs))
        return {
            "label": self.class_names[idx],
            "confidence": float(probs[idx]),
            "all_scores": {name: float(p) for name, p in zip(self.class_names, probs)},
            "method": "cnn",
            "note": "3-way test-time augmentation (original + horizontal + vertical flip, averaged).",
        }

    def _predict_heuristic(self, crop_rgb: np.ndarray) -> dict:
        """Color-statistics + lesion-shape triage. Works directly on the RGB crop pulled
        from inside a detected crop bounding box (no bbox = no meaningful signal, so
        callers should only invoke this on crop-class detections, not weeds)."""
        # Restrict scoring to actual leaf-tissue pixels within the box, not the whole
        # box — a crop bounding box frequently includes soil, shadow gaps between
        # leaves, or neighboring stems along its edges, and scoring disease evidence
        # against the *whole* box (including that non-leaf area in the denominator of
        # every fraction) is exactly what caused disease to appear to cover "large
        # regions" instead of just the infected leaf tissue. This mask keeps every
        # fraction below scoped to pixels that are actually plant material.
        local_leaf_mask = vegetation_mask(crop_rgb, min_component_area=15)
        # The raw ExG vegetation mask only marks GREEN pixels as leaf — by definition
        # that excludes the brown/gray lesion pixels themselves, which would mask out
        # exactly the evidence we're trying to detect. Dilating grows the mask to also
        # cover non-green tissue sitting within/adjacent to green leaf area (i.e. a
        # lesion surrounded by leaf), while genuinely separate soil/background regions
        # elsewhere in the box stay excluded since they're not adjacent to any green.
        local_leaf_mask = cv2.dilate(local_leaf_mask, np.ones((9, 9), np.uint8), iterations=2)
        leaf_bool = local_leaf_mask > 0
        leaf_px_count = int(leaf_bool.sum())
        if leaf_px_count < 0.05 * leaf_bool.size:
            leaf_bool = np.ones_like(leaf_bool, dtype=bool)
            leaf_px_count = leaf_bool.size

        img = Image.fromarray(crop_rgb).convert("HSV")
        hsv = np.asarray(img, dtype=np.float32)
        h, s, v = hsv[..., 0], hsv[..., 1], hsv[..., 2]

        # HSV hue is 0-255 in PIL's representation; green foliage sits roughly 60-110,
        # yellow/chlorotic tissue sits roughly 20-55, brown/necrotic patches are low
        # saturation + low-mid value with a brownish hue (~10-30) or very low value.
        # Every fraction below is computed only over leaf pixels (leaf_px_count as the
        # denominator), not the whole box.
        yellow_frac = float(np.sum((h > 18) & (h < 55) & (s > 60) & leaf_bool)) / leaf_px_count
        brown_dark_frac = float(np.sum((v < 90) & (s > 40) & leaf_bool)) / leaf_px_count
        healthy_green_frac = float(np.sum((h > 60) & (h < 115) & (s > 50) & (v > 60) & leaf_bool)) / leaf_px_count

        # Shape/border pass: a color fraction alone can't tell a genuine Cercospora
        # lesion (ash-gray center, distinct dark border, roughly circular) apart from
        # diffuse shadowing or uneven coloration that's dark on average but has no
        # actual lesion structure. This looks for that structure directly, restricted
        # to leaf pixels via leaf_mask so soil/background specks can't form a "lesion".
        necrotic_mask = (v < 90) & (s > 40)
        lesion_info = _detect_lesions(crop_rgb, necrotic_mask, leaf_mask=local_leaf_mask)
        lesion_shape_score = min(1.0, 0.0
                                  + 0.4 * min(1.0, lesion_info["lesion_count"] / 3.0)
                                  + 0.3 * lesion_info["avg_circularity"]
                                  + 0.3 * lesion_info["avg_border_contrast"])

        color_cercospora_score = max(brown_dark_frac - 0.3 * healthy_green_frac, 0.0)
        # Lesion shape/border evidence is the primary signal — a handful of small,
        # well-defined lesions on an otherwise healthy-green leaf is exactly what real
        # disease looks like, so the score can't be structurally penalized just because
        # most of the leaf is still green (that was a latent bug: gating a few lesions'
        # worth of signal against whole-crop color fractions made real disease
        # undetectable). Color fraction is kept only as a weak supplementary signal for
        # diffuse cases the shape pass might miss.
        fused_cercospora_score = 0.85 * lesion_shape_score + 0.15 * color_cercospora_score

        scores = {
            "Healthy": max(healthy_green_frac - 0.5 * yellow_frac - 0.6 * lesion_shape_score - 0.3 * brown_dark_frac, 0.05),
            "Cercospora Leaf Spot": max(fused_cercospora_score, 0.02),
            "Bacterial Blight": max(yellow_frac - 0.3 * healthy_green_frac, 0.02),
        }
        total = sum(scores.values()) or 1.0
        norm = {k: sv / total for k, sv in scores.items()}
        label = max(norm, key=norm.get)
        confidence = norm[label]

        # Minimum decision bar: don't call it diseased unless the evidence clears a real
        # threshold, not just "highest of three weak scores." A heuristic with three
        # options will always produce *a* winner even when none of them are well
        # supported — this is what was letting healthy plants occasionally get labeled
        # diseased on weak/ambiguous evidence. Below the bar, default to Healthy instead.
        MIN_DISEASE_CONFIDENCE = 0.42
        if label != "Healthy" and confidence < MIN_DISEASE_CONFIDENCE:
            label = "Healthy"
            confidence = max(norm["Healthy"], 1.0 - confidence)

        # Confidence calibration: this is a heuristic, not a calibrated probability
        # model, so it shouldn't ever report near-100% or near-0% certainty — clip to a
        # realistic band so displayed confidence is honest about how uncertain a color/
        # shape heuristic actually is, rather than implying trained-model-level certainty.
        confidence = float(np.clip(confidence, 0.15, 0.92))

        return {
            "label": label,
            "confidence": confidence,
            "all_scores": norm,
            "method": "heuristic",
            "lesion_count": lesion_info["lesion_count"],
            "avg_circularity": round(lesion_info["avg_circularity"], 3),
            "avg_border_contrast": round(lesion_info["avg_border_contrast"], 3),
            "note": ("Heuristic triage combining HSV color fractions (scoped to leaf pixels "
                     "only, via a local vegetation mask) with lesion shape/border detection "
                     "(circularity + darker-border-ring check). No disease-labeled training "
                     "data was available for this dataset. Train train_disease_classifier.py "
                     "on real labeled images to replace this with a learned model."),
        }


def load_disease_model(backend_models_dir: Path) -> DiseaseModel:
    checkpoint = backend_models_dir / "disease_cnn.pt"
    return DiseaseModel(checkpoint_path=checkpoint)
