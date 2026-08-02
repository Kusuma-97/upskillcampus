"""
app.py — SesameVision backend
------------------------------
FastAPI service that:
  1. Accepts an uploaded field image.
  2. Runs the CPU-bound YOLO11n weed/crop detector (backend/models/weed_detector.pt).
  3. For every detected "crop" box, runs the disease classifier (real CNN if trained,
     otherwise the clearly-labeled heuristic — see ml_pipeline/disease_classifier.py)
     on the cropped region.
  4. Computes simple field telemetry (percent area infested by weeds, percent of crop
     area showing disease signals, an estimated pesticide-saved figure from targeted
     spraying vs. blanket spraying).
  5. Returns everything as JSON for the frontend to render.

Run:
    uvicorn app:app --host 0.0.0.0 --port 8000
"""

import io
import sys
import time
from pathlib import Path
from typing import List

import numpy as np
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image
from pydantic import BaseModel

# Make ml_pipeline importable (shared disease_classifier module lives there)
THIS_DIR = Path(__file__).resolve().parent
ROOT_DIR = THIS_DIR.parent
sys.path.insert(0, str(ROOT_DIR / "ml_pipeline"))

from disease_classifier import load_disease_model  # noqa: E402
from preprocessing import enhance_image  # noqa: E402
from quality_filters import (  # noqa: E402
    BACKGROUND_DEBRIS_LABEL,
    vegetation_mask,
    vegetation_coverage,
    is_geometrically_plausible,
    suppress_near_weed_cluster,
    passes_confidence_margin,
    suppress_duplicate_boxes,
    resolve_weed_crop_overlap,
)

MODELS_DIR = THIS_DIR / "models"
FRONTEND_DIR = ROOT_DIR / "frontend"

# CPU-only inference tuning: cap intra-op threads so the API stays responsive
# under concurrent requests instead of one request hogging every core.
import torch  # noqa: E402
torch.set_num_threads(max(1, (torch.get_num_threads())))

app = FastAPI(title="SesameVision API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this to your farm-dashboard origin in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Model loading (lazy singletons, loaded once at startup, CPU-only)
# ---------------------------------------------------------------------------
CLASS_COLORS = {
    "weed": "#EF4444",              # red
    "crop_healthy": "#22C55E",      # green
    "crop_diseased": "#F59E0B",     # amber
    "debris": "#94A3B8",            # slate — filtered out before/after disease scoring
}

VEG_COVERAGE_THRESHOLD = 0.35
CONFIDENCE_MARGIN_THRESHOLD = 0.15
WEED_CLUSTER_IOU_THRESHOLD = 0.15
WEED_CLUSTER_MIN_OVERLAPS = 3

# Class-wise confidence floors: weeds get a slightly higher bar than crops because
# background vegetation being misread as a weed was a specifically reported failure
# mode, and a raised class-specific threshold directly cuts that without also raising
# the bar (and losing recall) on crop detections, which don't have the same problem.
CLASS_CONF_THRESHOLDS = {"weed": 0.45, "crop": 0.40}
DUPLICATE_IOU_THRESHOLD = 0.5          # same-class overlapping-box dedup
WEED_CROP_OVERLAP_IOU_THRESHOLD = 0.45  # weed box drawn on top of a crop box

_weed_detector = None
_weed_detector_error = None
_disease_model = load_disease_model(MODELS_DIR)


def get_weed_detector():
    global _weed_detector, _weed_detector_error
    if _weed_detector is not None or _weed_detector_error is not None:
        return _weed_detector

    weights_path = MODELS_DIR / "weed_detector.pt"
    if not weights_path.exists():
        _weed_detector_error = (
            "No trained weed detector found at backend/models/weed_detector.pt. "
            "Run ml_pipeline/dataset_prep.py then train_weed_detector.py first."
        )
        return None

    try:
        from ultralytics import YOLO
        model = YOLO(str(weights_path))
        _weed_detector = model
    except Exception as e:  # pragma: no cover - defensive
        _weed_detector_error = f"Failed to load weed detector: {e}"
    return _weed_detector


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------
class BoxResult(BaseModel):
    x1: float
    y1: float
    x2: float
    y2: float
    class_name: str            # "weed" | "crop_healthy" | "crop_diseased" | "debris"
    color: str
    detection_confidence: float
    disease_label: str | None = None
    disease_confidence: float | None = None
    disease_method: str | None = None  # "cnn" | "heuristic" | "veg_gate"
    filter_reason: str | None = None   # set when this box was downgraded/rejected by a quality filter
    veg_coverage: float | None = None


class PipelineTrace(BaseModel):
    raw_detections: int
    veg_gate_rejected: int
    geometric_rejected: int
    weed_cluster_suppressed: int
    confidence_margin_rejected: int
    final_kept: int
    class_conf_rejected: int = 0
    weed_veg_rejected: int = 0
    duplicate_suppressed: int = 0
    weed_crop_overlap_resolved: int = 0


class Telemetry(BaseModel):
    image_width: int
    image_height: int
    num_weeds: int
    num_crops: int
    num_diseased_crops: int
    num_debris_filtered: int
    weed_area_pct: float
    diseased_crop_area_pct: float
    estimated_pesticide_saved_pct: float
    inference_time_ms: float


class AnalyzeResponse(BaseModel):
    boxes: List[BoxResult]
    telemetry: Telemetry
    pipeline_trace: PipelineTrace
    model_status: dict


# ---------------------------------------------------------------------------
# Telemetry helpers
# ---------------------------------------------------------------------------
def box_area(x1, y1, x2, y2) -> float:
    return max(0.0, x2 - x1) * max(0.0, y2 - y1)


def compute_telemetry(boxes: list[dict], img_w: int, img_h: int, inference_ms: float) -> Telemetry:
    total_area = float(img_w * img_h)
    weed_boxes = [b for b in boxes if b["class_name"] == "weed"]
    crop_boxes = [b for b in boxes if b["class_name"] in ("crop_healthy", "crop_diseased")]
    diseased_boxes = [b for b in boxes if b["class_name"] == "crop_diseased"]
    debris_boxes = [b for b in boxes if b["class_name"] == "debris"]

    weed_area = sum(box_area(b["x1"], b["y1"], b["x2"], b["y2"]) for b in weed_boxes)
    diseased_area = sum(box_area(b["x1"], b["y1"], b["x2"], b["y2"]) for b in diseased_boxes)

    weed_area_pct = 100.0 * weed_area / total_area if total_area else 0.0
    diseased_area_pct = 100.0 * diseased_area / total_area if total_area else 0.0

    # Targeted spraying (spray only the weed_area) vs. blanket spraying the whole field:
    # pesticide saved = 1 - (targeted area / total area), floored at 0.
    pesticide_saved_pct = max(0.0, 100.0 * (1.0 - (weed_area / total_area))) if total_area else 0.0

    return Telemetry(
        image_width=img_w,
        image_height=img_h,
        num_weeds=len(weed_boxes),
        num_crops=len(crop_boxes),
        num_diseased_crops=len(diseased_boxes),
        num_debris_filtered=len(debris_boxes),
        weed_area_pct=round(weed_area_pct, 2),
        diseased_crop_area_pct=round(diseased_area_pct, 2),
        estimated_pesticide_saved_pct=round(pesticide_saved_pct, 2),
        inference_time_ms=round(inference_ms, 1),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    detector = get_weed_detector()
    return {
        "status": "ok",
        "weed_detector_loaded": detector is not None,
        "weed_detector_error": _weed_detector_error,
        "disease_model_method": _disease_model.method,
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(file: UploadFile = File(...), accurate_mode: bool = False):
    if file.content_type not in ("image/jpeg", "image/png", "image/jpg", "image/webp"):
        raise HTTPException(status_code=400, detail="Please upload a JPEG, PNG, or WEBP image.")

    raw = await file.read()
    try:
        pil_img = Image.open(io.BytesIO(raw)).convert("RGB")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode the uploaded image.")

    img_w, img_h = pil_img.size
    img_np = np.array(pil_img)
    # Preprocessing: auto brightness/contrast correction, CLAHE for low-contrast images,
    # and sharpening for blurry images — each gated to no-op on already-good images (see
    # ml_pipeline/preprocessing.py). This is what stabilizes predictions across images
    # shot in different field lighting instead of the model/heuristic seeing wildly
    # different pixel statistics for what is otherwise the same underlying scene.
    img_np = enhance_image(img_np)

    detector = get_weed_detector()
    if detector is None:
        raise HTTPException(
            status_code=503,
            detail=_weed_detector_error or "Weed detector model is not available.",
        )

    start = time.time()
    # accurate_mode=True enables Ultralytics' built-in test-time augmentation (inference
    # run on flipped/multi-scale versions of the image with predictions merged), which
    # trades roughly 2-3x CPU latency for a real mAP improvement — worth it for a one-off
    # careful scan, not worth it for a live/continuous feed, hence it's a toggle rather
    # than always-on. iou=0.5 (tighter than Ultralytics' 0.7 default) suppresses more
    # overlapping raw boxes for the same object at the detector level, directly reducing
    # the "multiple overlapping boxes" symptom before any of our own post-processing runs.
    results = detector.predict(
        img_np, device="cpu", imgsz=416, conf=0.25, iou=0.5, verbose=False,
        augment=accurate_mode,
    )
    result = results[0]

    veg_mask = vegetation_mask(img_np)

    raw_detections = []
    names = result.names  # {0: 'crop', 1: 'weed'}
    total_yolo_boxes = len(result.boxes)
    class_conf_rejected = 0
    for box in result.boxes:
        cls_idx = int(box.cls.item())
        conf = float(box.conf.item())
        raw_class = names.get(cls_idx, str(cls_idx))
        # Class-wise confidence floor (see CLASS_CONF_THRESHOLDS): the detector is run
        # at a low global conf=0.25 above so weak-but-real small/partially-occluded
        # detections aren't thrown away before we get a chance to evaluate them
        # per-class here, rather than a single global cutoff being either too strict
        # for one class or too lax for the other.
        if conf < CLASS_CONF_THRESHOLDS.get(raw_class, 0.35):
            class_conf_rejected += 1
            continue
        x1, y1, x2, y2 = [float(v) for v in box.xyxy[0].tolist()]
        raw_detections.append({
            "raw_class": raw_class,
            "conf": conf,
            "x1": x1, "y1": y1, "x2": x2, "y2": y2,
        })

    trace = {
        "raw_detections": total_yolo_boxes,
        "veg_gate_rejected": 0,
        "geometric_rejected": 0,
        "weed_cluster_suppressed": 0,
        "confidence_margin_rejected": 0,
        "class_conf_rejected": class_conf_rejected,
        "weed_veg_rejected": 0,
    }

    weed_boxes_xyxy = [(d["x1"], d["y1"], d["x2"], d["y2"]) for d in raw_detections if d["raw_class"] == "weed"]

    boxes_out = []
    for d in raw_detections:
        x1, y1, x2, y2 = d["x1"], d["y1"], d["x2"], d["y2"]

        if not is_geometrically_plausible((x1, y1, x2, y2), img_w, img_h):
            trace["geometric_rejected"] += 1
            boxes_out.append({
                "x1": x1, "y1": y1, "x2": x2, "y2": y2,
                "class_name": "debris",
                "color": CLASS_COLORS["debris"],
                "detection_confidence": d["conf"],
                "disease_label": None, "disease_confidence": None, "disease_method": None,
                "filter_reason": "geometrically implausible shape/size for a single plant",
                "veg_coverage": None,
            })
            continue

        if d["raw_class"] == "weed":
            # Previously weed boxes skipped vegetation gating entirely — only crop boxes
            # were checked. That gap is exactly how background vegetation or bare ground
            # with a vaguely plant-like shape could get labeled a weed. Apply the same
            # live-vegetation coverage check here.
            coverage = vegetation_coverage((x1, y1, x2, y2), veg_mask)
            if coverage < VEG_COVERAGE_THRESHOLD:
                trace["weed_veg_rejected"] += 1
                boxes_out.append({
                    "x1": x1, "y1": y1, "x2": x2, "y2": y2,
                    "class_name": "debris",
                    "color": CLASS_COLORS["debris"],
                    "detection_confidence": d["conf"],
                    "disease_label": None, "disease_confidence": None, "disease_method": None,
                    "filter_reason": f"low live-vegetation coverage ({coverage:.0%}) for a weed detection",
                    "veg_coverage": round(coverage, 3),
                })
                continue
            boxes_out.append({
                "x1": x1, "y1": y1, "x2": x2, "y2": y2,
                "class_name": "weed",
                "color": CLASS_COLORS["weed"],
                "detection_confidence": d["conf"],
                "disease_label": None, "disease_confidence": None, "disease_method": None,
                "filter_reason": None,
                "veg_coverage": round(coverage, 3),
            })
            continue

        coverage = vegetation_coverage((x1, y1, x2, y2), veg_mask)
        xi1, yi1 = max(0, int(x1)), max(0, int(y1))
        xi2, yi2 = min(img_w, int(x2)), min(img_h, int(y2))
        crop_np = img_np[yi1:yi2, xi1:xi2]

        if crop_np.size == 0:
            disease = {"label": "Healthy", "confidence": 0.5, "method": "heuristic", "all_scores": {}}
        else:
            disease = _disease_model.predict(crop_np, veg_coverage=coverage)

        if disease["method"] == "veg_gate":
            trace["veg_gate_rejected"] += 1
            boxes_out.append({
                "x1": x1, "y1": y1, "x2": x2, "y2": y2,
                "class_name": "debris",
                "color": CLASS_COLORS["debris"],
                "detection_confidence": d["conf"],
                "disease_label": disease["label"], "disease_confidence": disease["confidence"],
                "disease_method": disease["method"],
                "filter_reason": disease.get("note", "low live-vegetation coverage"),
                "veg_coverage": round(coverage, 3),
            })
            continue

        all_scores = list(disease.get("all_scores", {}).values())
        if all_scores and not passes_confidence_margin(all_scores, min_margin=CONFIDENCE_MARGIN_THRESHOLD):
            trace["confidence_margin_rejected"] += 1
            boxes_out.append({
                "x1": x1, "y1": y1, "x2": x2, "y2": y2,
                "class_name": "debris",
                "color": CLASS_COLORS["debris"],
                "detection_confidence": d["conf"],
                "disease_label": disease["label"], "disease_confidence": disease["confidence"],
                "disease_method": disease["method"],
                "filter_reason": "ambiguous — top two disease scores too close to trust",
                "veg_coverage": round(coverage, 3),
            })
            continue

        is_diseased = disease["label"] not in ("Healthy", BACKGROUND_DEBRIS_LABEL)

        if is_diseased and not suppress_near_weed_cluster(
            (x1, y1, x2, y2), weed_boxes_xyxy,
            iou_thresh=WEED_CLUSTER_IOU_THRESHOLD, cluster_min=WEED_CLUSTER_MIN_OVERLAPS,
        ):
            trace["weed_cluster_suppressed"] += 1
            boxes_out.append({
                "x1": x1, "y1": y1, "x2": x2, "y2": y2,
                "class_name": "debris",
                "color": CLASS_COLORS["debris"],
                "detection_confidence": d["conf"],
                "disease_label": disease["label"], "disease_confidence": disease["confidence"],
                "disease_method": disease["method"],
                "filter_reason": "heavily overlaps a weed cluster — likely an uprooted pile, not a diseased plant",
                "veg_coverage": round(coverage, 3),
            })
            continue

        boxes_out.append({
            "x1": x1, "y1": y1, "x2": x2, "y2": y2,
            "class_name": "crop_diseased" if is_diseased else "crop_healthy",
            "color": CLASS_COLORS["crop_diseased" if is_diseased else "crop_healthy"],
            "detection_confidence": d["conf"],
            "disease_label": disease["label"],
            "disease_confidence": disease["confidence"],
            "disease_method": disease["method"],
            "filter_reason": None,
            "veg_coverage": round(coverage, 3),
        })

    trace["final_kept"] = sum(1 for b in boxes_out if b["class_name"] != "debris")

    # Final post-processing pass: resolve weed-boxes-on-top-of-crops first (cross-class),
    # then dedupe any remaining same-class overlapping boxes (e.g. two overlapping
    # crop_diseased boxes for what's really one leaf). Both operate on the already
    # class-assigned box list, which is where these overlaps actually showed up —
    # Ultralytics' internal NMS only dedupes within its own raw crop/weed output, not
    # after we've reclassified some of those boxes to crop_healthy/crop_diseased/debris.
    boxes_out, weed_crop_overlap_resolved = resolve_weed_crop_overlap(
        boxes_out, iou_thresh=WEED_CROP_OVERLAP_IOU_THRESHOLD,
    )
    boxes_out, duplicate_suppressed = suppress_duplicate_boxes(
        boxes_out, iou_thresh=DUPLICATE_IOU_THRESHOLD,
    )
    trace["weed_crop_overlap_resolved"] = weed_crop_overlap_resolved
    trace["duplicate_suppressed"] = duplicate_suppressed
    trace["final_kept"] = sum(1 for b in boxes_out if b["class_name"] != "debris")

    inference_ms = (time.time() - start) * 1000.0
    telemetry = compute_telemetry(boxes_out, img_w, img_h, inference_ms)

    return AnalyzeResponse(
        boxes=[BoxResult(**b) for b in boxes_out],
        telemetry=telemetry,
        pipeline_trace=PipelineTrace(**trace),
        model_status={
            "weed_detector": "loaded",
            "disease_model_method": _disease_model.method,
            "accurate_mode": accurate_mode,
        },
    )


# Serve the standalone frontend so the whole app can run from one process too.
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def index():
        index_path = FRONTEND_DIR / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        return {"message": "SesameVision API is running. See /docs for the API."}
