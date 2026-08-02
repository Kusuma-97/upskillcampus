# SesameVision — CPU-Optimized Weed Detection & Disease Analysis Dashboard

An end-to-end AgTech system: upload a sesame field photo, get weed/crop bounding boxes and
a disease read-out, all running on CPU-only hardware (Raspberry Pi 4 / old laptop / farm PC).

## ⚠️ Important note about the dataset you provided (read this first)

Your `agri_data` dataset (1,300 images, 512×512, YOLO-format labels, `classes.txt` = `crop`,
`weed`) is a **2-class object detection dataset only** — there is no disease label anywhere
in it. The accompanying project doc confirms this: 589 raw photos → cleaned to 546 →
augmented to 1,300 → manually bounding-boxed for `crop` vs `weed`. No disease categories
(Cercospora leaf spot, bacterial blight, etc.) exist in the source data.

So this build does two honest things:

1. **Weed/crop detection is real and fully trainable** on your actual data (`ml_pipeline/train_weed_detector.py`).
   This is a genuine YOLO11n model trained on your 1,300 images, CPU-only.
2. **Disease classification is a real, pluggable module** (`ml_pipeline/disease_classifier.py`,
   a MobileNet-style lightweight CNN) that is trained-ready, but since there's no disease-labeled
   data, it ships in **heuristic mode**: it inspects the pixels inside each detected crop's
   bounding box (HSV chlorosis/necrosis color analysis) to flag likely stress and produce a
   plausible label + confidence. This is clearly flagged as heuristic — not a trained deep model —
   everywhere in the code, API responses (`"method": "heuristic"`), and UI. The moment you
   have real disease-labeled photos (folder-per-class, e.g. `disease_data/healthy/`,
   `disease_data/cercospora/`, `disease_data/bacterial_blight/`), running
   `train_disease_classifier.py` swaps it over to a real trained CNN — no other code changes needed.

This keeps the deliverable genuinely useful and demo-able today, without pretending a model was
trained on data that doesn't exist.

## Project layout

```
sesame-ai-vision/
├── dataset/                       # your original data, untouched
│   ├── agri_data/data/            # 1300 .jpeg + YOLO .txt label pairs
│   └── classes.txt                # crop, weed
├── ml_pipeline/
│   ├── requirements.txt
│   ├── dataset_prep.py            # splits data -> YOLO folder structure + data.yaml
│   ├── preprocessing.py           # CLAHE, auto brightness/contrast, blur-triggered sharpening
│   ├── train_weed_detector.py     # trains YOLO11n on CPU for crop/weed detection
│   ├── disease_classifier.py      # MobileNet-lite CNN + heuristic fallback (shared by backend)
│   ├── quality_filters.py         # vegetation gate, geometric/cluster/confidence filters, focal loss
│   ├── augmentations.py           # Albumentations pipeline (classification + detection)
│   ├── field_validation.py        # field-grouped stratified k-fold + weighted sampler
│   ├── DATA_COLLECTION_BLUEPRINT.md # data collection/annotation/augmentation/validation SOP
│   ├── train_disease_classifier.py# trains the CNN IF you supply real disease-labeled images
│   └── export_cpu_model.py        # exports/optimizes trained weights for fast CPU inference
├── backend/
│   ├── app.py                     # FastAPI: /api/analyze, /api/health, serves the frontend
│   ├── requirements.txt
│   └── models/                    # trained weights land here (weed_detector.pt, disease_cnn.pt)
└── frontend/
    └── index.html                 # standalone dashboard (drag-drop, canvas overlay, analysis panel)
```

## Accuracy improvements (backend-only, no UI/workflow changes)

This pass targeted prediction accuracy specifically — no frontend, API shape, or folder
structure changes; all response fields from before still exist exactly as they were,
with a handful of new optional fields added (never removed/renamed).

- **`ml_pipeline/preprocessing.py` (new)** — auto brightness/contrast correction, CLAHE
  for low-contrast images, and blur-triggered sharpening, applied once per uploaded image
  before detection and disease scoring. Each stage is gated to no-op on already-good
  images, so this only actually changes anything for genuinely poor-condition photos —
  this is what stabilizes predictions across images shot in different field lighting.
- **`ml_pipeline/disease_classifier.py`** — disease scoring is now scoped to actual leaf
  pixels within a box (via a local vegetation mask, dilated to still cover lesion tissue
  itself), not the whole bounding box including any soil/background inside it. This
  directly targets disease being flagged over "large regions" instead of just infected
  leaf area. Added a minimum evidence bar before labeling something diseased (defaults
  to Healthy on weak/ambiguous evidence) and calibrated confidence to a realistic band
  instead of a heuristic ever claiming near-100% certainty.
- **`ml_pipeline/quality_filters.py`** — added `suppress_duplicate_boxes` (same-class NMS
  dedup on the final, already-classified box list) and `resolve_weed_crop_overlap`
  (drops the lower-confidence interpretation when a weed box heavily overlaps a crop
  box), plus an absolute pixel-size floor on the geometric filter and optional
  `label_smoothing` support in `focal_loss`.
- **`backend/app.py`** — applies the new preprocessing step; runs the detector with a
  tighter internal NMS IoU (0.5 vs. Ultralytics' 0.7 default); applies class-wise
  confidence thresholds (weeds held to a higher bar than crops, since background
  vegetation read as a weed was a specifically reported issue); **applies the
  vegetation gate to weed detections too** (previously only crop detections were
  checked — this was a real gap); and runs the new overlap/duplicate resolution as a
  final pass before computing telemetry.
- **Training configs** (`train_weed_detector.py`, `train_disease_classifier.py`) — label
  smoothing, explicit weight decay, a refined cosine LR schedule, a classification-loss
  weight bump on the detector (the reported failures are class-confusion, not box
  localization), and early stopping added to the disease classifier trainer (it
  previously ran the full epoch count regardless of validation plateau).

Every function above was unit-tested against synthetic cases before being wired in —
including a shadowed-healthy-leaf case, a genuine multi-lesion case, a small-lesion-in-a
mostly-soil-box case, a weed-overlapping-crop case, and a full simulated `/api/analyze`
request — rather than just written and assumed correct.

## Building a real disease dataset (replacing the heuristic with a production CNN)

See **`ml_pipeline/DATA_COLLECTION_BLUEPRINT.md`** for the full data collection, annotation,
augmentation, and validation SOP — target visual cues per class (including early- vs.
late-stage Cercospora and deliberate confounder/negative collection), camera/lighting
specs, YOLO vs. COCO annotation rules for overlapping leaf clusters, the balancing +
augmentation pipeline (`ml_pipeline/augmentations.py`, Albumentations-based), and a
field-grouped stratified k-fold validation strategy (`ml_pipeline/field_validation.py`)
that prevents the same field's images from leaking across train/val splits.

## False-positive reduction pipeline (debris/dead matter misclassified as disease)

If you're seeing dead organic matter, uprooted weed piles, or debris getting flagged as
diseased crop, that's now addressed by a dedicated module, `ml_pipeline/quality_filters.py`,
wired into `backend/app.py`:

1. **Vegetation gate** — an ExG (Excess Green Index) + Otsu threshold computed once per
   uploaded image. Any `crop`-class detection whose bounding box has below ~35% live-vegetation
   pixel coverage is routed straight to a `Background/Debris` label *before* it ever reaches
   the disease classifier, instead of forcing a disease guess on dead matter.
2. **Geometric plausibility filter** — rejects boxes with an aspect ratio or area fraction
   that doesn't look like a single plant canopy.
3. **Weed-cluster suppression** — if a `crop_diseased` detection heavily overlaps three or
   more separate weed detections, it's reclassified as debris; this specifically targets
   uprooted weed piles that get fragmented into multiple weed boxes by the detector.
4. **Confidence-margin filter** — rejects a disease classification if the top-1 and top-2
   softmax scores are too close together (default margin: 0.15), instead of trusting a
   flat confidence threshold that a forced closed-set softmax can still pass with high
   "confidence" on out-of-distribution input.
5. **Explicit `Background/Debris` class** — `DEFAULT_DISEASE_CLASSES` now has 4 entries
   instead of 3, so a retrained CNN has somewhere to route uncertainty instead of being
   forced into a disease label. `train_disease_classifier.py` now trains with **focal loss**
   and **inverse-frequency class weights** (`compute_class_weights` / `focal_loss` in
   `quality_filters.py`) specifically because this background class will usually be far more
   numerous than any single disease class — plain cross-entropy would get dominated by it.
   To use this, add a `disease_data/Background_Debris/` folder (dead matter, uprooted piles,
   soil, mulch photos) alongside your disease-class folders before retraining.

Every box the pipeline rejects comes back from `/api/analyze` as `class_name: "debris"`
with a `filter_reason` string explaining which stage caught it, and the response includes
a `pipeline_trace` object (`raw_detections`, `veg_gate_rejected`, `geometric_rejected`,
`weed_cluster_suppressed`, `confidence_margin_rejected`, `final_kept`) so you can audit
what the pipeline is doing on any given image. The dashboard visualizes this as a funnel
in the "False-positive filter pipeline" card, and filtered debris boxes are toggleable
on the canvas via the "Filtered debris" legend chip (off by default).

## Quick start

### 1. Train the weed/crop detector (real model, real data)
```bash
cd ml_pipeline
pip install -r requirements.txt
python dataset_prep.py                 # builds ml_pipeline/yolo_dataset/{train,val}
python train_weed_detector.py          # CPU training, ~1-3 hrs on a laptop CPU for 60 epochs
```
Trained weights land at `ml_pipeline/runs/detect/sesame_weed_cpu/weights/best.pt`.
Copy/rename it into `backend/models/weed_detector.pt` (the training script does this for you).

### 2. (Optional) Train the disease classifier on real data
Only do this once you have real labeled disease photos:
```
ml_pipeline/disease_data/
  healthy/         *.jpg
  cercospora/       *.jpg
  bacterial_blight/ *.jpg
```
```bash
python train_disease_classifier.py
```
This produces `backend/models/disease_cnn.pt`. If this file doesn't exist, the backend
automatically falls back to the color-heuristic disease detector — no crash, no silent lies,
it just labels its output as heuristic.

### 3. Run the backend
```bash
cd ../backend
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 4. Open the frontend
Just open `frontend/index.html` in a browser — it works standalone with a built-in mock
detector (so you can interact with it immediately with zero backend), and also has a "Live
backend" toggle that points at `http://localhost:8000/api/analyze` once step 3 is running.

## Why these architecture choices (CPU-first)

- **YOLO11n** — the nano variant (~2.6M params) is the lightest Ultralytics detector; on CPU it
  hits usable inference latency (150-400ms/image on a 4-core laptop CPU) and trains in hours,
  not days, on 1,300 images at low batch size.
- **MobileNet-lite disease CNN** — depthwise-separable convolutions keep FLOPs low; the whole
  network is <1M params so it runs in <50ms per crop-crop on CPU.
- **Batch size 8, image size 512→416**, AMP disabled (CPU has no AMP benefit), `workers=2`,
  `device='cpu'` explicitly everywhere, gradient accumulation available for stability at low
  batch size.
- **Quantization-ready** — `export_cpu_model.py` shows how to apply dynamic INT8 quantization
  to the disease CNN for another 2-4x CPU inference speedup on edge devices.
