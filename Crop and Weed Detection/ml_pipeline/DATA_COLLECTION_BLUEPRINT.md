# Disease Detection Dataset Blueprint
### Replacing the color-heuristic classifier with a production-grade CNN

This document specifies exactly what to collect, how to annotate it, how to augment and
balance it, and how to validate the resulting model, for the three target classes:
**Cercospora Leaf Spot**, **Healthy Crop**, **Weeds**. It's written to plug directly into
`ml_pipeline/train_disease_classifier.py` and the `Background/Debris` class already added
to `disease_classifier.py` — treat this as the data-collection SOP that feeds that pipeline.

---

## 1. Target classes & visual cues

### 1.1 Cercospora Leaf Spot

**Early-stage lesions (capture explicitly — this is the class boundary that matters most):**
- Pinpoint to 1-3mm circular/oval spots, light tan to reddish-brown, often with a faint
  chlorotic (yellow) halo just beginning to form.
- Sparse distribution: typically <5% of total leaf area affected, usually starting on
  older/lower canopy leaves first.
- No visible gray center yet — this is what separates early-stage from late-stage, and it's
  the stage most likely to be confused with healthy leaf texture or insect stipple damage.
  Capture at least 150-200 early-stage examples per field site; this stage is chronically
  under-collected because it's visually subtle, which is exactly why it needs deliberate effort.

**Late-stage lesions:**
- Spots enlarge to 3-10mm, coalescing into irregular necrotic patches.
- Diagnostic signature: **ash-gray to tan necrotic center** with a **distinct dark
  brown-to-purple border**, sometimes with faint concentric "target" rings.
- Surrounding chlorotic (yellowing) halo, often followed by leaf curling and premature
  drop in severe cases.
- Photograph both leaf surfaces — sporulation (a fine grayish fungal bloom) is frequently
  more visible on the abaxial (underside) surface under humid conditions, and a model
  trained only on top-surface photos will miss this cue in the field.

**Severity tagging:** log a severity estimate per leaf with every image — early (1-10%
coverage), moderate (10-25%), severe (>25%) — as metadata even if you're training a flat
classifier now. It costs nothing to capture and lets you build an ordinal severity model
later without recollecting data.

**Deliberate confounder/negative collection (this is the step most datasets skip, and it's
the single biggest lever against false positives):** collect explicit examples of things
that *look* like disease but aren't, and label them `Healthy` or a dedicated `Other_Stress`
class rather than leaving them unlabeled: natural senescence yellowing at maturity, nutrient
deficiency chlorosis, sunscald, insect feeding holes, mechanical/hail damage, water-stress
necrosis. Without these as explicit negatives, the model learns "any dark spot = disease"
instead of the actual lesion morphology — the same failure mode that caused the
debris-as-disease false positives you already fixed at the pipeline level; fixing it here
closes the loop at the data level too.

### 1.2 Healthy Crop

- Capture across the **full diurnal lighting range** the model will see in deployment:
  morning (cool blue-toned light), midday (harsh direct sun, sharp shadows), late afternoon
  (warm golden light), and overcast (diffuse, most color-accurate). This is what the model
  needs to be invariant to — collecting only midday photos is the most common healthy-class
  data gap.
- Capture across growth stages (seedling, vegetative, flowering, maturity) since sesame leaf
  morphology and canopy density change substantially across the season.
- **Deliberately include partially-shadowed healthy leaves.** Shadow-darkened healthy tissue
  is one of the most common sources of disease false positives (low brightness reads as
  "necrotic" to both heuristic and naively-trained models) — the model needs positive
  examples of "this is dark because of shadow, not because it's diseased."

### 1.3 Weeds

- Identify and separately tag the actual weed species present in your fields — broadleaf
  and grassy weeds have different diagnostic cues and benefit from being distinguishable
  even if collapsed into one `weed` class at training time:
  - **Grassy weeds**: parallel venation, narrow upright blades, tufted growth habit.
  - **Broadleaf weeds**: net (reticulate) venation, varied leaf shapes, often lower/spreading habit.
- Capture weeds at multiple **heights relative to the crop canopy**: below canopy
  (partially occluded by crop), at-canopy height, and overtopping the canopy — height
  relative to crop is itself a strong detection signal your current model isn't using yet.
- Capture both intermixed-with-crop (realistic field density, partial occlusion) and
  isolated-against-soil framings.
- **Edge/shape emphasis for segmentation quality**: shoot dedicated macro close-ups of leaf
  margins (serrated, lobed, entire) on a tripod at a fixed focal length — segmentation mask
  quality is bottlenecked by edge sharpness, and handheld macro shots are usually too motion-
  blurred at the leaf margin to produce a clean polygon boundary.

---

## 2. Imaging compliance & quality control

### 2.1 Resolution & distance

| Capture type | Distance | Source resolution | Purpose |
|---|---|---|---|
| Macro leaf/lesion close-up | 15-30cm from a single leaf, lesion fills >60% of frame | ≥12MP (4000×3000) | Disease classification/segmentation training crops |
| Canopy-level wide scan | 1-2m handheld/mast-mounted, or drone at 3-5m AGL | ≥12MP | Field-scale crop/weed detection (matches your existing 512×512 dataset's geometry) |

Rule of thumb for lesion visibility: at your final training resolution, a lesion should
occupy **at least ~20px in diameter** — if it's smaller than that after resizing, either
shoot closer or tile the source image instead of downsampling it directly.

For canopy scans, shoot **nadir** (camera perpendicular to the ground, ±5°) to keep
geometry consistent across the dataset — oblique angles introduce perspective distortion
that makes bounding-box area a less reliable proxy for real-world coverage (which matters
for your telemetry calculations downstream).

### 2.2 Lighting

- **Prefer overcast, diffuse light** — even cloud cover with no visible sun disc. This is
  the single highest-leverage capture condition: it minimizes both hard shadows (which
  create false "necrotic" dark regions) and specular leaf glare (which blows out the
  chlorotic yellow signal you need for disease detection).
- If direct sun is unavoidable, shoot during low solar elevation (morning/late afternoon,
  sun angle <45°) and use a diffuser or handheld shade for macro shots.
- Avoid artificial high-contrast backdrops for macro shots — use the natural soil/canopy
  background but frame so it occupies a minority of the pixels in classification crops.
- Fix white balance to a daylight preset for the whole capture session — **do not use
  auto white balance** — since hue-based disease cues (the yellow chlorotic halo, the
  brown/purple lesion border) need to stay numerically consistent across images for
  the HSV-based heuristic fallback and for early-training-stage sanity checks.
- A circular polarizing filter is worth the cost — it meaningfully cuts leaf-surface
  glare that otherwise gets misread as a lesion highlight.

### 2.3 Metadata (log this per image, not per session)

GPS field/plot ID, timestamp, growth stage, weather condition, camera distance and angle.
Field/plot ID in particular is required for the stratified validation strategy in §4 — if
you don't log it now, you cannot retrofit a leakage-free validation split later.

### 2.4 Annotation standard

**Two annotation layers, used for different purposes — don't try to make one format do both jobs:**

1. **Object/plant-level detection — YOLO format, tight axis-aligned bounding boxes.**
   Used for whole-plant crop/weed localization (this is what your existing
   `weed_detector.pt` already does). Box drawn to the tightest fit around the visible
   plant/leaf extent. Run an inter-annotator agreement audit on a 10% double-annotated
   sample, requiring pairwise IoU > 0.85; anything below that gets adjudicated.

2. **Lesion/leaf-instance segmentation — COCO polygon format.**
   Used for the macro close-up subset where individual lesions need to be separated as
   instances, and where overlapping leaves at canopy level need distinct masks rather
   than one bounding box covering several plants.

**Overlapping-leaf-cluster rule (this is the specific rule requested, and it matters):**
When leaves overlap or occlude each other, annotate only the **visible (unoccluded)
portion** of each leaf as its own polygon instance — the standard COCO "modal mask"
convention. Do not extend a mask under an occluding leaf to guess at the hidden shape.
If a single lesion is visually split by an occlusion boundary but is clearly one lesion,
annotate it as one instance; if it's ambiguous whether it's one lesion or two, annotate
separately and flag for review rather than guessing.

**Recommended hierarchy to avoid the "tiny-spot bounding box" trap:** annotate at the
leaf-instance level first (polygon mask), then attach a `disease_status` attribute
(healthy / cercospora / other_stress) to each leaf instance. Reserve true lesion-level
polygons for the dedicated macro close-up subset only — trying to box individual 2-3mm
spots inside a whole-plant detector is where most "conflicting annotation" problems
originate, because annotators disagree on where one lesion ends and another begins at
that scale, especially in coalesced late-stage patches.

**QA process:** every image double-annotated, adjudicated by a third annotator on
disagreements exceeding a 15% mask-IoU delta. Maintain a separate "ambiguous/rejected"
bucket for early-early-stage images where the visual cues are genuinely borderline —
better to exclude a few hundred ambiguous images than inject label noise that the model
will learn as a real pattern.

---

## 3. Data balancing & augmentation pipeline

### 3.1 Balancing strategy

Healthy crop images will vastly outnumber disease images in raw field collection — this is
expected and shouldn't be "fixed" by throwing away healthy data. Instead:

- Set a **minimum per-class instance target** (500-1000 labeled instances per disease
  class is a reasonable floor before a CNN generalizes reliably) and treat data collection
  as incomplete until each disease class hits it, even if that means multiple collection
  trips specifically targeting infected plots.
- **Oversample minority classes at the sampler level**, not by duplicating raw files —
  use a `WeightedRandomSampler` (see code below) so each epoch sees disease examples
  proportionally more often, with augmentation providing the actual pixel-level variation
  (duplicating identical images without augmentation just causes overfitting to those
  exact images).
- Combine with **focal loss + inverse-frequency class weighting** — already implemented in
  this project's `ml_pipeline/quality_filters.py` (`focal_loss`, `compute_class_weights`) and
  wired into `train_disease_classifier.py`. The blueprint here is what feeds that pipeline
  with properly distributed data; the loss function alone can't compensate for a dataset
  with zero examples of a class's early-stage presentation.
- **Advanced/optional — synthetic lesion compositing**: cut-and-paste real lesion crops
  onto healthy leaf backgrounds to synthetically boost minority-class volume. This works,
  but treat it as a last resort after real collection is exhausted, not a first resort —
  composited lesions can introduce subtle blending artifacts (edge halos, lighting
  mismatches) that a CNN can learn to key on instead of the actual lesion morphology,
  which would reintroduce a version of the exact false-positive problem this whole
  pipeline exists to fix. If you use it, validate exclusively on real (non-composited)
  images to catch this failure mode.

### 3.2 Augmentation pipeline (Albumentations)

Saved as `ml_pipeline/augmentations.py` in this project — see that file for the runnable
version wired to both classification crops and detection/segmentation bounding boxes/masks.

```python
import albumentations as A
from albumentations.pytorch import ToTensorV2

def build_train_transform(image_size=224):
    return A.Compose([
        A.RandomResizedCrop(size=(image_size, image_size), scale=(0.75, 1.0), ratio=(0.85, 1.15)),
        A.HorizontalFlip(p=0.5),
        A.VerticalFlip(p=0.3),
        A.RandomRotate90(p=0.5),
        A.ShiftScaleRotate(shift_limit=0.06, scale_limit=0.1, rotate_limit=20, border_mode=0, p=0.6),
        A.OneOf([
            A.RandomBrightnessContrast(brightness_limit=0.25, contrast_limit=0.25, p=1.0),
            A.RandomGamma(gamma_limit=(80, 120), p=1.0),
        ], p=0.8),
        A.HueSaturationValue(hue_shift_limit=8, sat_shift_limit=25, val_shift_limit=15, p=0.6),
        A.OneOf([
            A.GaussianBlur(blur_limit=(3, 5), p=1.0),
            A.MotionBlur(blur_limit=5, p=1.0),
        ], p=0.25),
        A.GaussNoise(std_range=(0.02, 0.08), p=0.25),
        A.RandomShadow(shadow_roi=(0, 0.4, 1, 1), num_shadows_limit=(1, 2), p=0.25),
        A.CoarseDropout(num_holes_range=(1, 4), hole_height_range=(0.03, 0.08),
                         hole_width_range=(0.03, 0.08), fill=0, p=0.3),
        A.Normalize(mean=(0.485, 0.456, 0.406), std=(0.229, 0.224, 0.225)),
        ToTensorV2(),
    ])


def build_val_transform(image_size=224):
    return A.Compose([
        A.Resize(height=image_size, width=image_size),
        A.Normalize(mean=(0.485, 0.456, 0.406), std=(0.229, 0.224, 0.225)),
        ToTensorV2(),
    ])


def build_detection_train_transform(image_size=416):
    return A.Compose([
        A.HorizontalFlip(p=0.5),
        A.RandomBrightnessContrast(brightness_limit=0.2, contrast_limit=0.2, p=0.7),
        A.HueSaturationValue(hue_shift_limit=6, sat_shift_limit=20, val_shift_limit=12, p=0.5),
        A.GaussianBlur(blur_limit=(3, 5), p=0.15),
        A.Resize(height=image_size, width=image_size),
    ], bbox_params=A.BboxParams(format="yolo", label_fields=["class_labels"], min_visibility=0.3))
```

Notes on each augmentation and why it's in the pipeline:
- **RandomShadow** specifically simulates the variable field lighting condition called out
  in the spec — partial cloud cover, canopy self-shadowing — which is also exactly the
  condition most likely to produce false-positive "necrotic" readings if the model isn't
  trained to see through it.
- **CoarseDropout** simulates partial occlusion (overlapping leaves, insect damage, camera
  obstruction) so the model doesn't require the entire lesion visible to classify correctly.
- **HueSaturationValue** is kept moderate (not extreme) — disease diagnosis is
  color-dependent, so this should simulate realistic lighting-condition color drift, not
  scramble the hue signal the model actually needs to learn from.
- `min_visibility=0.3` in the detection transform drops bounding boxes that get cropped
  below 30% visible area after augmentation, rather than keeping a near-invisible box with
  a stale label.

### 3.3 Weighted sampler (pairs with the augmentation pipeline above)

```python
import numpy as np
from torch.utils.data import WeightedRandomSampler

def build_weighted_sampler(class_counts, sample_labels):
    class_weights = 1.0 / np.array(class_counts, dtype=np.float64)
    sample_weights = class_weights[sample_labels]
    return WeightedRandomSampler(
        weights=sample_weights,
        num_samples=len(sample_labels),
        replacement=True,
    )
```

---

## 4. Validation framework

### 4.1 Stratified, field-grouped k-fold

The critical rule: **images from the same field/plot must never appear in both the train
and validation split of the same fold.** Near-duplicate images from the same field (same
lighting rig, same soil background, same plant genetics) will leak information and inflate
validation metrics if split randomly — the model ends up memorizing field-specific
background texture rather than learning generalizable disease morphology, and you won't
find out until it fails on a genuinely new field.

Use `StratifiedGroupKFold` (scikit-learn), grouping by field/plot ID (logged per §2.3) and
stratifying by class label so each fold retains a representative class balance:

```python
from sklearn.model_selection import StratifiedGroupKFold

def build_field_grouped_folds(labels, groups, n_splits=5, seed=42):
    skf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    return list(skf.split(X=np.zeros(len(labels)), y=labels, groups=groups))
```

### 4.2 What to report per fold

- mAP50-95 for detection, mask AP for segmentation.
- **Per-class precision/recall, with special attention to disease-class recall** — a model
  that's 95% accurate overall but misses 40% of early-stage Cercospora is not production-ready,
  since early detection is the entire point of the system.
- **False-positive rate against a held-out debris/dead-matter negative set** — an explicit
  sanity check tying back to the false-positive-reduction pipeline already built into
  `backend/app.py`; this dataset should include a dedicated `Background_Debris` validation
  split even though it's not part of the k-fold class stratification, specifically to
  catch regressions in the debris-vs-disease boundary as the model is retrained over time.
- Report **mean ± standard deviation across folds**, not just a single best-fold number —
  high variance across folds is itself a signal that the dataset doesn't yet have enough
  field diversity, independent of the mean score.

### 4.3 True holdout: unseen-field test set

Reserve 1-2 entire fields that are **never** used in training or k-fold validation at all
— not even for hyperparameter tuning. Evaluate on this set exactly once, after the model
is finalized from the k-fold results. This is the only number that actually estimates
real-world generalization to a new field; repeatedly tuning against a validation set
(even a well-constructed k-fold one) causes gradual overfitting to that specific set of
fields through the tuning process itself.

### 4.4 Optional: temporal validation split

Since Cercospora presentation changes across the crop lifecycle (early sparse spotting
early season, coalesced late-stage lesions later), consider an additional temporal split
— train on early-to-mid-season images, validate on late-season images from the same
fields — to explicitly check whether the model generalizes across disease progression
stages, not just across field locations. This is a secondary check, not a replacement
for the field-grouped k-fold in §4.1.
