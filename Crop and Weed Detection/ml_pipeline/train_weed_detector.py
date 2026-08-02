"""
train_weed_detector.py
-----------------------
Trains a YOLO11n object detector on the sesame crop/weed dataset, explicitly
configured for CPU-only training on budget farm hardware.

Run `python dataset_prep.py` first to generate yolo_dataset/data.yaml.

CPU-specific choices (see README for the "why"):
    - model: yolo11n.pt (nano — smallest Ultralytics detector, ~2.6M params)
    - device: 'cpu'  (explicit, never assumes a GPU is present)
    - batch: 8       (small batch keeps peak RAM low on 4-8GB edge boxes)
    - imgsz: 416     (downscaled from the native 512 to cut CPU FLOPs ~1.5x
                       with minimal accuracy loss for this bounding-box task)
    - workers: 2     (CPU dataloading threads; too many contends with training threads)
    - cache: 'ram'   (dataset is small enough — ~1300 images at 416px — to cache in RAM
                       and avoid repeated disk decode, which is the main CPU training bottleneck)
    - amp: False     (automatic mixed precision only helps on GPU tensor cores; on CPU it's a no-op
                       or can even slow things down, so we disable it explicitly)
    - patience: 20   (early stopping to avoid wasting CPU-hours once validation plateaus;
                       raised slightly from 15 to give the refined LR schedule below room
                       to actually converge before stopping)

Accuracy-tuning changes (retraining-config review):
    - label_smoothing=0.05  — softens one-hot targets, which reduces overconfident wrong
      predictions and generally improves calibration on a dataset this size (1,300 images)
      where the model can otherwise memorize training-set quirks.
    - weight_decay=0.0005 (explicit) — L2 regularization, reduces overfitting on a small
      dataset, which is a direct lever on false-positive rate on unseen field photos.
    - lrf=0.01 — final LR as a fraction of lr0 for the cosine schedule, so the tail of
      training fine-tunes with a genuinely small step size instead of the schedule's
      default endpoint, improving convergence stability.
    - cls=0.7 (up from Ultralytics' default 0.5) — puts more relative weight on the
      classification loss vs. box regression, since the reported failure modes (weed
      boxed over crop, weed misread from background vegetation) are class-confusion
      problems more than localization problems; box quality is already tight in this
      dataset, classification boundary is the weaker link.

Usage:
    python train_weed_detector.py
"""

import shutil
from pathlib import Path

from ultralytics import YOLO

THIS_DIR = Path(__file__).resolve().parent
DATA_YAML = THIS_DIR / "yolo_dataset" / "data.yaml"
BACKEND_MODELS_DIR = THIS_DIR.parent / "backend" / "models"

# ---------------------------------------------------------------------------
# Hyperparameters — tuned for CPU-only training on ~1300 images
# ---------------------------------------------------------------------------
EPOCHS = 60
IMG_SIZE = 416
BATCH_SIZE = 8
PATIENCE = 20
RUN_NAME = "sesame_weed_cpu"


def main():
    if not DATA_YAML.exists():
        raise FileNotFoundError(
            f"{DATA_YAML} not found. Run `python dataset_prep.py` first."
        )

    # yolo11n.pt auto-downloads pretrained COCO weights on first run (transfer
    # learning gives much faster convergence than training from scratch on CPU,
    # which matters a lot when every epoch is CPU-bound).
    model = YOLO("yolo11n.pt")

    model.train(
        data=str(DATA_YAML),
        epochs=EPOCHS,
        imgsz=IMG_SIZE,
        batch=BATCH_SIZE,
        device="cpu",          # <- explicit CPU-only training, no GPU assumed
        workers=2,
        cache="ram",
        amp=False,             # AMP is a GPU feature; explicitly off on CPU
        patience=PATIENCE,
        optimizer="AdamW",
        lr0=0.001,
        lrf=0.01,               # final LR = lr0 * lrf, for a genuinely small end-of-training step
        weight_decay=0.0005,    # explicit L2 regularization against overfitting on 1,300 images
        label_smoothing=0.05,   # softer targets -> better-calibrated, less overconfident predictions
        cls=0.7,                # weight classification loss higher — the reported failures are
                                 # mostly class-confusion (weed vs crop), not box localization
        cos_lr=True,           # cosine LR schedule converges more reliably in few epochs
        mosaic=0.5,            # lighter mosaic augmentation -> less CPU-side image compositing
        close_mosaic=10,       # disable mosaic for the last 10 epochs to stabilize convergence
        degrees=5.0,           # small rotation aug — field photos are rarely perfectly level
        translate=0.1,
        scale=0.3,
        fliplr=0.5,
        flipud=0.0,            # crops/weeds have a natural "up" (growing toward sky) — don't flip vertically
        hsv_h=0.015,
        hsv_s=0.5,             # moderate saturation jitter helps generalize across lighting/soil tones
        hsv_v=0.3,
        project=str(THIS_DIR / "runs" / "detect"),
        name=RUN_NAME,
        exist_ok=True,
        plots=True,
        verbose=True,
    )

    # Validate on the held-out val split and print metrics
    metrics = model.val(data=str(DATA_YAML), device="cpu", imgsz=IMG_SIZE)
    print("\n=== Validation metrics ===")
    print(f"mAP50:    {metrics.box.map50:.4f}")
    print(f"mAP50-95: {metrics.box.map:.4f}")

    # Copy best weights into backend/models/ so app.py can load them directly
    best_weights = THIS_DIR / "runs" / "detect" / RUN_NAME / "weights" / "best.pt"
    BACKEND_MODELS_DIR.mkdir(parents=True, exist_ok=True)
    dest = BACKEND_MODELS_DIR / "weed_detector.pt"
    shutil.copy2(best_weights, dest)
    print(f"\nBest weights copied to {dest}")
    print("Backend will pick this up automatically on next restart.")


if __name__ == "__main__":
    main()
