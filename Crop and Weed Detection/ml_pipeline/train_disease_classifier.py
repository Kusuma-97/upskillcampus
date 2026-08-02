"""
train_disease_classifier.py
----------------------------
Trains the MobileNet-lite DiseaseCNN (see disease_classifier.py) on real,
labeled disease images — CPU-only.

This script does nothing useful until you supply labeled data, because (as explained
in README.md and disease_classifier.py) the original agri_data dataset has no disease
labels at all — only crop/weed bounding boxes.

Expected input layout (standard ImageFolder style), one folder per class:

    ml_pipeline/disease_data/
        Healthy/                *.jpg / *.jpeg / *.png
        Cercospora Leaf Spot/
        Bacterial Blight/
        Background_Debris/      dead matter, uprooted weed piles, soil, mulch, litter
        ... (add/rename folders freely; class list is read from folder names)

Including the Background_Debris folder is what fixes the false-positive pattern where
dead organic matter or uprooted weed piles get misclassified as diseased crop — without
a negative class, softmax has nowhere to route low-confidence/out-of-distribution crops
except into one of the disease labels. This script uses focal loss with inverse-frequency
class weights (see quality_filters.py) specifically because that background class will
typically be far more numerous than any single disease class once you start collecting
field photos, and plain unweighted cross-entropy would get dominated by it.

Usage:
    python train_disease_classifier.py
"""

import shutil
from pathlib import Path

import torch
from torch.utils.data import DataLoader, random_split
from torchvision import datasets, transforms

from disease_classifier import DiseaseCNN, IMG_SIZE
from quality_filters import compute_class_weights, focal_loss

THIS_DIR = Path(__file__).resolve().parent
DATA_DIR = THIS_DIR / "disease_data"
BACKEND_MODELS_DIR = THIS_DIR.parent / "backend" / "models"

# Retraining-config review:
# - EPOCHS raised 30 -> 40 paired with early stopping (EARLY_STOP_PATIENCE) below, so
#   runs that converge quickly still stop early, but runs that need more epochs (e.g.
#   once Background_Debris is a much larger class than before) aren't cut off too soon.
# - BATCH_SIZE 16 -> 24: still CPU-safe at this crop size (96x96), and reduces per-epoch
#   gradient noise a bit, which matters more now that a 4th class is thinner on data.
# - LR unchanged (1e-3 with AdamW + cosine schedule is a reasonable default for a model
#   this small), but WEIGHT_DECAY is now explicit for the same overfitting-control reason
#   as the detector's training config.
# - LABEL_SMOOTHING added, same rationale as the detector: softer targets, better
#   calibrated confidence, less overconfident-wrong on a small dataset.
EPOCHS = 40
BATCH_SIZE = 24
LR = 1e-3
WEIGHT_DECAY = 1e-4
LABEL_SMOOTHING = 0.05
EARLY_STOP_PATIENCE = 8  # stop if val_acc hasn't improved in this many epochs
VAL_FRACTION = 0.2
SEED = 42


def build_dataloaders():
    train_tf = transforms.Compose([
        transforms.Resize((IMG_SIZE, IMG_SIZE)),
        transforms.RandomHorizontalFlip(),
        transforms.RandomRotation(10),
        transforms.ColorJitter(brightness=0.2, contrast=0.2, saturation=0.2),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])
    eval_tf = transforms.Compose([
        transforms.Resize((IMG_SIZE, IMG_SIZE)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])

    full_ds = datasets.ImageFolder(str(DATA_DIR), transform=train_tf)
    class_names = full_ds.classes
    class_counts = [0] * len(class_names)
    for _, label in full_ds.samples:
        class_counts[label] += 1

    n_val = int(len(full_ds) * VAL_FRACTION)
    n_train = len(full_ds) - n_val
    generator = torch.Generator().manual_seed(SEED)
    train_ds, val_ds = random_split(full_ds, [n_train, n_val], generator=generator)
    # apply the non-augmented eval transform to the val subset
    val_ds.dataset.transform = eval_tf

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, num_workers=2)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False, num_workers=2)
    return train_loader, val_loader, class_names, class_counts


def main():
    if not DATA_DIR.exists() or not any(DATA_DIR.iterdir()):
        raise FileNotFoundError(
            f"No labeled data found at {DATA_DIR}.\n"
            "Create one subfolder per disease class with images inside, e.g.\n"
            "  ml_pipeline/disease_data/Healthy/*.jpg\n"
            "  ml_pipeline/disease_data/Cercospora Leaf Spot/*.jpg\n"
            "  ml_pipeline/disease_data/Bacterial Blight/*.jpg\n"
            "  ml_pipeline/disease_data/Background_Debris/*.jpg   <- include this to fix\n"
            "                                                        debris false positives\n"
            "The original agri_data dataset does not contain this data — see README.md."
        )

    torch.manual_seed(SEED)
    device = torch.device("cpu")  # explicit CPU-only training

    train_loader, val_loader, class_names, class_counts = build_dataloaders()
    print(f"Classes discovered: {class_names}")
    print(f"Per-class counts: {dict(zip(class_names, class_counts))}")

    class_weights = compute_class_weights(class_counts)

    model = DiseaseCNN(num_classes=len(class_names)).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS)

    best_val_acc = 0.0
    epochs_without_improvement = 0
    BACKEND_MODELS_DIR.mkdir(parents=True, exist_ok=True)
    best_path = THIS_DIR / "disease_cnn_best.pt"

    for epoch in range(1, EPOCHS + 1):
        model.train()
        running_loss = 0.0
        for images, labels in train_loader:
            images, labels = images.to(device), labels.to(device)
            optimizer.zero_grad()
            logits = model(images)
            loss = focal_loss(logits, labels, class_weights=class_weights, gamma=2.0,
                               label_smoothing=LABEL_SMOOTHING)
            loss.backward()
            optimizer.step()
            running_loss += loss.item() * images.size(0)
        scheduler.step()
        train_loss = running_loss / len(train_loader.dataset)

        model.eval()
        correct, total = 0, 0
        with torch.no_grad():
            for images, labels in val_loader:
                images, labels = images.to(device), labels.to(device)
                logits = model(images)
                preds = logits.argmax(dim=1)
                correct += (preds == labels).sum().item()
                total += labels.size(0)
        val_acc = correct / max(total, 1)

        print(f"Epoch {epoch:02d}/{EPOCHS} | train_loss={train_loss:.4f} | val_acc={val_acc:.4f}")

        if val_acc > best_val_acc:
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= EARLY_STOP_PATIENCE:
                print(f"Early stopping: no val_acc improvement in {EARLY_STOP_PATIENCE} epochs.")
                break

        if val_acc >= best_val_acc:
            best_val_acc = val_acc
            torch.save({"state_dict": model.state_dict(), "class_names": class_names}, best_path)

    print(f"\nBest val accuracy: {best_val_acc:.4f}")
    dest = BACKEND_MODELS_DIR / "disease_cnn.pt"
    shutil.copy2(best_path, dest)
    print(f"Trained disease model copied to {dest}")
    print("Restart the backend to switch it from heuristic mode to CNN mode.")


if __name__ == "__main__":
    main()
