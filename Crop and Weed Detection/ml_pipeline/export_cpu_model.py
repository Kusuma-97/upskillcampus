"""
export_cpu_model.py
---------------------
Optional post-training optimization for edge/farm deployment.

1. Weed detector (YOLO11n): Ultralytics already ships a CPU-friendly ONNX export path.
   Exporting to ONNX + using the ONNX Runtime CPU execution provider typically gives a
   1.3-2x inference speedup over raw PyTorch on CPU, with no accuracy loss.

2. Disease CNN: applies PyTorch dynamic INT8 quantization to the Linear/Conv layers,
   which shrinks the model and speeds up CPU inference ~2-4x with usually <1% accuracy
   drop on small classifiers like this one.

Usage:
    python export_cpu_model.py --detector      # exports weed_detector.pt -> .onnx
    python export_cpu_model.py --classifier     # quantizes disease_cnn.pt -> disease_cnn_int8.pt
    python export_cpu_model.py --all
"""

import argparse
from pathlib import Path

import torch

THIS_DIR = Path(__file__).resolve().parent
BACKEND_MODELS_DIR = THIS_DIR.parent / "backend" / "models"


def export_detector_to_onnx():
    from ultralytics import YOLO

    weights = BACKEND_MODELS_DIR / "weed_detector.pt"
    if not weights.exists():
        print(f"[skip] {weights} not found — train the detector first.")
        return
    model = YOLO(str(weights))
    onnx_path = model.export(format="onnx", imgsz=416, dynamic=False, simplify=True, device="cpu")
    print(f"Exported ONNX weed detector -> {onnx_path}")
    print("To use it for faster CPU inference, install `onnxruntime` and swap the "
          "backend's Ultralytics load for `onnxruntime.InferenceSession(onnx_path)`.")


def quantize_disease_classifier():
    from disease_classifier import DiseaseCNN

    ckpt_path = BACKEND_MODELS_DIR / "disease_cnn.pt"
    if not ckpt_path.exists():
        print(f"[skip] {ckpt_path} not found — the disease classifier is still in "
              f"heuristic mode (no trained checkpoint to quantize). Train it first "
              f"with train_disease_classifier.py once you have labeled disease data.")
        return

    ckpt = torch.load(ckpt_path, map_location="cpu")
    class_names = ckpt["class_names"]
    model = DiseaseCNN(num_classes=len(class_names))
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    quantized = torch.quantization.quantize_dynamic(
        model, {torch.nn.Linear, torch.nn.Conv2d}, dtype=torch.qint8
    )

    out_path = BACKEND_MODELS_DIR / "disease_cnn_int8.pt"
    torch.save({"state_dict": quantized.state_dict(), "class_names": class_names}, out_path)
    print(f"Quantized disease classifier -> {out_path}")
    print("Note: dynamic quantization mainly speeds up Linear layers; for a model this "
          "small the gain is modest but memory footprint drops noticeably, which helps "
          "on constrained edge devices.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--detector", action="store_true", help="Export weed detector to ONNX")
    parser.add_argument("--classifier", action="store_true", help="Quantize disease CNN to INT8")
    parser.add_argument("--all", action="store_true", help="Run both exports")
    args = parser.parse_args()

    if args.all or args.detector:
        export_detector_to_onnx()
    if args.all or args.classifier:
        quantize_disease_classifier()
    if not (args.all or args.detector or args.classifier):
        parser.print_help()
