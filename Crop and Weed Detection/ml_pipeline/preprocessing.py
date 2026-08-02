"""
preprocessing.py
------------------
Image quality preprocessing applied before detection and disease scoring.

Scope note: resizing is deliberately NOT done here. Ultralytics' `model.predict()`
already applies aspect-ratio-preserving letterbox resizing internally and maps
predicted box coordinates back to the original image size automatically — doing our
own resize before calling it would double-transform coordinates and risk misaligned
boxes. This module only touches pixel *quality* (contrast, brightness, sharpness) at
the original resolution, which is the part that was missing.

Functions here are pure (input array in, new array out) and safe to no-op on
already-good images — every correction is gated so it only fires when the image
actually needs it, rather than always altering every image.
"""

from __future__ import annotations

import cv2
import numpy as np


def _estimate_brightness(gray: np.ndarray) -> float:
    return float(np.mean(gray))


def _estimate_contrast(gray: np.ndarray) -> float:
    return float(np.std(gray))


def auto_brightness_contrast(image_rgb: np.ndarray, target_brightness: float = 128.0) -> np.ndarray:
    gray = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2GRAY)
    brightness = _estimate_brightness(gray)
    contrast = _estimate_contrast(gray)

    if 100.0 <= brightness <= 156.0 and contrast >= 35.0:
        return image_rgb

    alpha = float(np.clip(50.0 / max(contrast, 1e-6), 0.8, 1.8))
    beta = float(np.clip(target_brightness - brightness * alpha, -60.0, 60.0))
    corrected = cv2.convertScaleAbs(image_rgb, alpha=alpha, beta=beta)
    return corrected


def apply_clahe(image_rgb: np.ndarray, clip_limit: float = 2.5, tile_grid_size: int = 8) -> np.ndarray:
    gray = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2GRAY)
    if _estimate_contrast(gray) >= 45.0:
        return image_rgb

    lab = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2LAB)
    l_channel, a_channel, b_channel = cv2.split(lab)
    clahe = cv2.createCLAHE(clipLimit=clip_limit, tileGridSize=(tile_grid_size, tile_grid_size))
    l_enhanced = clahe.apply(l_channel)
    lab_enhanced = cv2.merge((l_enhanced, a_channel, b_channel))
    return cv2.cvtColor(lab_enhanced, cv2.COLOR_LAB2RGB)


def sharpen_if_blurry(image_rgb: np.ndarray, blur_threshold: float = 60.0) -> np.ndarray:
    gray = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2GRAY)
    laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
    if laplacian_var >= blur_threshold:
        return image_rgb

    blurred = cv2.GaussianBlur(image_rgb, (0, 0), sigmaX=3)
    sharpened = cv2.addWeighted(image_rgb, 1.5, blurred, -0.5, 0)
    return np.clip(sharpened, 0, 255).astype(np.uint8)


def enhance_image(image_rgb: np.ndarray) -> np.ndarray:
    """Full pipeline: auto brightness/contrast -> CLAHE (low-contrast images only) ->
    sharpen (blurry images only). Each stage is gated to be a no-op on images that are
    already good quality, so well-lit, sharp, well-contrasted field photos pass through
    essentially unchanged while poor-condition photos get corrected before detection and
    disease scoring — this is what "stable predictions across different images" in
    practice depends on, since the model/heuristic otherwise sees wildly different pixel
    statistics for the same underlying scene shot in different lighting."""
    out = auto_brightness_contrast(image_rgb)
    out = apply_clahe(out)
    out = sharpen_if_blurry(out)
    return out
