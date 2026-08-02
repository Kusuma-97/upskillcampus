"""
augmentations.py
------------------
Albumentations-based augmentation pipelines for the disease classifier and (optionally)
the weed/crop detector, implementing the strategy documented in DATA_COLLECTION_BLUEPRINT.md
section 3.2 — realistic field-condition augmentation (lighting variation, partial occlusion,
blur) rather than generic/aggressive augmentation that would distort the color cues the
disease classifier actually depends on.

Requires: pip install albumentations
(Not added to requirements.txt by default since the project's current training script uses
torchvision transforms; add `albumentations` to ml_pipeline/requirements.txt if you switch
train_disease_classifier.py over to these.)
"""

from __future__ import annotations

import albumentations as A
from albumentations.pytorch import ToTensorV2

IMAGENET_MEAN = (0.485, 0.456, 0.406)
IMAGENET_STD = (0.229, 0.224, 0.225)


def build_train_transform(image_size: int = 224) -> A.Compose:
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
        A.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD),
        ToTensorV2(),
    ])


def build_val_transform(image_size: int = 224) -> A.Compose:
    return A.Compose([
        A.Resize(height=image_size, width=image_size),
        A.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD),
        ToTensorV2(),
    ])


def build_detection_train_transform(image_size: int = 416) -> A.Compose:
    return A.Compose([
        A.HorizontalFlip(p=0.5),
        A.RandomBrightnessContrast(brightness_limit=0.2, contrast_limit=0.2, p=0.7),
        A.HueSaturationValue(hue_shift_limit=6, sat_shift_limit=20, val_shift_limit=12, p=0.5),
        A.GaussianBlur(blur_limit=(3, 5), p=0.15),
        A.Resize(height=image_size, width=image_size),
    ], bbox_params=A.BboxParams(format="yolo", label_fields=["class_labels"], min_visibility=0.3))


def build_detection_val_transform(image_size: int = 416) -> A.Compose:
    return A.Compose([
        A.Resize(height=image_size, width=image_size),
    ], bbox_params=A.BboxParams(format="yolo", label_fields=["class_labels"]))
