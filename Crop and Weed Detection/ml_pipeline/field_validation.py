"""
field_validation.py
---------------------
Validation-split utilities implementing DATA_COLLECTION_BLUEPRINT.md section 4:
field-grouped stratified k-fold (so no field/plot leaks across train/val within a fold),
plus a weighted sampler for the minority disease classes referenced in section 3.1/3.3.

Usage sketch (once you have a labeled dataset with field/plot IDs logged per image):

    from field_validation import build_field_grouped_folds, build_weighted_sampler

    folds = build_field_grouped_folds(labels=disease_labels, groups=field_ids, n_splits=5)
    for fold_idx, (train_idx, val_idx) in enumerate(folds):
        ...

Requires: pip install scikit-learn
"""

from __future__ import annotations

from typing import Sequence

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from torch.utils.data import WeightedRandomSampler


def build_field_grouped_folds(labels: Sequence[int], groups: Sequence[str],
                               n_splits: int = 5, seed: int = 42) -> list[tuple[np.ndarray, np.ndarray]]:
    labels_arr = np.asarray(labels)
    groups_arr = np.asarray(groups)
    skf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    return list(skf.split(X=np.zeros(len(labels_arr)), y=labels_arr, groups=groups_arr))


def build_weighted_sampler(class_counts: Sequence[int], sample_labels: Sequence[int]) -> WeightedRandomSampler:
    class_weights = 1.0 / np.array(class_counts, dtype=np.float64)
    sample_labels_arr = np.asarray(sample_labels)
    sample_weights = class_weights[sample_labels_arr]
    return WeightedRandomSampler(
        weights=sample_weights,
        num_samples=len(sample_labels_arr),
        replacement=True,
    )


def summarize_fold_metrics(fold_metrics: Sequence[dict]) -> dict:
    keys = fold_metrics[0].keys()
    summary = {}
    for key in keys:
        values = np.array([m[key] for m in fold_metrics], dtype=np.float64)
        summary[key] = {"mean": float(values.mean()), "std": float(values.std())}
    return summary


def hold_out_unseen_fields(all_field_ids: Sequence[str], unseen_field_ids: Sequence[str]) -> np.ndarray:
    unseen_set = set(unseen_field_ids)
    return np.array([fid in unseen_set for fid in all_field_ids])
