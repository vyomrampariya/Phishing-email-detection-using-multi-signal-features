"""Leakage-aware group split and classification metrics."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.metrics import (confusion_matrix, f1_score, precision_score, recall_score,
                             roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold

from .models import WordPoolModel


def metrics(y_true, scores, threshold=0.5):
    y_true = np.asarray(y_true, dtype=int); scores = np.asarray(scores, dtype=float)
    pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    from sklearn.metrics import precision_recall_fscore_support
    p_cls, r_cls, f_cls, support = precision_recall_fscore_support(y_true, pred, labels=[0, 1], zero_division=0)
    return {"n": int(len(y_true)), "threshold": float(threshold),
            "precision": float(precision_score(y_true, pred, zero_division=0)),
            "recall": float(recall_score(y_true, pred, zero_division=0)),
            "f1": float(f1_score(y_true, pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_true, scores)) if len(set(y_true)) == 2 else None,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
            "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
            "by_class": {str(i): {"precision": float(p_cls[i]), "recall": float(r_cls[i]),
                                  "f1": float(f_cls[i]), "support": int(support[i])} for i in (0,1)}}


def grouped_holdout(frame, seed=42, test_size=0.2):
    if frame["label"].nunique() < 2: raise ValueError("Evaluation requires both classes")
    folds = max(2, min(10, int(round(1 / test_size))))
    candidates = list(StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
                      .split(frame, frame["label"], frame["duplicate_group"]))
    overall_rate = float(frame.label.mean())
    valid = []
    for a, b in candidates:
        train, test = frame.iloc[a], frame.iloc[b]
        if train.label.nunique() == 2 and test.label.nunique() == 2:
            distance = abs(float(test.label.mean()) - overall_rate) + abs(len(test) / len(frame) - test_size)
            valid.append((distance, a, b))
    if not valid:
        # Fallback handles very small or unusually grouped corpora.
        for rs in range(seed, seed + 100):
            a, b = next(GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=rs)
                        .split(frame, frame.label, frame.duplicate_group))
            if frame.iloc[a].label.nunique() == frame.iloc[b].label.nunique() == 2:
                distance = abs(float(frame.iloc[b].label.mean()) - overall_rate) + abs(len(b) / len(frame) - test_size)
                valid.append((distance, a, b))
    if not valid: raise ValueError("Unable to create a two-class duplicate-group holdout; add suitable data")
    _, train_idx, test_idx = min(valid, key=lambda item: item[0])
    return frame.iloc[train_idx].copy(), frame.iloc[test_idx].copy()


def run_evaluation(frame, *, weights=None, seed=42, threshold=0.5, model_path=None):
    trainval, test = grouped_holdout(frame, seed)
    train, validation = grouped_holdout(trainval, seed + 1000, test_size=0.2)
    print(f"Fitting validation model on {len(train):,} training rows...", flush=True)
    model = WordPoolModel(weights=weights, seed=seed).fit(train.text.tolist(), train.label.tolist())
    print(f"Scoring {len(validation):,} validation rows and tuning component weights...", flush=True)
    validation_results = [model.analyze(body=t) for t in validation.text]
    default_weights = model.weights
    from .scoring import WordPoolWeights, calculate_word_pool_score
    default_scores = [calculate_word_pool_score(x["component_scores"], default_weights) for x in validation_results]
    validation_default = metrics(validation.label, default_scores, threshold)
    # Tune weights only on validation data, using a deterministic simplex grid.
    best_weights, best_report = default_weights, validation_default
    component_matrix = np.asarray([[x["component_scores"][k] for k in ("N", "C", "T", "R", "A")] for x in validation_results])
    validation_labels = np.asarray(validation.label, dtype=int)
    best_f1 = validation_default["f1"]
    step = 0.1
    for w1 in np.arange(0, 1.0001, step):
      for w2 in np.arange(0, 1.0001-w1, step):
       for w3 in np.arange(0, 1.0001-w1-w2, step):
        for w4 in np.arange(0, 1.0001-w1-w2-w3, step):
         w5 = round(1 - w1-w2-w3-w4, 10)
         if w5 < -1e-8: continue
         candidate = WordPoolWeights(float(w1), float(w2), float(w3), float(w4), max(0.0, float(w5)))
         candidate_scores = component_matrix @ np.asarray([candidate.W1, candidate.W2, candidate.W3, candidate.W4, candidate.W5])
         candidate_pred = candidate_scores >= threshold
         tp = int(np.sum(candidate_pred & (validation_labels == 1)))
         fp = int(np.sum(candidate_pred & (validation_labels == 0)))
         fn = int(np.sum(~candidate_pred & (validation_labels == 1)))
         f1 = 2 * tp / max(1, 2 * tp + fp + fn)
         if f1 > best_f1:
          best_f1 = f1
          best_weights = candidate
          best_report = metrics(validation.label, candidate_scores, threshold)
    model.weights = best_weights
    validation_report = {"default": validation_default, "tuned": best_report,
                         "tuning": "0.1-step exhaustive weight simplex grid; validation labels only; threshold held at configured value"}
    # Fit final model on train+validation; all learned vocab/statistics remain training-only w.r.t. test.
    print(f"Refitting final model on {len(trainval):,} train+validation rows...", flush=True)
    model.fit(trainval.text.tolist(), trainval.label.tolist())
    print(f"Scoring {len(test):,} final test rows...", flush=True)
    test_scores = [model.analyze(body=t)["S_WP"] for t in test.text]
    report = {"seed": seed, "split": {"train": len(train), "validation": len(validation), "test": len(test),
                                       "duplicate_groups_test": int(test.duplicate_group.nunique())},
              "weights": model.weights.__dict__, "validation": validation_report,
              "test": metrics(test.label, test_scores, threshold),
              "sources": frame.source_dataset.value_counts().to_dict(),
              "source_test_metrics": {str(s): metrics(g.label, g["_score"], threshold)
                                      for s,g in test.assign(_score=test_scores).groupby("source_dataset")},
              "limitations": ["Exact normalized duplicates were grouped/deduplicated; near-duplicate clustering is not implemented.",
                              "Dataset labels retain source meaning; spam is only a proxy for phishing where source labels are spam/ham.",
                              "TF-IDF probabilities and heuristic components are not calibrated risk probabilities."]}
    if model_path: model.save(model_path)
    return model, report


def cross_dataset_evaluation(frame, *, held_out_source, weights=None, seed=42, threshold=0.5):
    train, test = frame[frame.source_dataset != held_out_source], frame[frame.source_dataset == held_out_source]
    if train.empty or test.empty: raise ValueError(f"Unknown or empty held-out dataset: {held_out_source}")
    if train.label.nunique() < 2: raise ValueError("Cross-dataset training split has only one class")
    model = WordPoolModel(weights=weights, seed=seed).fit(train.text.tolist(), train.label.tolist())
    scores = [model.analyze(body=t)["S_WP"] for t in test.text]
    return {"held_out_source": held_out_source, "train_rows": len(train), "test_rows": len(test),
            "weights": model.weights.__dict__, "metrics": metrics(test.label, scores, threshold),
            "warning": "Source label semantics may differ; inspect source manifest before comparing."}
