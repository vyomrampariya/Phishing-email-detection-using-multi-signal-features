"""Exact six-component weighted sum with explicit missing-data behavior."""
from __future__ import annotations
from typing import Mapping

DEFAULT_WEIGHTS = {"W1": .15, "W2": .15, "W3": .15, "W4": .20, "W5": .20, "W6": .15}
COMPONENTS = ("Rep", "Mismatch", "Anomaly", "Auth", "Spoof", "Similarity")

def validate_weights(weights: Mapping[str, float]) -> dict[str, float]:
    if set(weights) != set(DEFAULT_WEIGHTS): raise ValueError("weights must contain exactly W1 through W6")
    vals = {k: float(v) for k, v in weights.items()}
    if any(v < 0 or v > 1 for v in vals.values()): raise ValueError("weights must be between 0 and 1")
    if abs(sum(vals.values()) - 1.0) > 1e-9: raise ValueError("weights must sum to 1")
    return vals

def score_components(scores: Mapping[str, float | None], weights: Mapping[str, float] | None = None) -> dict[str, object]:
    w = validate_weights(weights or DEFAULT_WEIGHTS)
    if set(scores) != set(COMPONENTS): raise ValueError("scores must contain Rep, Mismatch, Anomaly, Auth, Spoof, Similarity")
    for k, v in scores.items():
        if v is not None and not 0 <= float(v) <= 1: raise ValueError(f"{k} score must be between 0 and 1")
    key_for = dict(zip(COMPONENTS, w.keys()))
    available = [c for c in COMPONENTS if scores[c] is not None]
    coverage = sum(w[key_for[c]] for c in available)
    if not available or coverage < .50:
        return {"S_HDR": None, "status": "incomplete", "score_completeness": round(coverage, 6), "missing_components": [c for c in COMPONENTS if scores[c] is None], "weights": w}
    partial = len(available) != len(COMPONENTS)
    value = sum(w[key_for[c]] * float(scores[c]) for c in available) / coverage if partial else sum(w[key_for[c]] * float(scores[c]) for c in COMPONENTS)
    return {"S_HDR": round(min(1.0, max(0.0, value)), 6), "status": "partial" if partial else "complete", "score_completeness": round(coverage, 6), "missing_components": [c for c in COMPONENTS if scores[c] is None], "weights": w}
