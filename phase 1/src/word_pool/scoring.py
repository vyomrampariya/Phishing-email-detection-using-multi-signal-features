"""Validated Word Pool weighted-sum scoring."""
from __future__ import annotations

from dataclasses import dataclass, asdict
import math
from typing import Mapping


@dataclass(frozen=True)
class WordPoolWeights:
    W1: float = 0.20
    W2: float = 0.20
    W3: float = 0.20
    W4: float = 0.20
    W5: float = 0.20

    def __post_init__(self):
        values = tuple(asdict(self).values())
        if any(not math.isfinite(x) or x < 0 for x in values):
            raise ValueError("Word Pool weights must be finite and non-negative")
        if not math.isclose(sum(values), 1.0, rel_tol=0.0, abs_tol=1e-8):
            raise ValueError(f"Word Pool weights must sum to 1.0; got {sum(values):.12g}")


def weights_from_mapping(values: Mapping[str, float], normalize: bool = False) -> WordPoolWeights:
    names = ("W1", "W2", "W3", "W4", "W5")
    try:
        raw = {k: float(values[k]) for k in names}
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Weights must define W1, W2, W3, W4, and W5") from exc
    total = sum(raw.values())
    if normalize and total > 0 and all(math.isfinite(v) and v >= 0 for v in raw.values()):
        raw = {k: v / total for k, v in raw.items()}
    return WordPoolWeights(**raw)


def calculate_word_pool_score(component_scores: Mapping[str, float], weights: WordPoolWeights | Mapping[str, float]) -> float:
    weights = weights if isinstance(weights, WordPoolWeights) else weights_from_mapping(weights)
    components = ("N", "C", "T", "R", "A")
    if any(k not in component_scores for k in components):
        raise ValueError("All component scores N, C, T, R, and A are required")
    scores = {k: float(component_scores[k]) for k in components}
    if any(not math.isfinite(v) or not 0.0 <= v <= 1.0 for v in scores.values()):
        raise ValueError("Every Word Pool component score must be finite and in [0, 1]")
    result = (weights.W1 * scores["N"] + weights.W2 * scores["C"] +
              weights.W3 * scores["T"] + weights.W4 * scores["R"] +
              weights.W5 * scores["A"])
    return min(1.0, max(0.0, result))
