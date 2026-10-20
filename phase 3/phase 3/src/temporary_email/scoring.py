"""Transparent weighted score aggregation with explicit missing-data handling."""
import math
from .config import load_config
from .models import ComponentResult

def validate_component_score(score):
    if score is None: return
    if isinstance(score,bool) or not isinstance(score,(int,float)) or not math.isfinite(float(score)) or not 0 <= float(score) <= 1:
        raise ValueError("Component score must be None or a finite number in [0,1]")

def combine_scores(components, config=None):
    cfg=load_config(config); weights=cfg["weights"]
    for name in ("DB","SC","DA","DC"):
        if name not in components: raise ValueError(f"Missing component {name}")
        item=components[name]; score=item.score if isinstance(item,ComponentResult) else item.get("score")
        validate_component_score(score)
    available={k:weights[k] for k,v in components.items() if (v.score if isinstance(v,ComponentResult) else v.get("score")) is not None}
    total=sum(available.values())
    if not available or total <= 0: return None, {k:0.0 for k in weights}, 0.0
    effective={k:(weights[k]/total if k in available else 0.0) for k in weights}
    score=sum(effective[k]*float(components[k].score if isinstance(components[k],ComponentResult) else components[k]["score"]) for k in available)
    if not math.isfinite(score): raise ValueError("Final score is not finite")
    score=min(1.0,max(0.0,score))
    completeness=sum(weights[k] for k in available)
    return score,effective,completeness
