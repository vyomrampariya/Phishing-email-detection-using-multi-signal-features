"""Configuration loading and validation. YAML is optional; JSON-compatible YAML subset fallback."""
from __future__ import annotations
import json
import math
from pathlib import Path

DEFAULT_CONFIG = {
 "model_version":"3.0.0", "weights":{"DB":0.45,"SC":0.20,"DA":0.15,"DC":0.20},
 "normalize_weights":False, "subdomain_matching":False, "source_freshness_days":90,
 "source_trust":{"disposable-email-domains":1.0},
 "known_provider_rules":{"disposable":["mailinator.com","10minutemail.com","guerrillamail.com"],
 "ordinary":["gmail.com","googlemail.com","outlook.com","hotmail.com","yahoo.com","icloud.com","proton.me","protonmail.com"], "organization":[]},
 "age_risk_days":[{"max_age_days":7,"score":0.9},{"max_age_days":30,"score":0.7},{"max_age_days":180,"score":0.4},{"max_age_days":365,"score":0.2},{"max_age_days":None,"score":0.0}]
}
class ConfigurationError(ValueError): pass

def load_config(config=None):
    if config is None: data = json.loads(json.dumps(DEFAULT_CONFIG))
    elif isinstance(config, dict): data = json.loads(json.dumps(DEFAULT_CONFIG)); _merge(data, config)
    else:
        path=Path(config)
        try:
            import yaml  # type: ignore
            loaded=yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except ImportError:
            # YAML used by this project is valid JSON only if rewritten; provide an actionable error.
            raise ConfigurationError("Reading YAML files requires PyYAML; install it or pass a Python dict")
        data=json.loads(json.dumps(DEFAULT_CONFIG)); _merge(data, loaded)
    weights=data.get("weights", {})
    if set(weights) != {"DB","SC","DA","DC"}: raise ConfigurationError("weights must define exactly DB, SC, DA, DC")
    try: vals={k:float(v) for k,v in weights.items()}
    except (TypeError,ValueError) as e: raise ConfigurationError("Weights must be numeric") from e
    if any(not math.isfinite(v) for v in vals.values()): raise ConfigurationError("Weights must be finite numbers")
    if any(v < 0 for v in vals.values()): raise ConfigurationError("Weights must be non-negative")
    total=sum(vals.values())
    if not math.isfinite(total) or total <= 0: raise ConfigurationError("At least one weight must be positive and total must be finite")
    if abs(total-1.0)>1e-8:
        if data.get("normalize_weights") is True: vals={k:v/total for k,v in vals.items()}
        else: raise ConfigurationError(f"Weights must sum to 1 (got {total:.12g}); set normalize_weights: true to explicitly normalize")
    data["weights"]=vals
    return data

def _merge(target, source):
    for k,v in source.items():
        if isinstance(v,dict) and isinstance(target.get(k),dict): _merge(target[k],v)
        else: target[k]=v
