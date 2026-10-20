"""Offline reputation-list adapter; no provider is queried automatically."""
from pathlib import Path
from .domain_normalizer import normalize_domain, InvalidDomainError

def reputation_lookup(domain, positive_findings=None, ordinary_domains=None):
    """positive_findings maps domain -> {source, status, ...}; ordinary_domains is optional evidence."""
    try: domain=normalize_domain(domain)
    except InvalidDomainError: return {"score":None,"status":"UNKNOWN","evidence":[],"source":None,"findings":[],"explanation":"Invalid domain."}
    normalized_findings = {}
    for key, value in (positive_findings or {}).items():
        try:
            normalized_findings[normalize_domain(key)] = value
        except (InvalidDomainError, TypeError):
            continue
    finding=normalized_findings.get(domain)
    if finding:
        status=str(finding.get("status","CONFIRMED")).upper()
        if status in {"MALICIOUS","CONFIRMED_NEGATIVE","CONFIRMED"} and "score" in finding:
            score=float(finding["score"])
            if not 0 <= score <= 1: raise ValueError("Reputation score must be in [0,1]")
            return {"score":score,"status":"OBSERVED","evidence":[str(finding.get("evidence","Reputation finding supplied by local source"))],"source":finding.get("source"),"findings":[str(finding.get("label","negative reputation finding"))],"explanation":"Reputation evidence is separate from disposable status."}
    normalized_ordinary = set()
    for item in ordinary_domains or []:
        try:
            normalized_ordinary.add(normalize_domain(item))
        except (InvalidDomainError, TypeError):
            continue
    if domain in normalized_ordinary:
        return {"score":0.0,"status":"OBSERVED","evidence":["Present in explicitly supplied ordinary-reputation dataset"],"source":"local reputation dataset","findings":[],"explanation":"No negative finding in the supplied dataset; this is not a global clean bill of health."}
    return {"score":None,"status":"UNKNOWN","evidence":[],"source":None,"findings":[],"explanation":"No reputation provider or cached finding supplied."}
