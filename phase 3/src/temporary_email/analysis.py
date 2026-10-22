"""Public Phase 3 entry point."""
from pathlib import Path
from .config import load_config
from .domain_normalizer import extract_domain, InvalidDomainError
from .disposable_database import DisposableDatabase
from .sender_category import classify_sender
from .domain_age import age_risk_from_days
from .domain_reputation import reputation_lookup
from .models import ComponentResult, AnalysisResult
from .scoring import combine_scores

BASE=Path(__file__).resolve().parents[2]

def analyze_temporary_email(email_address, config=None, *, domain_age_days=None, reputation_findings=None, reputation_ordinary_domains=None, database=None):
    cfg=load_config(config); weights=cfg["weights"]; warnings=[]
    try: domain=extract_domain(email_address)
    except InvalidDomainError as exc:
        return AnalysisResult(None,None,"INVALID",{k:None for k in weights},weights,{k:0.0 for k in weights},{k:"UNKNOWN" for k in weights},None,[],"INVALID",None,[],{"input_validation":str(exc)},list(weights),0.0,[str(exc)],cfg.get("model_version","3.0.0"))
    db=database or DisposableDatabase.from_file(BASE/"data"/"processed"/"disposable_domains.json",subdomain_matching=cfg.get("subdomain_matching",False))
    match=db.lookup(domain)
    db_component=ComponentResult(1.0 if match["matched"] else 0.0,"OBSERVED",["Exact domain match found" if match["matched"] else "No exact match in loaded local database"],";".join(match["sources"]) or "local disposable database","List membership indicates disposable-provider evidence, not maliciousness." )
    category=classify_sender(domain,cfg,db_match=match["matched"])
    sc_component=ComponentResult(category["score"],category["status"],category["evidence"],category["source"],"Provider category is a risk heuristic, not a phishing verdict.")
    age=age_risk_from_days(domain_age_days,cfg)
    da_component=ComponentResult(age["score"],age["status"],age["evidence"],age["source"],age["explanation"])
    rep=reputation_lookup(domain,reputation_findings,reputation_ordinary_domains)
    dc_component=ComponentResult(rep["score"],rep["status"],rep["evidence"],rep["source"],rep["explanation"])
    components={"DB":db_component,"SC":sc_component,"DA":da_component,"DC":dc_component}
    score,effective,completeness=combine_scores(components,cfg)
    missing=[k for k,v in components.items() if v.score is None]
    if missing: warnings.append("Partial score: unavailable/unknown components were excluded and remaining weights renormalized.")
    if score is None: warnings.append("Insufficient evidence to calculate a score.")
    classification="DISPOSABLE_CONFIRMED" if match["matched"] else ("LIKELY_DISPOSABLE" if category["category"]=="KNOWN_DISPOSABLE" else ("ORDINARY_PROVIDER" if category["category"] in {"ORDINARY_PROVIDER","ORGANIZATION_OWNED"} else "UNKNOWN"))
    return AnalysisResult(score,domain,classification,{k:v.score for k,v in components.items()},weights,effective,{k:v.status for k,v in components.items()},match["matched"],match["sources"],category["category"],domain_age_days,rep["findings"],{k:{"evidence":v.evidence,"source":v.source,"explanation":v.explanation} for k,v in components.items()},missing,completeness,warnings,cfg.get("model_version","3.0.0"))
