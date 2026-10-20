"""Unified six-phase email phishing assessment entry point."""
from __future__ import annotations
import argparse, json, math, sys
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PHASE_PATHS = [ROOT / "phase 1" / "src", ROOT / "phase 2" / "sender_header_phase2" / "src", ROOT / "phase 3" / "phase 3" / "src", ROOT / "phase 4" / "src", ROOT / "phase 5" / "src"]
for p in PHASE_PATHS:
    if str(p) not in sys.path: sys.path.insert(0, str(p))

from word_pool.models import WordPoolModel
from sender_header import analyze_sender_header
from temporary_email import analyze_temporary_email
from url_analysis import analyze_email_urls
from website_analysis import analyze_website

STATUS = {"available", "not_applicable", "unavailable", "error"}
DEFAULTS = {"weights": {"word_pool": .30, "sender_header": .20, "temporary_email": .10, "url_analysis": .25, "website_analysis": .15}, "thresholds": {"suspicious": .40, "high_risk": .70}, "url_aggregation": "maximum", "website_retrieval": "disabled"}

def _component(status, score=None, evidence=None, details=None, message=None):
    if status not in STATUS: raise ValueError(f"Invalid component status: {status}")
    if status == "available" and (score is None or not 0 <= float(score) <= 1): raise ValueError("Available components require a score in [0,1]")
    if status != "available": score = None
    return {"status": status, "score": round(float(score), 8) if score is not None else None, "evidence": evidence or [], "details": details or {}, "message": message}

def fuse(components, weights=None, thresholds=None):
    cfg = dict(weights) if weights is not None else dict(DEFAULTS["weights"])
    if set(cfg) != set(components) or any(not isinstance(v, (int,float)) or v < 0 for v in cfg.values()): raise ValueError("Fusion weights must be nonnegative and cover each component exactly")
    for component in components.values():
        status, score = component.get("status"), component.get("score")
        if status not in STATUS: raise ValueError("Invalid component status")
        if status == "available":
            if score is None or not math.isfinite(float(score)) or not 0 <= float(score) <= 1: raise ValueError("Available components require a finite score in [0,1]")
        elif score is not None:
            raise ValueError("Non-available components must not carry a score")
    eligible = {k:c["score"] for k,c in components.items() if c["status"] == "available" and c["score"] is not None}
    total = sum(cfg[k] for k in eligible)
    score = sum(cfg[k]*v for k,v in eligible.items())/total if total > 0 else None
    th = {**DEFAULTS["thresholds"], **(thresholds or {})}
    if not (0 <= th["suspicious"] < th["high_risk"] <= 1): raise ValueError("Thresholds must satisfy 0 <= suspicious < high_risk <= 1")
    label = "insufficient_evidence" if score is None else "high_risk" if score >= th["high_risk"] else "suspicious" if score >= th["suspicious"] else "low_risk_review"
    return {"score": round(score, 8) if score is not None else None, "classification": label, "weights": cfg, "effective_weights": {k:cfg[k]/total for k in eligible} if total else {}, "evidence_coverage": round(total/sum(cfg.values()),8) if sum(cfg.values()) else 0.0, "eligible_components": list(eligible), "excluded_components": [k for k in components if k not in eligible]}

def _load_config(config):
    if config is None: return DEFAULTS
    import yaml
    data = yaml.safe_load(Path(config).read_text(encoding="utf-8")) or {}
    return {**DEFAULTS, **data, "weights": {**DEFAULTS["weights"], **data.get("weights", {})}, "thresholds": {**DEFAULTS["thresholds"], **data.get("thresholds", {})}}

def analyze_email(raw_email: str, *, config=None, word_pool_model=None):
    cfg = _load_config(config)
    if not isinstance(raw_email, str) or not raw_email.strip(): raise ValueError("Provide a non-empty RFC 5322 email message")
    message = Parser(policy=policy.default).parsestr(raw_email)
    subject = str(message.get("Subject", "")); body_parts=[]; html_parts=[]
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart" or part.get_content_disposition() == "attachment": continue
            try: content=part.get_content()
            except Exception: continue
            if part.get_content_type() == "text/html": html_parts.append(str(content))
            elif part.get_content_type() == "text/plain": body_parts.append(str(content))
    else:
        try: content=message.get_content()
        except Exception: content=""
        (html_parts if message.get_content_type()=="text/html" else body_parts).append(str(content))
    body="\n".join(body_parts); html_body="\n".join(html_parts) or None
    components={}; warnings=[]
    # Phase 1: use the saved fitted model; absence is explicit and never treated as a zero score.
    try:
        model=word_pool_model or WordPoolModel.load(ROOT / "phase 1" / "models" / "word_pool" / "model.joblib")
        if not (subject.strip() or body.strip()): components["word_pool"]=_component("unavailable",message="No subject or readable text body")
        else:
            result=model.analyze(subject,body); warnings += result.get("warnings",[])
            components["word_pool"]=_component("available",result["S_WP"],result.get("detected_ngrams",[])+result.get("detected_collocations",[])+result.get("cta_matches",[]),result)
    except FileNotFoundError as exc: components["word_pool"]=_component("unavailable",message=str(exc))
    except Exception as exc: components["word_pool"]=_component("error",message=f"{type(exc).__name__}: {exc}")
    # Phase 2: actual raw headers, preserving parser and scorer evidence.
    try:
        result=analyze_sender_header(raw_email)
        components["sender_header"]=_component("available",result["S_HDR"],result.get("header_anomalies",[])+result.get("spoofing_indicators",[])+result.get("domain_similarity_findings",[]),result) if result.get("S_HDR") is not None else _component("unavailable",details=result,message="Insufficient parsed sender/header signals")
        warnings += result.get("warnings",[])
    except Exception as exc: components["sender_header"]=_component("error",message=f"{type(exc).__name__}: {exc}")
    # Phase 3: relevant only when a sender address exists.
    try:
        sender=parseaddr(str(message.get("From", "")))[1]
        if not sender: components["temporary_email"]=_component("unavailable",message="Sender address is missing")
        else:
            result=analyze_temporary_email(sender); details=result.to_dict() if hasattr(result,"to_dict") else result
            score=details.get("S_TEMP")
            components["temporary_email"]=_component("available",score,details.get("matched_sources",[])+details.get("reputation_findings",[]),details) if score is not None else _component("unavailable",details=details,message="No usable temporary-email scoring evidence")
            warnings += details.get("warnings",[])
    except Exception as exc: components["temporary_email"]=_component("error",message=f"{type(exc).__name__}: {exc}")
    # Phase 4: URL lexical model analyzes each extracted URL and applies its configured max/mean aggregation.
    url_result=None
    try:
        url_result=analyze_email_urls(subject,body,html_body)
        if not url_result["url_count"]: components["url_analysis"]=_component("not_applicable",message="No URLs in the email")
        elif url_result.get("S_URL") is None: components["url_analysis"]=_component("unavailable",details=url_result,message="URLs were found but none could be scored")
        else: components["url_analysis"]=_component("available",url_result["S_URL"],url_result.get("original_urls",[]),url_result)
        warnings += url_result.get("warnings",[])
    except Exception as exc: components["url_analysis"]=_component("error",message=f"{type(exc).__name__}: {exc}")
    # Phase 5: static analysis of URL metadata and optional caller-supplied safe cached HTML only.
    urls=(url_result or {}).get("individual_url_scores",[])
    if not urls: components["website_analysis"]=_component("not_applicable",message="No suitable URL target")
    else:
        website_results=[]
        for item in urls:
            try:
                # No URL is fetched by default. Phase 5 acquisition deliberately disables live retrieval.
                website_results.append(analyze_website(item.get("normalized_url") or item.get("original_url")))
            except Exception as exc: website_results.append({"S_WEB":None,"status":"ERROR","original_url":item.get("original_url"),"error":f"{type(exc).__name__}: {exc}"})
        assessed=[x["S_WEB"] for x in website_results if x.get("S_WEB") is not None]
        web_score=max(assessed) if assessed else None
        components["website_analysis"]=_component("available",web_score,[],{"websites":website_results,"retrieval":"disabled"}) if web_score is not None else _component("unavailable",details={"websites":website_results,"retrieval":"disabled"},message="Static website analysis did not yield a score")
    fusion=fuse(components,cfg["weights"],cfg["thresholds"])
    return {"score":fusion["score"],"classification":fusion["classification"],"components":components,"evidence_coverage":fusion["evidence_coverage"],"eligible_components":fusion["eligible_components"],"excluded_components":fusion["excluded_components"],"effective_weights":fusion["effective_weights"],"extracted_urls":[x.get("original_url") for x in urls],"limitations":["Scores are risk heuristics, not calibrated phishing probabilities.","Website retrieval is disabled by default; website analysis uses URL metadata only.","Authentication-Results are unverified claims; SPF/DKIM/DMARC are not cryptographically checked."],"warnings":list(dict.fromkeys(warnings))}

def main(argv=None):
    parser=argparse.ArgumentParser(description="Unified six-phase phishing email risk assessment")
    parser.add_argument("email",nargs="?",help="Path to an RFC 5322 .eml file; defaults to stdin")
    parser.add_argument("--config",help="Optional YAML configuration")
    args=parser.parse_args(argv)
    raw=Path(args.email).read_text(encoding="utf-8",errors="replace") if args.email else sys.stdin.read()
    print(json.dumps(analyze_email(raw,config=args.config),indent=2,ensure_ascii=False))
    return 0
if __name__ == "__main__": raise SystemExit(main())
