"""Explainable, offline S_WEB scoring; all heuristics are provisional."""
from pathlib import Path
from urllib.parse import urlsplit
from difflib import SequenceMatcher
import re
from .domain_intelligence import domain_info
from .html_analysis import parse_html
from .acquisition import inspect_live
DEFAULT={"weights":{"D":.20,"N":.15,"I":.20,"C":.15,"F":.20,"S":.10},"aggregation":{"max_weight":.70,"mean_weight":.30},"minimum_available_weight":.50,"brand_similarity_threshold":.72,"brands":[{"name":"PayPal","domains":["paypal.com"]},{"name":"Microsoft","domains":["microsoft.com"]},{"name":"Google","domains":["google.com"]},{"name":"Apple","domains":["apple.com"]},{"name":"Amazon","domains":["amazon.com"]},{"name":"Netflix","domains":["netflix.com"]}],"third_party_auth_domains":["accounts.google.com","login.microsoftonline.com","appleid.apple.com","paypal.com"],"model_version":"5.0.0"}
class ConfigurationError(ValueError):pass
def load_config(config=None):
    c=dict(DEFAULT)
    if isinstance(config,(str,Path)):
        try:
            import yaml
            with open(config,encoding="utf8") as f:config=yaml.safe_load(f) or {}
        except ImportError as e:raise ConfigurationError("Install PyYAML or pass a config dictionary") from e
    if config:c.update(config)
    c["weights"]={**DEFAULT["weights"],**(c.get("weights") or {})};c["aggregation"]={**DEFAULT["aggregation"],**(c.get("aggregation") or {})}
    w=c["weights"]
    if set(w)!=set("DNICFS") or any(not isinstance(v,(int,float)) or v<0 for v in w.values()) or abs(sum(w.values())-1)>1e-9:raise ConfigurationError("website weights D,N,I,C,F,S must be nonnegative and sum to 1")
    a=c["aggregation"]
    if any(v<0 for v in a.values()) or abs(sum(a.values())-1)>1e-9:raise ConfigurationError("aggregation weights must be nonnegative and sum to 1")
    return c
def _result(score,status,evidence,source,why):return {"score":round(max(0,min(1,float(score))),8) if score is not None else None,"status":status,"evidence":evidence,"source":source,"explanation":why}
def _observed_num(obj,key):
    try:
        v=obj[key]
        if v is None:return None
        if isinstance(v,bool):return float(v)
        return max(0,min(1,float(v)))
    except (KeyError,TypeError,ValueError):return None
def analyze_website(url,config=None,cached_evidence=None):
    c=load_config(config);e=cached_evidence or {};original=str(url or "").strip();candidate=original if "://" in original else "https://"+original
    p=urlsplit(candidate);scheme=p.scheme.lower();host=(p.hostname or "").lower().rstrip(".")
    if scheme not in ("http","https") or not host:
        raise ValueError("URL must have an HTTP(S) scheme and hostname; supply Phase 4 normalized URL when available")
    d=domain_info(candidate);registered=d["registered_domain"];labels=host.split(".")
    brands=[]
    for brand in c["brands"]:
        name=brand["name"]; domains=brand.get("domains",[])
        if any(host==x or host.endswith("."+x) for x in domains):continue
        # Compare base domain text and mapped common digit substitutions; evidence remains URL-level.
        base=registered.split(".")[0].lower();mapped=base.translate(str.maketrans({"0":"o","1":"l","3":"e","5":"s"}))
        sim=max(SequenceMatcher(None,name.lower().replace(" ",""),base).ratio(),SequenceMatcher(None,name.lower().replace(" ",""),mapped).ratio())
        if name.lower() in host and not any(host==x or host.endswith("."+x) for x in domains):sim=max(sim,.78)
        if sim>=float(c["brand_similarity_threshold"]):brands.append({"brand":name,"registered_domain":registered,"similarity":round(sim,3),"evidence":"hostname label similarity; visual content not assessed"})
    title=None;parsed=None;analysis_mode="metadata_only";warnings=[]
    html=e.get("html")
    if html is not None:
            parsed=parse_html(str(html),candidate,c.get("third_party_auth_domains",[]));warnings.extend(parsed["warnings"]);analysis_mode=e.get("analysis_mode","cached_fixture");
    # D and I can use URL-level evidence, but reputation and registration remain unknown without evidence.
    age=e.get("registration_age_days")
    reg=e.get("registration") if isinstance(e.get("registration"),dict) else {}
    if not (reg.get("source") and (reg.get("observed_at") or reg.get("observation_timestamp"))):age=None
    age_risk=None
    try:
        if age is not None:
            age=float(age)
            if age<0:raise ValueError("registration_age_days cannot be negative")
            age_risk=.50 if age<=14 else .30 if age<=30 else .15 if age<=90 else 0.0
    except (ValueError,TypeError):age=None
    reputation=e.get("reputation_findings") or []
    reputation_risks=[]
    for finding in reputation:
        if isinstance(finding,dict):
            try:reputation_risks.append(max(0,min(1,float(finding.get("risk",finding.get("score"))))))
            except (TypeError,ValueError):pass
    rep_risk=max(reputation_risks,default=0)
    d_score=min(1,.35*bool(d["is_ip"])+.08*max(0,len(labels)-3)+.25*rep_risk+(.20*age_risk if age_risk is not None else 0))
    d_evidence=[]
    if d["is_ip"]:d_evidence.append("IP literal hostname")
    if len(labels)>4:d_evidence.append(f"{len(labels)-2} subdomain labels")
    if reputation:d_evidence.extend(reputation)
    if age_risk is not None:d_evidence.append({"registration_age_days":age,"risk_mapping":age_risk,"source":(e.get("registration") or {}).get("source","caller_supplied_registration") if isinstance(e.get("registration"),dict) else "caller_supplied_registration"})
    D=_result(d_score,"OBSERVED",d_evidence,"parsed_url" if not e.get("reputation_findings") else "parsed_url+cached_reputation","URL domain structure and optional caller-supplied reputation; registration age is not inferred")
    # Domain/network evidence is available only if lookup observations were explicitly supplied.
    dns=e.get("dns");tls=e.get("tls");N=None;n_ev=[]
    vals=[]
    if isinstance(dns,dict):
        n_ev.append({"dns":dns}); status=(dns.get("status") or "unknown").lower(); vals.append(1.0 if status in ("nxdomain","failed","inconsistent") else 0.0 if status in ("resolved","ok") else None)
    if isinstance(tls,dict):
        n_ev.append({"tls":tls}); status=(tls.get("status") or "unknown").lower(); vals.append(1.0 if status in ("invalid","expired","hostname_mismatch","failed") else 0.0 if status in ("valid","ok") else None)
    vals=[v for v in vals if v is not None]
    if vals:N=sum(vals)/len(vals)
    Nres=_result(N,"OBSERVED" if N is not None else ("UNAVAILABLE" if dns is not None or tls is not None else "NOT_COLLECTED"),n_ev,"caller_cached_network_evidence","DNS and TLS findings require explicit verified evidence; HTTPS alone is not a trust signal")
    Ival=min(1,max((x["similarity"] for x in brands),default=0)) if brands else 0.0
    if parsed and parsed["title"]:
        title=parsed["title"]
        for b in c["brands"]:
            if b["name"].lower() in title.lower() and not any(host==x or host.endswith("."+x) for x in b.get("domains",[])):
                finding={"brand":b["name"],"registered_domain":registered,"similarity":.8,"evidence":"brand in page title on unrelated domain"}
                if finding not in brands:brands.append(finding)
        Ival=max(Ival,.8 if brands and any("page title" in x["evidence"] for x in brands) else 0)
    I=_result(Ival,"OBSERVED",brands or (["No configured brand similarity exceeded threshold"] if parsed else []),"url_and_cached_html" if parsed else "parsed_url","Text/domain identity comparison only; no visual inspection was performed")
    C=F=S=None;content_findings=[];form_findings=[];structure_findings=[]
    if parsed is not None:
        lang=parsed["suspicious_language"];C=min(1,.25*len(lang)+.1*bool(re.search(r"(?i)bank|social security|credit card",parsed["text_excerpt"])))
        content_findings=lang
        if parsed["title"]:content_findings.append({"page_title":parsed["title"]})
        forms=parsed["form_features"]
        if forms:
            form_findings=forms
            F=min(1,.15*bool(forms)+.30*any(x["password_fields"] for x in forms)+.35*any(x["external_action"] for x in forms)+.25*any(x["payment_fields"] for x in forms)+.10*any(x["hidden_fields"] for x in forms))
        else:F=0.0
        suspicious=[x for x in parsed["iframes"]+parsed["external_scripts"] if x and urlsplit(x if "://" in x else candidate).hostname not in (host,None)]
        structure_findings={"hidden_fields":sum(x["hidden_fields"] for x in forms),"iframes":parsed["iframes"],"external_scripts":parsed["external_scripts"],"external_references":len(suspicious),"static_redirect_indicators":parsed["static_redirect_indicators"]}
        S=min(1,.15*bool(structure_findings["hidden_fields"])+.20*(len(parsed["iframes"])>2)+.15*(len(parsed["external_scripts"])>10)+.20*bool(any(x["external_action"] for x in forms))+.30*bool(parsed["static_redirect_indicators"]))
    components={"D":D,"N":Nres,"I":I,"C":_result(C,"OBSERVED" if C is not None else "NOT_COLLECTED",content_findings,"cached_html" if parsed else "none","Static text/title inspection; language cues alone are weak evidence"),"F":_result(F,"OBSERVED" if F is not None else "NOT_COLLECTED",form_findings,"cached_html" if parsed else "none","Form fields and destinations only; no form was submitted"),"S":_result(S,"OBSERVED" if S is not None else "NOT_COLLECTED",structure_findings,"cached_html" if parsed else "none","Static HTML structure only; scripts were not executed")}
    available={k:v["score"] for k,v in components.items() if v["score"] is not None}; coverage=sum(c["weights"][k] for k in available)
    score=(sum(c["weights"][k]*v for k,v in available.items())/coverage) if coverage>=c["minimum_available_weight"] else None
    effective={k:c["weights"][k]/coverage for k in available} if score is not None else {}
    missing=[k for k,v in components.items() if v["score"] is None]
    return {"S_WEB":round(score,8) if score is not None else None,"status":"COMPLETE" if not missing else "PARTIAL" if score is not None else "INCOMPLETE","original_url":original,"normalized_url":candidate,"registered_domain":registered,"component_scores":components,"weights":c["weights"],"effective_weights":effective,"domain_findings":{"hostname":host,"registered_domain":registered,"is_ip":d["is_ip"],"registration_age_days":age,"reputation":e.get("reputation_findings",[])},"dns_findings":dns,"tls_findings":tls,"registration_findings":e.get("registration",None),"brand_findings":brands,"page_metadata":{"title":parsed["title"],"meta":parsed["meta"]} if parsed else {"status":"NOT_COLLECTED"},"content_findings":content_findings,"form_findings":form_findings,"structure_findings":structure_findings,"evidence_sources":sorted({v["source"] for v in components.values() if v["status"]=="OBSERVED"}),"missing_signals":missing,"score_completeness":round(coverage,8),"warnings":warnings,"analysis_mode":analysis_mode,"model_version":c["model_version"]}
def analyze_email_websites(urls,config=None,cached_evidence_by_url=None):
    c=load_config(config);results=[]
    for item in urls or []:
        url=item.get("normalized_url") or item.get("url") if isinstance(item,dict) else str(item)
        if not url:continue
        results.append(analyze_website(url,c,(cached_evidence_by_url or {}).get(url)))
    vals=[x["S_WEB"] for x in results if x["S_WEB"] is not None];hi=max(vals) if vals else None;mean=sum(vals)/len(vals) if vals else None;a=c["aggregation"]
    score=a["max_weight"]*hi+a["mean_weight"]*mean if vals else None
    return {"S_WEB":round(score,8) if score is not None else None,"status":"NO_WEBSITES" if not results else "PARTIAL" if any(x["status"]!="COMPLETE" for x in results) else "COMPLETE","websites":results,"website_count":len(results),"incomplete_count":sum(x["status"]!="COMPLETE" for x in results),"highest_website_risk":hi,"mean_website_risk":round(mean,8) if mean is not None else None,"aggregation_weights":a,"model_version":c["model_version"]}
