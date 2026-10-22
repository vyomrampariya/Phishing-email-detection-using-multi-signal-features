"""Transparent deterministic URL risk scores; this is not a trained probability model."""
from urllib.parse import urlsplit
import re
from difflib import SequenceMatcher
import json
from pathlib import Path
from .url_features import extract_features
from .extraction import extract_urls

DEFAULT={"weights":{"L":.15,"H":.20,"E":.20,"D":.20,"R":.15,"T":.10},"aggregation":{"max_weight":.70,"mean_weight":.30},"minimum_available_weight":.50,"protected_brands":["paypal","microsoft","google","apple","amazon","netflix"],"trusted_domains":["paypal.com","paypal.me","microsoft.com","google.com","apple.com","amazon.com","netflix.com"],"shorteners":["bit.ly","tinyurl.com","t.co","is.gd","ow.ly","goo.gl","buff.ly"],"model_version":"4.0.0"}
class ConfigurationError(ValueError):pass
def load_config(config=None):
    c=dict(DEFAULT)
    if isinstance(config,(str,Path)):
        try:
            import yaml
            with open(config,encoding="utf8") as f:config=yaml.safe_load(f) or {}
        except ImportError as e:raise ConfigurationError("PyYAML is needed to load YAML; pass a dict or install it") from e
    if config:c.update(config)
    c["weights"]={**DEFAULT["weights"],**(c.get("weights") or {})}
    c["aggregation"]={**DEFAULT["aggregation"],**(c.get("aggregation") or {})}
    w=c["weights"]
    if set(w)!={"L","H","E","D","R","T"} or any(not isinstance(v,(int,float)) or v<0 for v in w.values()) or abs(sum(w.values())-1)>1e-9:raise ConfigurationError("component weights must be non-negative and sum to 1")
    a=c["aggregation"]
    if any(v<0 for v in a.values()) or abs(sum(a.values())-1)>1e-9:raise ConfigurationError("aggregation weights must be non-negative and sum to 1")
    return c
def _comp(score,status,evidence,explanation,source="lexical"):
    return {"score":round(max(0,min(1,float(score))),8),"status":status,"evidence":evidence,"source":source,"explanation":explanation}
def analyze_url(url,config=None,threat_intelligence=None):
    c=load_config(config);f=extract_features(url,c);host=f["normalization"].get("ascii_hostname") or "";domain=f["registrable_domain"]
    valid=f["normalization"]["normalized_url"] is not None
    if not valid:
        comps={k:_comp(0,"unavailable",[],"URL could not be normalized") for k in c["weights"]}; return {"original_url":url,"normalized_url":None,"features":f,"component_scores":comps,"S_URL":None,"status":"INCOMPLETE","weights":c["weights"],"effective_weights":{},"score_completeness":0,"missing_signals":list(comps),"warnings":f["normalization_warnings"],"domain_similarity_findings":[],"redirect_indicators":[],"threat_intelligence_findings":[]}
    L=min(1,max(0,(f["url_length"]-75)/225)*.45+min(1,f["path_segments"]/12)*.2+min(1,f["query_parameters"]/12)*.2+min(1,f["encoded_characters"]/20)*.15)
    H=min(1,(.42 if f["is_ip"] else 0)+(.18 if f["unusual_port"] else 0)+min(.2,f["subdomain_count"]*.04)+(.1 if f["hostname_numeric"] else 0)+(.1 if f["punycode"] else 0)+(.06 if f.get("hyphenated_labels") else 0))
    E=min(1,max(0,(f["hostname_entropy"]-2)/3)*.35+max(0,(f["path_entropy"]-2)/3)*.25+max(0,(f["query_entropy"]-2)/3)*.2+min(.2,f["encoding_layers"]*.1))
    brands=c.get("protected_brands",[]); trusted=c.get("trusted_domains",[]);similar=[]
    if domain not in trusted:
        for b in brands:
            # Compare the registrable label only. Requiring a close, similarly
            # sized spelling avoids treating ordinary compounds as brands.
            first=domain.split(".")[0].lower().replace("-", "")
            brand=b.lower().replace("-", "")
            s=SequenceMatcher(None,brand,first).ratio()
            # Catch homoglyph-esque substitutions after a small common mapping.
            mapped=domain.lower().translate(str.maketrans({"0":"o","1":"l","3":"e","5":"s","@":"a"}))
            s=max(s,SequenceMatcher(None,b.lower(),mapped.split(".")[0].replace("-", "")).ratio())
            if len(first) < 5 or abs(len(first)-len(brand)) > 1:
                s=0.0
            if s>=float(c.get("brand_similarity_threshold",.80)):similar.append({"brand":b,"similarity":round(s,3),"domain":domain})
    D=max((x["similarity"] for x in similar),default=(.20 if f["punycode"] else 0))
    indicators=[]
    if f["redirect_parameters"]:indicators.append({"type":"redirect_parameter","parameters":f["redirect_parameters"]})
    if f["nested_url_parameters"]:indicators.append({"type":"nested_url_parameter","count":len(f["nested_url_parameters"])})
    if f["at_in_authority"]:indicators.append({"type":"userinfo_authority"})
    if domain in c["shorteners"]:indicators.append({"type":"shortener_domain","domain":domain})
    R=min(1,.25*bool(f["redirect_parameters"])+.25*bool(f["nested_url_parameters"])+.25*f["at_in_authority"]+.35*(domain in c["shorteners"]))
    T=None;ti=[]
    if threat_intelligence is not None:
        # Provider evidence shape is caller-controlled: risk, source, retrieved_at, status.
        try:
            T=float(threat_intelligence["risk"]); assert 0<=T<=1
            ti=[dict(threat_intelligence)]
            tstatus="available"
        except Exception:T=None;tstatus="unavailable"
    else:tstatus="unavailable"
    raw={"L":L,"H":H,"E":E,"D":D,"R":R,"T":T}; comps={}
    for k,val in raw.items():
        ev=[]
        if k=="L":ev=[f"URL length {f['url_length']}",f"path segments {f['path_segments']}",f"query parameters {f['query_parameters']}"]
        elif k=="H":ev=[f"IP literal={f['is_ip']}",f"unusual port={f['unusual_port']}",f"subdomains={f['subdomain_count']}"]
        elif k=="E":ev=[f"host/path/query entropy {f['hostname_entropy']:.2f}/{f['path_entropy']:.2f}/{f['query_entropy']:.2f}",f"encoding layers={f['encoding_layers']}"]
        elif k=="D":ev=similar or (["punycode hostname"] if f["punycode"] else [])
        elif k=="R":ev=indicators
        else:ev=ti
        comps[k]=_comp(val if val is not None else 0,"available" if val is not None else tstatus,ev,"Component risk heuristic" if val is not None else "No threat-intelligence evidence available", "caller_provider" if k=="T" else "lexical")
    available={k:v for k,v in raw.items() if v is not None}; aw=sum(c["weights"][k] for k in available); minimum=c["minimum_available_weight"]
    score=sum(c["weights"][k]*v for k,v in available.items())/aw if aw>=minimum and aw>0 else None
    eff={k:c["weights"][k]/aw for k in available} if score is not None else {}
    return {"original_url":url,"normalized_url":f["normalization"]["normalized_url"],"features":f,"component_scores":comps,"S_URL":round(score,8) if score is not None else None,"status":"COMPLETE" if len(available)==len(raw) else "PARTIAL" if score is not None else "INCOMPLETE","weights":c["weights"],"effective_weights":eff,"score_completeness":round(aw,8),"missing_signals":[k for k in raw if k not in available],"domain_similarity_findings":similar,"redirect_indicators":indicators,"threat_intelligence_findings":ti,"warnings":f["normalization_warnings"],"model_version":c["model_version"]}
def analyze_email_urls(subject="",body="",html_body=None,config=None,threat_intelligence_by_url=None):
    c=load_config(config); ext=extract_urls(subject,body,html_body); results=[]
    for u in ext["urls"]:
        item=analyze_url(u["original_url"],c,(threat_intelligence_by_url or {}).get(u["original_url"]))
        anchor=u.get("anchor_text") or ""
        visible=re.search(r"(?i)(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})",anchor)
        if visible and item.get("S_URL") is not None:
            shown=visible.group(1).lower()
            actual=item.get("features",{}).get("registrable_domain","").lower()
            try: shown=__import__("publicsuffix2").get_sld(shown) or shown
            except Exception: shown=".".join(shown.split(".")[-2:])
            if shown!=actual:
                item["anchor_mismatch"]={"visible_domain":shown,"destination_domain":actual}
                d=item["component_scores"]["D"]
                d["score"]=max(.85,d["score"]); d["evidence"].append({"type":"anchor_destination_mismatch","visible_domain":shown,"destination_domain":actual})
                available={k:v["score"] for k,v in item["component_scores"].items() if v["status"]=="available"}
                total=sum(c["weights"][k] for k in available)
                item["S_URL"]=round(sum(c["weights"][k]*v for k,v in available.items())/total,8) if total>=c["minimum_available_weight"] else None
        results.append({**item,"extraction":u})
    vals=[x["S_URL"] for x in results if x["S_URL"] is not None]; high=max(vals) if vals else None; mean=sum(vals)/len(vals) if vals else None
    agg=c["aggregation"];score=agg["max_weight"]*high+agg["mean_weight"]*mean if vals else None
    return {"S_URL":round(score,8) if score is not None else None,"status":"NO_URLS" if not results else ("PARTIAL" if any(x["status"]!="COMPLETE" for x in results) else "COMPLETE"),"original_urls":[x["original_url"] for x in results],"normalized_urls":[x["normalized_url"] for x in results],"url_count":len(results),"individual_url_scores":results,"component_scores":[x["component_scores"] for x in results],"weights":c["weights"],"effective_weights":[x["effective_weights"] for x in results],"highest_url_risk":high,"mean_url_risk":round(mean,8) if mean is not None else None,"domain_similarity_findings":[y for x in results for y in x["domain_similarity_findings"]],"redirect_indicators":[y for x in results for y in x["redirect_indicators"]],"threat_intelligence_findings":[y for x in results for y in x["threat_intelligence_findings"]],"evidence_sources":sorted({s for x in results for v in x["component_scores"].values() if v["status"]=="available" for s in [v["source"]]}),"missing_signals":[{"url":x["original_url"],"signals":x["missing_signals"]} for x in results if x["missing_signals"]],"score_completeness":round(sum(x["score_completeness"] for x in results)/len(results),8) if results else 0,"warnings":ext["warnings"]+[w for x in results for w in x["warnings"]],"model_version":c["model_version"]}
