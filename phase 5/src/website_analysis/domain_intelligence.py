"""Offline domain parsing and caller-supplied domain evidence adapter."""
from urllib.parse import urlsplit
import ipaddress
def domain_info(url):
    p=urlsplit(url if "://" in url else "https://"+url); host=(p.hostname or "").rstrip(".").lower()
    try: ipaddress.ip_address(host); return {"hostname":host,"registered_domain":host,"is_ip":True,"source":"parsed_url"}
    except ValueError: pass
    try:
        import publicsuffix2
        registered=publicsuffix2.get_sld(host) or host
    except ImportError:
        labels=host.split(".");registered=".".join(labels[-2:]) if len(labels)>1 else host
    return {"hostname":host,"registered_domain":registered,"is_ip":False,"source":"parsed_url"}
def evidence_state(evidence,key):
    if not evidence or key not in evidence:return "NOT_COLLECTED",None
    value=evidence[key]
    if value is None:return "UNAVAILABLE",None
    return "OBSERVED",value
