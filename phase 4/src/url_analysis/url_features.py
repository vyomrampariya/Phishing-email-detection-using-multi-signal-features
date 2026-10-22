from urllib.parse import urlsplit,parse_qsl
from collections import Counter
import math,ipaddress,re
from .normalization import normalize_url
def entropy(s):
    if not s:return 0.0
    n=len(s);return -sum((c/n)*math.log2(c/n) for c in Counter(s).values())
def extract_features(url,config=None):
    n=normalize_url(url);p=urlsplit(n["normalized_url"] or "");host=(n.get("hostname") or "").lower().rstrip(".");path=p.path or "";query=p.query or ""
    try:ip=ipaddress.ip_address(host.strip("[]"));is_ip=True;private=ip.is_private or ip.is_reserved or ip.is_loopback
    except ValueError:is_ip=False;private=False
    labels=host.split(".") if host else [];params=parse_qsl(query,keep_blank_values=True);port=p.port
    try:registrable=__import__("publicsuffix2").get_sld(n.get("ascii_hostname") or host) or host
    except Exception:registrable=".".join(labels[-2:]) if len(labels)>1 else host
    keys=(config or {}).get("redirect_parameters",["url","uri","redirect","redirect_url","next","target","dest","destination","continue","return","returnurl"])
    return {"normalization":n,"url_length":len(str(url)),"hostname_length":len(host),"path_length":len(path),"query_length":len(query),"path_segments":len([x for x in path.split("/") if x]),"query_parameters":len(params),"subdomain_count":max(0,len(labels)-2),"hyphenated_labels":[x for x in labels if "-" in x],"unusual_separators":sum(str(url).count(c) for c in "@\\"),"encoded_characters":len(re.findall(r"%[0-9a-fA-F]{2}",str(url))),"special_characters":sum(not c.isalnum() for c in str(url)),"is_ip":is_ip,"is_private_ip":private,"port":port,"unusual_port":port is not None and port not in (80,443,21),"punycode":any(x.startswith("xn--") for x in labels),"hostname_entropy":entropy(host),"path_entropy":entropy(path),"query_entropy":entropy(query),"encoding_layers":len(re.findall(r"%25[0-9a-fA-F]{2}",str(url))),"at_in_authority":"@" in p.netloc,"registrable_domain":registrable,"labels":labels,"redirect_parameters":[k for k,v in params if k.lower() in keys],"nested_url_parameters":[v for k,v in params if re.search(r"(?i)(https?%3a|https?://)",v)],"hostname_numeric":bool(host) and not is_ip and bool(re.fullmatch(r"[0-9.]+",host)),"normalization_warnings":n["warnings"]}
