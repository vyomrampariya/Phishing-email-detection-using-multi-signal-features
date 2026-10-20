"""Small transparent dataset utilities; source records are never modified in-place."""
from urllib.parse import urlsplit
import hashlib
def normalized_key(url):
    from .normalization import normalize_url
    n=normalize_url(url).get("normalized_url")
    return n or str(url).strip()
def deduplicate(records):
    seen={};out=[];duplicates=[]
    for row in records:
        key=normalized_key(row["url"])
        if key in seen:
            duplicates.append({"key":key,"first":seen[key],"duplicate":row});continue
        seen[key]=row;out.append({**row,"normalized_url":key,"domain":urlsplit(key).hostname})
    return out,duplicates
def grouped_split(records,seed=42,train=.7,validation=.15):
    """Deterministic domain-group split; domains never cross partitions."""
    import random
    groups={}
    for row in records:groups.setdefault(row.get("domain") or urlsplit(row["normalized_url"]).hostname,[]).append(row)
    keys=sorted(groups);random.Random(seed).shuffle(keys);n=len(keys);a=int(n*train);b=int(n*(train+validation))
    parts={"train":[],"validation":[],"test":[]}
    for i,k in enumerate(keys):parts["train" if i<a else "validation" if i<b else "test"].extend(groups[k])
    return parts
