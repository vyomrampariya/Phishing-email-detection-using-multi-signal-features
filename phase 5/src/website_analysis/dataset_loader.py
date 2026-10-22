"""Dataset hygiene utilities; preserve input records and source labels."""
from urllib.parse import urlsplit
from .domain_intelligence import domain_info
def deduplicate(records):
    output=[];seen={};duplicates=[]
    for row in records:
        url=row.get("normalized_url") or row.get("url") or row.get("original_url")
        if not url:continue
        key=url.strip().rstrip("/").lower()
        if key in seen:duplicates.append({"key":key,"first":seen[key],"duplicate":row});continue
        seen[key]=row;info=domain_info(url)
        output.append({**row,"normalized_url":url,"registered_domain":info["registered_domain"]})
    return output,duplicates
def grouped_split(records,seed=42,train=.7,validation=.15):
    """Stable group split by registered domain; prevents domain leakage."""
    import random
    groups={}
    for row in records:groups.setdefault(row.get("registered_domain") or domain_info(row["normalized_url"])["registered_domain"],[]).append(row)
    keys=sorted(groups);random.Random(seed).shuffle(keys);a=int(len(keys)*train);b=int(len(keys)*(train+validation));out={"train":[],"validation":[],"test":[]}
    for i,k in enumerate(keys):out["train" if i<a else "validation" if i<b else "test"].extend(groups[k])
    return out
