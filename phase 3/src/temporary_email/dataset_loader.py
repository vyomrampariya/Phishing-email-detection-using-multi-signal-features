"""Load and normalize plain-text disposable domain lists with provenance."""
from __future__ import annotations
import json
from pathlib import Path
from .domain_normalizer import normalize_domain, InvalidDomainError

def normalize_list_file(path, source_name: str):
    raw=Path(path).read_text(encoding="utf-8-sig").splitlines()
    records={}; malformed=[]; duplicates=0
    for line_no,line in enumerate(raw,1):
        value=line.strip()
        if not value or value.startswith(("#","!","//")): continue
        value=value[2:].strip() if value.startswith("*.") else value
        try: domain=normalize_domain(value)
        except InvalidDomainError: malformed.append({"line":line_no,"value":value}); continue
        if domain in records: duplicates+=1; records[domain]["source_dataset"].append(source_name)
        else: records[domain]={"domain":domain,"normalized_domain":domain,"is_disposable":True,"provider_name":None,"source_dataset":[source_name],"source_urls":[],"last_verified":None,"classification_confidence":0.9,"evidence_status":"listed_unverified_locally","domain_age_days":None,"reputation_status":"UNKNOWN","notes":"Imported from a community list; not a malicious-domain label."}
    for item in records.values(): item["source_dataset"]=sorted(set(item["source_dataset"]))
    return {"records":records,"malformed":malformed,"duplicate_count":duplicates,"input_lines":len(raw)}

def write_processed(dataset, output_path):
    Path(output_path).parent.mkdir(parents=True,exist_ok=True)
    Path(output_path).write_text(json.dumps(dataset["records"],ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
