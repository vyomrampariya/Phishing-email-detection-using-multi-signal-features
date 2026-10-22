"""Exact-match disposable database lookup."""
from pathlib import Path
import json
from .domain_normalizer import normalize_domain, InvalidDomainError

class DisposableDatabase:
    def __init__(self, records=None, source_name="local-fixture", subdomain_matching=False):
        self.records={}; self.subdomain_matching=subdomain_matching
        for key,value in (records or {}).items():
            try: d=normalize_domain(key)
            except InvalidDomainError: continue
            self.records[d]=value if isinstance(value,dict) else {"source_dataset":[source_name]}
    @classmethod
    def from_file(cls,path,subdomain_matching=False):
        p=Path(path)
        if not p.exists(): return cls({},subdomain_matching=subdomain_matching)
        if p.suffix.lower()==".json": data=json.loads(p.read_text(encoding="utf-8")); return cls(data,subdomain_matching=subdomain_matching)
        rows={}
        for line in p.read_text(encoding="utf-8-sig").splitlines():
            d=line.strip()
            if d and not d.startswith("#"): rows[d]={"source_dataset":[p.name]}
        return cls(rows,subdomain_matching=subdomain_matching)
    def lookup(self,domain):
        try: domain=normalize_domain(domain)
        except InvalidDomainError: return {"matched":False,"sources":[],"status":"INVALID","matched_domain":None}
        if domain in self.records: key=domain
        elif self.subdomain_matching:
            matches=[d for d in self.records if domain.endswith("."+d)]
            key=max(matches,key=len) if matches else None
        else: key=None
        if key is None: return {"matched":False,"sources":[],"status":"OBSERVED","matched_domain":None}
        record=self.records[key]; sources=record.get("source_dataset",record.get("sources",["local-list"]))
        if isinstance(sources,str): sources=[sources]
        return {"matched":True,"sources":sorted(set(sources)),"status":"OBSERVED","matched_domain":key,"record":record}
