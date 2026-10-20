from dataclasses import dataclass, asdict
from html.parser import HTMLParser
import re
_URL=re.compile(r"(?i)(?:(?:https?|ftp)://|www\.)[^\s<>\"']+")
_TRAILING=".,;:!?)]}>'\""
@dataclass
class ExtractedURL:
    original_url:str
    source:str
    anchor_text:str|None=None
    occurrences:list|None=None
    def to_dict(self): return asdict(self)
class _Anchors(HTMLParser):
    def __init__(self): super().__init__(convert_charrefs=True); self.items=[]; self.href=None; self.text=[]
    def handle_starttag(self,tag,attrs):
        if tag.lower()=="a": self.href=dict(attrs).get("href"); self.text=[]
    def handle_data(self,data):
        if self.href is not None:self.text.append(data)
    def handle_endtag(self,tag):
        if tag.lower()=="a" and self.href is not None:
            if self.href:self.items.append((self.href," ".join(self.text).strip() or None))
            self.href=None; self.text=[]
def _clean(s):
    s=s.strip()
    while s and s[-1] in _TRAILING:s=s[:-1]
    return s
def extract_urls(subject="",body="",html_body=None):
    found=[]; warnings=[]
    def add(v,src,anchor=None):
        v=_clean(v)
        if not v:return
        found.append(ExtractedURL(v,src,anchor,[src]))
    for src,txt in (("subject",subject or ""),("body",body or "")):
        for m in _URL.finditer(str(txt)):add(m.group(),src)
    if html_body:
        try:
            p=_Anchors();p.feed(str(html_body));p.close()
            for href,label in p.items:
                if re.match(r"(?i)^(https?|ftp)://|^www\.",href or ""):add(href,"html_anchor",label)
            for m in _URL.finditer(re.sub(r"<[^>]*>"," ",str(html_body))):add(m.group(),"html_text")
        except Exception as e:warnings.append(f"HTML parsing warning: {type(e).__name__}")
    merged=[]; index={}
    for x in found:
        if x.original_url in index:
            y=merged[index[x.original_url]];y.occurrences.append(x.source)
            if x.anchor_text and not y.anchor_text:y.anchor_text=x.anchor_text
        else:index[x.original_url]=len(merged);merged.append(x)
    return {"urls":[x.to_dict() for x in merged],"warnings":warnings}
