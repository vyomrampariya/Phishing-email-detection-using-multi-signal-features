"""Bounded, non-executing HTML feature extraction; never stores full page text."""
from html.parser import HTMLParser
from urllib.parse import urlsplit,urljoin
import re
MAX_HTML=1_000_000
class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True);self.title=False;self.title_parts=[];self.meta={};self.forms=[];self.form=None;self.text=[];self.iframes=[];self.external_scripts=[];self.inline_scripts=[];self.in_script=False;self.script_parts=[];self.hidden_count=0
    def handle_starttag(self,tag,attrs):
        a=dict(attrs);tag=tag.lower()
        if tag=="title":self.title=True
        if tag=="meta" and a.get("name","").lower() in ("description","application-name"):self.meta[a.get("name","").lower()]=a.get("content","")[:300]
        if tag=="form":self.form={"action":a.get("action",""),"method":a.get("method","get").lower(),"fields":[],"hidden_fields":0}
        if self.form is not None and tag=="input":
            item={"type":a.get("type","text").lower(),"name":a.get("name","").lower(),"autocomplete":a.get("autocomplete","").lower()}
            self.form["fields"].append(item)
            if item["type"]=="hidden" or "hidden" in a.get("style","").lower() or "hidden" in (a.get("class","").lower()):self.form["hidden_fields"]+=1
        if tag=="iframe":self.iframes.append(a.get("src",""))
        if tag=="script":
            self.in_script=True;self.script_parts=[]
            if a.get("src"):self.external_scripts.append(a["src"])
    def handle_endtag(self,tag):
        if tag.lower()=="title":self.title=False
        if tag.lower()=="form" and self.form is not None:self.forms.append(self.form);self.form=None
        if tag.lower()=="script" and self.in_script:
            self.inline_scripts.append(" ".join(self.script_parts)[:2000]);self.in_script=False
    def handle_data(self,data):
        if self.title:self.title_parts.append(data)
        if self.in_script:self.script_parts.append(data)
        self.text.append(data)
def parse_html(html,base_url,third_party_auth_domains=None):
    if not isinstance(html,str):raise TypeError("html must be text")
    if len(html)>MAX_HTML:raise ValueError(f"HTML fixture exceeds {MAX_HTML} byte safety limit")
    p=_Page();warnings=[]
    try:
        p.feed(html);p.close()
        if p.form is not None:p.forms.append(p.form);p.form=None
    except Exception as e:warnings.append(f"HTML parse warning: {type(e).__name__}")
    text=" ".join(p.text);title=" ".join(p.title_parts).strip()[:300];host=(urlsplit(base_url).hostname or "").lower()
    forms=[];allowed=set(third_party_auth_domains or [])
    for f in p.forms:
        action=f["action"];action_host=(urlsplit(urljoin(base_url,action)).hostname or host).lower()
        third_party=any(action_host==x or action_host.endswith("."+x) for x in allowed)
        forms.append({**f,"action_host":action_host,"external_action":bool(action_host and host and action_host!=host and not third_party),"third_party_destination":third_party,"password_fields":sum(x["type"]=="password" for x in f["fields"]),"identity_fields":sum(x["type"] in ("email","text") and any(k in x["name"] for k in ("user","email","login")) for x in f["fields"]),"payment_fields":sum(any(k in x["name"] for k in ("card","bank","ssn","account")) for x in f["fields"])})
    words=text.lower();patterns={"urgency":r"\b(urgent|immediately|within 24 hours|act now)\b","suspension":r"\b(suspend(?:ed|sion)?|deactivat(?:ed|ion))\b","credential_request":r"\b(confirm|verify|validate|update)\s+(your\s+)?(password|account|credentials|identity)\b","payment_demand":r"\b(payment required|pay now|outstanding payment)\b"}
    language=[k for k,v in patterns.items() if re.search(v,words)]
    static_redirects=[s for s in p.inline_scripts if re.search(r"(?i)(window\.)?location\.(href|replace|assign)|meta\s+http-equiv\s*=\s*['\"]?refresh",s)]
    return {"title":title or None,"meta":p.meta,"text_excerpt":text[:500],"form_features":forms,"suspicious_language":language,"iframes":p.iframes[:30],"external_scripts":p.external_scripts[:30],"static_redirect_indicators":static_redirects,"text_length":len(text),"warnings":warnings}
