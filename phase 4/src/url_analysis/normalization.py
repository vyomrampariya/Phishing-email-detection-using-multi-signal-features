from urllib.parse import urlsplit,urlunsplit,quote,unquote
import ipaddress,re
def normalize_url(url):
    original=str(url or "").strip();candidate=original;warnings=[]
    if not candidate:return {"original_url":original,"normalized_url":None,"hostname":None,"warnings":["empty URL"]}
    if candidate.startswith("//"):candidate="https:"+candidate
    elif not re.match(r"(?i)^[a-z][a-z0-9+.-]*://",candidate):candidate="https://"+candidate
    try:
        p=urlsplit(candidate)
        if p.scheme.lower() not in ("http","https","ftp"):raise ValueError("unsupported scheme")
        host=p.hostname
        if not host:raise ValueError("missing hostname")
        try:ipaddress.ip_address(host);ahost=host.lower()
        except ValueError:
            try:
                import idna
                ahost=idna.encode(host.rstrip("."),uts46=True,std3_rules=True).decode().lower()
            except ImportError:
                # Python's IDNA codec is a conservative dependency-free fallback (IDNA2003).
                ahost=host.rstrip(".").encode("idna").decode("ascii").lower()
        auth=""
        if p.username is not None:
            auth=quote(unquote(p.username),safe="")
            if p.password is not None:auth+=":"+quote(unquote(p.password),safe="")
            auth+="@"
        port=p.port
        display=f"[{ahost}]" if ":" in ahost and not ahost.startswith("[") else ahost
        default=(p.scheme.lower(),port) in (("http",80),("https",443),("ftp",21))
        netloc=auth+display+(f":{port}" if port and not default else "")
        return {"original_url":original,"normalized_url":urlunsplit((p.scheme.lower(),netloc,p.path or "",p.query,p.fragment)),"hostname":host,"ascii_hostname":ahost.strip("[]"),"warnings":warnings}
    except Exception as e:return {"original_url":original,"normalized_url":None,"hostname":None,"warnings":[f"normalization failed: {e}"]}
