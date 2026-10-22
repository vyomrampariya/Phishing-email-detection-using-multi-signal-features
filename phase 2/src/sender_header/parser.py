"""Conservative RFC-style header parsing. Authentication claims are not verified here."""
from __future__ import annotations
from email import policy
from email.parser import Parser
from email.utils import parseaddr
import re
from typing import Any

AUTH_STATES = {"PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "TEMPERROR", "PERMERROR", "UNKNOWN", "UNAVAILABLE"}

def _address(value: str | None) -> tuple[str | None, str | None, str | None]:
    if not value: return None, None, None
    name, addr = parseaddr(value)
    addr = addr.strip().lower() if addr else ""
    if "@" not in addr or addr.count("@") != 1: return name or None, None, None
    local, domain = addr.rsplit("@", 1)
    if not local or not domain or any(c.isspace() for c in addr): return name or None, None, None
    return name or None, addr, domain.rstrip(".").encode("idna").decode("ascii").lower()

def _auth_results(headers: list[str]) -> dict[str, str]:
    # Only parse claims; the caller must establish whether an Authentication-Results
    # header was inserted by a trusted receiving MTA.
    result = {k: "UNAVAILABLE" for k in ("spf", "dkim", "dmarc")}
    for h in headers:
        if not h: continue
        for key in result:
            matches = re.findall(rf"(?i)(?<![\w-]){key}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|unknown)", h)
            if matches:
                val = matches[-1].upper()
                result[key] = "TEMPERROR" if val == "TEMPERROR" else val
    return result

def parse_email(raw_email: str) -> dict[str, Any]:
    msg = Parser(policy=policy.default).parsestr(raw_email or "")
    getall = lambda name: [str(x) for x in msg.get_all(name, [])]
    from_values, reply_values, rp_values = getall("From"), getall("Reply-To"), getall("Return-Path")
    from_name, from_addr, from_domain = _address(from_values[0]) if from_values else (None, None, None)
    _, reply_addr, reply_domain = _address(reply_values[0]) if reply_values else (None, None, None)
    _, rp_addr, rp_domain = _address(rp_values[0]) if rp_values else (None, None, None)
    dkim_sigs = getall("DKIM-Signature")
    dkim_tags: list[dict[str, str]] = []
    for sig in dkim_sigs:
        tags = {k.lower(): v.strip() for k, v in re.findall(r"(?:^|;)\s*([a-zA-Z])\s*=\s*([^;]+)", sig)}
        dkim_tags.append({k: tags[k] for k in ("d", "s") if k in tags})
    anomalies = []
    if len(from_values) != 1: anomalies.append("missing_from" if not from_values else "duplicate_from")
    if from_values and not from_addr: anomalies.append("malformed_from")
    for name in ("Date", "Message-ID"):
        if len(getall(name)) == 0: anomalies.append("missing_" + name.lower().replace("-", "_"))
        elif len(getall(name)) > 1: anomalies.append("duplicate_" + name.lower().replace("-", "_"))
    if len(reply_values) > 1: anomalies.append("duplicate_reply_to")
    if len(rp_values) > 1: anomalies.append("duplicate_return_path")
    if getall("Message-ID") and not re.match(r"^\s*<[^<>\s@]+@[^<>\s@]+>\s*$", getall("Message-ID")[0]): anomalies.append("malformed_message_id")
    auth = _auth_results(getall("Authentication-Results"))
    # Multiple conflicting claims are surfaced rather than silently resolved.
    for key in auth:
        claims = set(re.findall(rf"(?i)(?<![\w-]){key}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|unknown)", " ".join(getall("Authentication-Results"))))
        if len(claims) > 1: anomalies.append("conflicting_" + key + "_claims")
    return {"from_display_name": from_name, "from_address": from_addr, "from_domain": from_domain,
            "reply_to_address": reply_addr, "reply_to_domain": reply_domain,
            "return_path_address": rp_addr, "return_path_domain": rp_domain,
            "from_values": from_values, "reply_to_values": reply_values, "return_path_values": rp_values,
            "headers": {k.lower(): getall(k) for k in msg.keys()}, "header_anomalies": sorted(set(anomalies)),
            "auth": auth, "dkim_signatures": dkim_tags,
            "authentication_evidence_trust": "unverified_header_claims" if getall("Authentication-Results") else "unavailable"}
