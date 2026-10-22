"""Email-thread and cross-email analysis (Section 7, second bullet)."""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from email import policy
from email.parser import Parser
from email.utils import getaddresses, parsedate_to_datetime

from intent import SENSITIVE, intent_categories, registered_domain, host_of, FREE_MAIL

_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_PREFIX = re.compile(r"^\s*((re|fw|fwd|aw|sv)\s*:\s*)+", re.I)
_IDS = re.compile(r"<[^<>\s]+>")


def _text(msg) -> str:
    parts = []
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        if part.get_content_maintype() == "text" and not part.get_filename():
            try:
                parts.append(str(part.get_content()))
            except Exception:
                payload = part.get_payload(decode=True) or b""
                parts.append(payload.decode("utf-8", "replace"))
    return "\n".join(parts)


def parse_message(raw: str) -> dict:
    msg = Parser(policy=policy.default).parsestr(raw)
    name_addr = getaddresses([str(msg.get("From", ""))])
    display, addr = (name_addr[0] if name_addr else ("", ""))
    addr = addr.lower()
    reply = getaddresses([str(msg.get("Reply-To", ""))])
    reply_addr = reply[0][1].lower() if reply else ""
    body = _text(msg)
    subject = str(msg.get("Subject", ""))
    urls = _URL.findall(body)
    date = None
    try:
        date = parsedate_to_datetime(str(msg.get("Date"))) if msg.get("Date") else None
    except (TypeError, ValueError):
        pass
    return {
        "message_id": (_IDS.findall(str(msg.get("Message-ID", ""))) or [None])[0],
        "in_reply_to": _IDS.findall(str(msg.get("In-Reply-To", ""))),
        "references": _IDS.findall(str(msg.get("References", ""))),
        "subject": subject, "subject_norm": _PREFIX.sub("", subject).strip().lower(),
        "is_reply_subject": bool(_PREFIX.match(subject)),
        "display": (display or "").strip().lower(), "from": addr,
        "from_domain": registered_domain(addr.split("@")[-1]) if "@" in addr else None,
        "reply_domain": registered_domain(reply_addr.split("@")[-1]) if "@" in reply_addr else None,
        "url_domains": sorted({registered_domain(host_of(u)) for u in urls if host_of(u)}),
        "intents": sorted(intent_categories(subject + " " + body)), "date": date,
    }


def _lookalike(a: str, b: str) -> bool:
    if not a or not b or a == b:
        return False
    la, lb = a.split(".")[0], b.split(".")[0]
    short, long_ = sorted((la, lb), key=len)
    if len(short) >= 4 and short in long_.replace('-', ''):  # e.g. acme vs acme-corp
        return True
    return SequenceMatcher(None, la, lb).ratio() >= 0.8


def analyze_thread(primary_raw: str, related_raws: list[str] | None = None) -> dict:
    primary = parse_message(primary_raw)
    related = [parse_message(r) for r in (related_raws or []) if r and r.strip()]
    findings = []

    if primary["is_reply_subject"] and not primary["in_reply_to"] and not primary["references"]:
        findings.append({"type": "fake_reply_subject", "weight": 0.35,
                         "finding": "Subject claims to be a reply/forward (Re:/Fwd:) but there is no In-Reply-To or References header"})

    linked = []
    for r in related:
        ids = set(primary["in_reply_to"]) | set(primary["references"])
        rid = {r["message_id"]} - {None}
        theirs = set(r["in_reply_to"]) | set(r["references"])
        same_subject = bool(primary["subject_norm"]) and primary["subject_norm"] == r["subject_norm"]
        if (rid & ids) or (primary["message_id"] and primary["message_id"] in theirs) or same_subject:
            linked.append(r)

    if related and not linked:
        findings.append({"type": "unlinked_related_emails", "weight": 0.1,
                         "finding": "Supplied related emails share no thread headers or subject with this message"})

    if linked:
        prior_senders = {r["from_domain"] for r in linked if r["from_domain"]}
        prior_displays = {r["display"]: r["from_domain"] for r in linked if r["display"]}
        prior_urls = {d for r in linked for d in r["url_domains"]} | prior_senders
        prior_replies = {r["reply_domain"] for r in linked if r["reply_domain"]} | prior_senders
        prior_intents = {i for r in linked for i in r["intents"]}
        if primary["from_domain"] and prior_senders and primary["from_domain"] not in prior_senders:
            if any(_lookalike(primary["from_domain"], s) for s in prior_senders):
                findings.append({"type": "lookalike_sender_in_thread", "weight": 0.8,
                                 "finding": f"Sender domain {primary['from_domain']} is a look-alike of earlier thread participant(s) {sorted(prior_senders)}"})
            else:
                findings.append({"type": "sender_domain_change", "weight": 0.5,
                                 "finding": f"Sender domain {primary['from_domain']} was not seen earlier in the thread ({sorted(prior_senders)})"})
        if primary["display"] in prior_displays and prior_displays[primary["display"]] not in (None, primary["from_domain"]):
            findings.append({"type": "display_name_reused", "weight": 0.6,
                             "finding": "Same display name as an earlier message but from a different domain"})
        if primary["reply_domain"] and primary["reply_domain"] not in prior_replies:
            findings.append({"type": "reply_to_change", "weight": 0.45,
                             "finding": f"Reply-To domain {primary['reply_domain']} is new to the thread"})
        new_urls = set(primary["url_domains"]) - prior_urls
        if new_urls and prior_urls:
            findings.append({"type": "url_domain_shift", "weight": 0.4,
                             "finding": f"Links point to domain(s) not seen earlier in the thread: {sorted(new_urls)}"})
        new_sensitive = (set(primary["intents"]) & SENSITIVE) - prior_intents
        if new_sensitive and prior_intents:
            findings.append({"type": "intent_shift", "weight": 0.4,
                             "finding": f"Thread turns to {sorted(new_sensitive)} (credential/payment topics) that earlier messages did not involve"})

    # Cross-email (any related message, linked or not)
    by_display = {}
    for r in related + [primary]:
        if r["display"] and r["from_domain"] and r["from_domain"] not in FREE_MAIL:
            by_display.setdefault(r["display"], set()).add(r["from_domain"])
    for name, doms in by_display.items():
        if len(doms) >= 2:
            findings.append({"type": "display_name_multiple_domains", "weight": 0.5,
                             "finding": f"Display name '{name}' is used from {len(doms)} different domains: {sorted(doms)}"})
            break

    if not related and not findings:
        return {"status": "not_applicable", "score": None, "findings": [], "emails_compared": 0,
                "message": "No related emails supplied and no thread-header anomalies in this message"}
    return {"status": "available", "score": round(min(1.0, sum(f["weight"] for f in findings)), 4),
            "findings": findings, "emails_compared": len(related), "linked_emails": len(linked),
            "thread_headers": {"message_id": primary["message_id"], "in_reply_to": primary["in_reply_to"], "references": primary["references"]}}
