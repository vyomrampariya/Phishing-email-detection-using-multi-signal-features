"""Evidence reliability & intent consistency (Section 7, first bullet).

Asks: do the sender, the message wording, the links and the landing page all describe
the *same* intent / organisation?  Example from the spec: the sender header says "bank"
but the website is about cars -> inconsistent evidence -> higher risk.
"""
from __future__ import annotations

import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit

try:
    import publicsuffix2
except Exception:  # pragma: no cover
    publicsuffix2 = None

CATEGORIES = {
    "banking": ["bank", "netbanking", "wire transfer", "iban", "swift", "ifsc", "debit card", "credit card", "loan", "atm", "statement"],
    "payments": ["paypal", "payment", "invoice", "billing", "refund", "venmo", "stripe", "receipt"],
    "tech_account": ["password", "login", "log in", "sign in", "signin", "microsoft", "office 365", "outlook", "google", "apple id", "icloud", "mailbox", "storage quota", "two-factor", "2fa", "verify your account", "account", "security", "security alert"],
    "shipping": ["parcel", "package", "delivery", "shipment", "tracking", "courier", "dhl", "fedex", "ups", "usps"],
    "ecommerce": ["order", "purchase", "amazon", "flipkart", "ebay", "shopping cart", "shop"],
    "automotive": ["car", "cars", "vehicle", "automobile", "dealership", "motors", "tyre", "tire", "sedan", "suv", "auto"],
    "government": ["irs", "income tax", "tax return", "customs", "passport", "court", "government"],
    "crypto": ["crypto", "bitcoin", "wallet", "ethereum", "binance"],
    "employment": ["job", "hiring", "recruit", "salary", "interview", "vacancy"],
    "healthcare": ["insurance", "medical", "pharmacy", "prescription", "health"],
}
# categories that, when claimed by a mailing, carry credential/payment intent
SENSITIVE = {"banking", "payments", "tech_account", "crypto", "government"}

BRANDS = {
    "paypal": ["paypal.com", "paypal.me"], "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"], "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"], "netflix": ["netflix.com"],
    "dhl": ["dhl.com"], "fedex": ["fedex.com"], "ups": ["ups.com"], "usps": ["usps.com"],
    "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"], "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "wells fargo": ["wellsfargo.com"], "bank of america": ["bankofamerica.com"], "citibank": ["citi.com", "citibank.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"], "linkedin": ["linkedin.com"], "dropbox": ["dropbox.com"],
    "chase": ["chase.com", "jpmorganchase.com"], "github": ["github.com"],
    "docusign": ["docusign.com", "docusign.net"], "adobe": ["adobe.com"], "whatsapp": ["whatsapp.com"], "instagram": ["instagram.com"],
}
FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com", "aol.com", "live.com"}
INTENT_PAIR_WEIGHT, BRAND_WEIGHT, DISPERSION_WEIGHT = 0.35, 0.50, 0.25


def registered_domain(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().strip().rstrip(".")
    try:  # an IP literal has no registrable domain; keep the whole address
        ipaddress.ip_address(host.strip("[]"))
        return host.strip("[]")
    except ValueError:
        pass
    if publicsuffix2 is not None:
        try:
            return publicsuffix2.get_sld(host) or host
        except Exception:
            pass
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def host_of(url: str) -> str | None:
    try:
        return (urlsplit(url if "://" in url else "https://" + url).hostname or "").lower() or None
    except ValueError:
        return None


def intent_categories(text: str, *, domain_mode: bool = False) -> set[str]:
    text = (text or "").lower()
    found = set()
    for cat, words in CATEGORIES.items():
        for w in words:
            if domain_mode:
                if len(w) >= 4 and w in text:
                    found.add(cat); break
            elif re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", text):
                found.add(cat); break
    return found


def brands_in(text: str) -> set[str]:
    text = (text or "").lower()
    return {b for b in BRANDS if re.search(r"(?<![a-z0-9])" + re.escape(b) + r"(?![a-z0-9])", text)}


def _owned(brand: str, domain: str | None) -> bool:
    return bool(domain) and any(domain == d or domain.endswith("." + d) for d in BRANDS[brand])


def analyze_consistency(ctx: dict) -> dict:
    """ctx keys: from_display, from_address, reply_to, subject, body, urls (list[str]),
    websites (list[{url,title,text}]) -- all optional."""
    from_addr = (ctx.get("from_address") or "").lower()
    from_dom = registered_domain(from_addr.split("@")[-1]) if "@" in from_addr else None
    reply_addr = (ctx.get("reply_to") or "").lower()
    reply_dom = registered_domain(reply_addr.split("@")[-1]) if "@" in reply_addr else None
    url_hosts = [h for h in (host_of(u) for u in ctx.get("urls") or []) if h]
    url_doms = sorted({registered_domain(h) for h in url_hosts})
    sites = ctx.get("websites") or []

    sender_text = f"{ctx.get('from_display') or ''}"
    content_text = f"{ctx.get('subject') or ''} {ctx.get('body') or ''}"
    web_text = " ".join(f"{s.get('title') or ''} {s.get('text') or ''}" for s in sites)

    sources = {}
    s_cats = intent_categories(sender_text) | (intent_categories(from_addr.split("@")[-1], domain_mode=True) if from_dom not in FREE_MAIL else set())
    if sender_text.strip() or from_addr:
        sources["sender"] = s_cats
    if content_text.strip():
        sources["content"] = intent_categories(content_text)
    if url_hosts:
        sources["links"] = intent_categories(" ".join(url_hosts) + " " + " ".join(urlsplit(u if "://" in u else "https://" + u).path for u in ctx.get("urls") or []), domain_mode=True)
    if sites:
        sources["website"] = intent_categories(web_text)

    evidenced = {k: v for k, v in sources.items() if v}
    findings = []

    # 1. Pairwise intent comparison between sources that expressed an intent.
    names = list(evidenced)
    compared = disjoint = 0
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            compared += 1
            if evidenced[a].isdisjoint(evidenced[b]):
                disjoint += 1
                findings.append({"type": "intent_mismatch", "sources": [a, b], "weight": INTENT_PAIR_WEIGHT,
                                 "finding": f"{a} suggests {sorted(evidenced[a])} but {b} suggests {sorted(evidenced[b])}"})

    # 2. A brand is claimed (display name / wording / page) but no sender or link domain belongs to it.
    claimed = brands_in(sender_text) | brands_in(web_text)
    claimed |= {b for b in brands_in(content_text) if b in brands_in(sender_text) or b in brands_in(web_text) or url_doms}
    link_set = set(url_doms)
    for brand in sorted(claimed):
        sender_ok = _owned(brand, from_dom)
        links_ok = any(_owned(brand, d) for d in link_set)
        if not sender_ok and not links_ok and (from_dom or link_set):
            findings.append({"type": "brand_domain_mismatch", "brand": brand, "weight": BRAND_WEIGHT,
                             "finding": f"'{brand}' is named but neither the sender domain ({from_dom}) nor any link domain belongs to it"})
        elif not sender_ok and from_dom and from_dom not in FREE_MAIL and links_ok:
            findings.append({"type": "brand_sender_mismatch", "brand": brand, "weight": BRAND_WEIGHT * 0.6,
                             "finding": f"links point to {brand} but the sender domain {from_dom} does not"})

    # 3. Too many unrelated organisations in one message.
    all_doms = {d for d in [from_dom, reply_dom, *url_doms] if d and d not in FREE_MAIL}
    if len(all_doms) >= 3:
        findings.append({"type": "domain_dispersion", "weight": DISPERSION_WEIGHT * min(2, len(all_doms) - 2),
                         "finding": f"{len(all_doms)} unrelated registered domains across sender, reply-to and links", "domains": sorted(all_doms)})

    n_sources = len(sources)
    reliability = round(len([v for v in sources.values() if v]) / 4, 3)
    if len(evidenced) < 2 and not any(f["type"] != "intent_mismatch" for f in findings):
        score, status = None, "insufficient_evidence"
    else:
        score, status = min(1.0, sum(f["weight"] for f in findings)), "available"
    return {
        "status": status, "score": None if score is None else round(score, 4),
        "intents_by_source": {k: sorted(v) for k, v in sources.items()},
        "sources_present": n_sources, "sources_with_intent": len(evidenced),
        "evidence_reliability": reliability, "pairs_compared": compared, "pairs_inconsistent": disjoint,
        "findings": findings,
        "consistent_intent": bool(evidenced) and not findings,
    }


_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})
IMPERSONATION_SIMILARITY = 0.84
# An exact brand token next to one of these is a classic phishing domain pattern
# (paypal-secure, chase-bank-security); next to an ordinary word it is not.
LURE_TOKENS = {"secure", "security", "login", "signin", "support", "verify", "verification", "account", "accounts", "bank",
               "banking", "update", "billing", "service", "services", "auth", "alert", "alerts", "help", "pay", "payment",
               "payments", "online", "customer", "care", "portal", "recovery", "confirm", "unlock", "wallet", "id"}


def _brand_owns(brand: str, domain: str) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in BRANDS[brand])


def impersonated_brand(host: str | None) -> dict | None:
    """Return the brand a non-owner host appears to imitate, else None.

    Catches (a) a brand name embedded in a hyphen/dot separated label such as
    ``paypal-secure.net`` or ``chase-bank-security.com``, and (b) a near-miss or
    homoglyph spelling such as ``microsft`` / ``paypa1``. Owned domains
    (``paypal.com``, ``mail.paypal.com``) never match, and a token must be a
    whole label part, so ``apple-orchard-farm.com`` still needs an exact token.
    """
    host = (host or "").lower().strip().rstrip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return None
    except ValueError:
        pass
    domain = registered_domain(host) or host
    label = domain.split(".")[0]
    tokens = [t for t in re.split(r"[-_.]", label) if t]
    for brand in BRANDS:
        if " " in brand:
            if brand.replace(" ", "") in label.replace("-", "") and not _brand_owns(brand, domain) and label != brand.replace(" ", ""):
                return {"brand": brand, "domain": domain, "kind": "embedded"}
            continue
        if _brand_owns(brand, domain):
            continue
        for tok in tokens:
            mapped = tok.translate(_HOMOGLYPHS)
            if mapped == brand or tok == brand:
                if tok != brand:
                    return {"brand": brand, "domain": domain, "kind": "homoglyph"}
                if any(o in LURE_TOKENS for o in tokens if o != tok):
                    return {"brand": brand, "domain": domain, "kind": "embedded"}
            elif len(brand) >= 6 and len(tok) >= 6 and abs(len(tok) - len(brand)) <= 1:
                ratio = SequenceMatcher(None, brand, mapped).ratio()
                if ratio >= IMPERSONATION_SIMILARITY:
                    return {"brand": brand, "domain": domain, "kind": "lookalike", "similarity": round(ratio, 3)}
    return None
