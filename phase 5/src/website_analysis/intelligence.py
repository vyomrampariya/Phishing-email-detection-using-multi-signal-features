"""External-signal helpers for website intelligence (Section 6).

* ``rdap_registration``  - domain registration date / age via RDAP (network, opt-in only).
* ``visual_brand_signals`` - static look-alike logo / page-identity check from fetched HTML.
* ``collect_optional_context`` - hooks for a screenshot renderer and a search-result
  context provider. Neither is bundled: they are used only when the caller supplies one.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")


def rdap_registration(domain: str, timeout: float = 4.0, opener=None):
    """Return registration evidence for a registered domain, or None.

    Contacts https://rdap.org (public bootstrap service). Call only when the user has
    opted in to external lookups. ``opener(url, timeout)`` may be injected for tests
    and must return the decoded JSON document as text.
    """
    domain = (domain or "").lower().rstrip(".")
    if not _DOMAIN_RE.match(domain):
        return None
    url = f"https://rdap.org/domain/{domain}"
    try:
        if opener is not None:
            text = opener(url, timeout)
        else:
            from urllib.request import Request, urlopen
            req = Request(url, headers={"Accept": "application/rdap+json", "User-Agent": "vyom-phishing-assessment"})
            with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https host
                text = resp.read(512_000).decode("utf-8", "replace")
        data = json.loads(text)
    except Exception:
        return None
    created = None
    for event in data.get("events", []) if isinstance(data, dict) else []:
        if str(event.get("eventAction", "")).lower() == "registration" and event.get("eventDate"):
            created = event["eventDate"]
            break
    if not created:
        return None
    try:
        when = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    age = (now - when).days
    if age < 0:
        return None
    return {
        "registration_age_days": age,
        "registration": {"source": "rdap.org", "observed_at": now.isoformat(), "created": created},
    }


def visual_brand_signals(html: str, final_url: str, brands, min_score: float = 0.0):
    """Static look-alike branding check: does the page present a known brand's
    logo/identity (image alt/src, favicon, og:site_name, headings) while being
    served from a domain that does not belong to that brand? No pixels are analysed."""
    host = (urlsplit(final_url).hostname or "").lower()
    findings, score = [], 0.0
    if not html:
        return {"score": None, "findings": []}
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html[:1_000_000], "html.parser")
    except Exception:
        return {"score": None, "findings": []}
    image_text, identity_text = [], []
    for img in soup.find_all("img"):
        image_text.append(" ".join(str(img.get(a, "")) for a in ("alt", "src", "title", "class")).lower())
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        if "icon" in rel:
            image_text.append(str(link.get("href", "")).lower())
    for meta in soup.find_all("meta"):
        key = str(meta.get("property") or meta.get("name") or "").lower()
        if key in {"og:site_name", "application-name", "og:title"}:
            identity_text.append(str(meta.get("content", "")).lower())
        if key == "og:image":
            image_text.append(str(meta.get("content", "")).lower())
    for h in soup.find_all(["h1", "h2"]):
        identity_text.append(h.get_text(" ", strip=True).lower()[:200])
    for brand in brands:
        name = brand["name"].lower().replace(" ", "")
        owned = any(host == d or host.endswith("." + d) for d in brand.get("domains", []))
        if owned:
            continue
        in_images = any(name in t.replace(" ", "") for t in image_text)
        in_identity = any(name in t.replace(" ", "") for t in identity_text)
        if in_images:
            findings.append({"brand": brand["name"], "evidence": "brand logo/image reference on an unrelated domain", "domain": host, "similarity": 0.85})
            score = max(score, 0.85)
        elif in_identity:
            findings.append({"brand": brand["name"], "evidence": "brand named in page identity (site name/heading) on an unrelated domain", "domain": host, "similarity": 0.6})
            score = max(score, 0.6)
    return {"score": score if score >= min_score else 0.0, "findings": findings}


def collect_optional_context(target: str, domain: str, screenshot_provider=None, search_provider=None):
    """Optional screenshot and search-context evidence supplied by the deployer.

    screenshot_provider(url) -> {"brand_match": 0..1, "login_form_visible": bool, ...} | None
    search_provider(domain)  -> {"indexed": bool, "negative_mentions": 0..1, ...} | None
    Returns the evidence plus the status of each, so the UI can say exactly what ran.
    """
    out = {"screenshot": {"status": "not_collected"}, "search_context": {"status": "not_collected"}}
    risks = []
    if screenshot_provider:
        try:
            shot = screenshot_provider(target)
            if shot:
                out["screenshot"] = {"status": "observed", **shot}
                risks.append(float(shot.get("brand_match", 0.0)))
        except Exception as exc:
            out["screenshot"] = {"status": "error", "reason": type(exc).__name__}
    if search_provider:
        try:
            ctx = search_provider(domain)
            if ctx:
                out["search_context"] = {"status": "observed", **ctx}
                risk = float(ctx.get("negative_mentions", 0.0))
                if ctx.get("indexed") is False:
                    risk = max(risk, 0.4)
                risks.append(risk)
        except Exception as exc:
            out["search_context"] = {"status": "error", "reason": type(exc).__name__}
    out["risk"] = max(risks) if risks else None
    return out
