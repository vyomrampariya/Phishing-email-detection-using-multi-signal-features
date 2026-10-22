"""Offline lexical domain-reputation heuristic (no network access).

This is NOT a threat-intelligence feed. It scores only observable properties
of the domain string, and returns None (unknown) for a plain, unremarkable
domain unless the caller supplied a trusted list or provider.
"""
from __future__ import annotations
import re

RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "support", "zip", "mov",
              "country", "loan", "icu", "rest", "cyou", "monster", "buzz", "bid", "download", "stream",
              "review", "men", "date", "party", "science", "trade", "cam", "live", "site", "online"}
FREE_PROVIDERS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
                  "proton.me", "protonmail.com", "aol.com", "live.com"}
SECURITY_WORDS = ("secure", "verify", "login", "signin", "account", "update", "support", "billing", "helpdesk",
                  "alert", "confirm", "wallet", "recover", "unlock")


def lexical_reputation(domain: str | None) -> dict:
    """Return {score, findings}. score is None when nothing observable can be said."""
    if not domain:
        return {"score": None, "findings": []}
    d = domain.lower().rstrip(".")
    if d in FREE_PROVIDERS:
        return {"score": 0.15, "findings": ["well-known free mailbox provider (not an organisational domain)"]}
    labels = d.split(".")
    tld = labels[-1]
    base = ".".join(labels[:-1])
    findings, score = [], 0.0
    if tld in RISKY_TLDS:
        findings.append(f"top-level domain .{tld} is frequently abused"); score += 0.45
    if any(w in base for w in SECURITY_WORDS):
        findings.append("security/account words embedded in the domain name"); score += 0.25
    if base.count("-") >= 2:
        findings.append("multiple hyphens in the domain name"); score += 0.15
    if re.search(r"[a-z][0-9]|[0-9][a-z]", labels[-2] if len(labels) > 1 else ""):
        findings.append("digits mixed with letters (possible character substitution)"); score += 0.2
    if len(labels) >= 5:
        findings.append("deep subdomain nesting"); score += 0.1
    if not findings:
        return {"score": None, "findings": []}
    return {"score": min(1.0, score), "findings": findings}
