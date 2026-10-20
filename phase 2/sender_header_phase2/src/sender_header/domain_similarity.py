"""Configurable registered-domain similarity heuristics; not a public-suffix-list implementation."""
from __future__ import annotations
import unicodedata

def registered_domain(domain: str | None) -> str | None:
    if not domain: return None
    d = domain.strip().rstrip(".").lower()
    try: d = d.encode("idna").decode("ascii")
    except UnicodeError: return d
    labels = d.split(".")
    if len(labels) < 2: return d
    # Conservative fallback only. Configure known multi-label suffixes in production.
    common_second_level = {"co.uk", "org.uk", "com.au", "net.au", "co.in", "com.br", "co.jp"}
    suffix2 = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix2 in common_second_level and len(labels) >= 3 else suffix2

def _distance(a: str, b: str) -> int:
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1): cur.append(min(cur[-1]+1, prev[j]+1, prev[j-1]+(ca != cb)))
        prev = cur
    return prev[-1]

def similarity(a: str | None, b: str | None) -> float:
    a, b = registered_domain(a), registered_domain(b)
    if not a or not b: return 0.0
    if a == b: return 1.0
    return max(0.0, 1.0 - _distance(a, b) / max(len(a), len(b), 1))

def findings(domain: str | None, protected_domains: list[str] | None = None) -> list[dict[str, object]]:
    if not domain: return []
    output = []
    try: ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError: ascii_domain = domain.lower()
    if ascii_domain != domain.lower(): output.append({"type": "idna_or_punycode", "domain": ascii_domain, "explanation": "Domain is represented differently under IDNA normalization."})
    if any(ord(c) > 127 for c in domain): output.append({"type": "unicode_domain", "domain": domain, "explanation": "Unicode characters occur in the supplied domain; this alone does not prove impersonation."})
    for trusted in protected_domains or []:
        score = similarity(domain, trusted)
        if registered_domain(domain) != registered_domain(trusted) and score >= 0.72:
            output.append({"type": "lookalike_candidate", "reference_domain": trusted, "similarity": round(score, 4), "explanation": "High string similarity to a configured reference domain; human review is required."})
    return output
