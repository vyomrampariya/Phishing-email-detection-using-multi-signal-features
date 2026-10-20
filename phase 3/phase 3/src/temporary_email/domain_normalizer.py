"""Strict domain and email normalization helpers (stdlib only)."""
from __future__ import annotations
import re
import unicodedata
from email.utils import parseaddr

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

class InvalidDomainError(ValueError):
    pass


def normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidDomainError("Domain must be a string")
    raw = value.strip()
    # IDNA recognizes these Unicode full-stop variants as label separators.
    raw = raw.translate(str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."}))
    if not raw or any(c in raw for c in " /\\:@?#") or raw.startswith(".") or raw.endswith("."):
        raise InvalidDomainError("Expected a bare hostname, not a URL, path, address, or malformed domain")
    # The stdlib IDNA codec is permissive for symbols such as emoji; reject
    # non-letter/number/mark characters before IDNA conversion.
    for label in raw.split("."):
        if not label or any(ch != "-" and unicodedata.category(ch)[0] not in {"L", "N", "M"} for ch in label):
            raise InvalidDomainError("Invalid character in hostname label")
    try:
        ascii_domain = raw.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise InvalidDomainError("Domain cannot be normalized with IDNA") from exc
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        raise InvalidDomainError("Hostname must contain at least two labels and be <=253 characters")
    labels = ascii_domain.split(".")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise InvalidDomainError("Invalid hostname label")
    if labels[-1].isdigit():
        raise InvalidDomainError("Top-level label cannot be all numeric")
    return ascii_domain


def extract_domain(value: str) -> str:
    """Accept a bare domain or one conventional email address; reject display names/URLs."""
    if not isinstance(value, str):
        raise InvalidDomainError("Input must be a string")
    raw = value.strip()
    if not raw:
        raise InvalidDomainError("Input is empty")
    if "@" not in raw:
        return normalize_domain(raw)
    # A full address must contain exactly one @ and no display-name syntax.
    if raw.count("@") != 1 or any(c in raw for c in " <>(),;:[]\\/\t\r\n"):
        raise InvalidDomainError("Malformed email address")
    local, domain = raw.rsplit("@", 1)
    if not local or len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
        raise InvalidDomainError("Malformed email local part")
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
        raise InvalidDomainError("Unsupported or malformed email local part")
    return normalize_domain(domain)
