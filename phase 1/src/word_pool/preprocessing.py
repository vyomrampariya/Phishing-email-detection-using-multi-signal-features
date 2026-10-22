"""Conservative, reusable email text normalization."""
from __future__ import annotations

import html
import re
import unicodedata
from typing import Any

try:
    from bs4 import BeautifulSoup
except ImportError:  # optional fallback keeps HTML entities and tags manageable
    BeautifulSoup = None

_TAG = re.compile(r"<[^>]+>")
_HTML_TAG = re.compile(r"</?[a-zA-Z][^>]*>|<!--")
_TOKEN = re.compile(r"[a-z0-9]+(?:['’][a-z0-9]+)*", re.I)
_NEGATIONS = {"not", "no", "never", "without", "cannot", "can't", "won't", "don't", "doesn't"}
MAX_FEATURE_CHARS = 30000


def readable_text(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            if value != value:  # NaN
                return ""
        except Exception:
            pass
        value = str(value)
    value = unicodedata.normalize("NFKC", value)
    if BeautifulSoup is not None and _HTML_TAG.search(value):
        value = BeautifulSoup(value, "html.parser").get_text(" ")
    else:
        value = _TAG.sub(" ", value)
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def normalize_text(value: Any, *, remove_stop_words: bool = False, lemmatize: bool = False) -> str:
    tokens = [t.casefold().replace("’", "'") for t in _TOKEN.findall(readable_text(value))]
    if remove_stop_words:
        # Keep negation and action words: they carry useful intent/context.
        stops = {"a", "an", "the", "of", "to", "in", "on", "for", "at", "by", "with", "is", "are", "was", "were", "be", "been", "being", "and", "or", "but"}
        tokens = [t for t in tokens if t not in stops or t in _NEGATIONS]
    if lemmatize:
        # Lightweight deterministic fallback; no external corpus download required.
        tokens = [_simple_lemma(t) for t in tokens]
    return " ".join(tokens)


def _simple_lemma(token: str) -> str:
    if len(token) > 5 and token.endswith("ies"):
        return token[:-3] + "y"
    if len(token) > 5 and token.endswith("ing"):
        return token[:-3]
    if len(token) > 4 and token.endswith("ed"):
        return token[:-2]
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def prepare_email(subject: Any = "", body: Any = "") -> dict[str, str]:
    subject_original, body_original = readable_text(subject), readable_text(body)
    original = " ".join(part for part in (subject_original, body_original) if part).strip()
    feature_text = normalize_text(original)
    truncated = len(feature_text) > MAX_FEATURE_CHARS
    if truncated:
        feature_text = feature_text[:MAX_FEATURE_CHARS].rsplit(" ", 1)[0]
    return {
        "subject": subject_original,
        "body": body_original,
        "original_text": original,
        "text": feature_text,
        "text_truncated": truncated,
    }


def lexical_pipeline(value: Any) -> dict:
    """Full Section 2 pipeline, exposed step by step:
    lowercase -> symbol/punctuation removal -> tokenization -> stop-word handling -> lemmatization.
    """
    clean = readable_text(value)
    lowered = clean.casefold()
    tokens = [t.replace("\u2019", "'") for t in _TOKEN.findall(lowered)]  # tokenizer drops symbols/punctuation
    no_stop = normalize_text(clean, remove_stop_words=True).split()
    lemmas = [_simple_lemma(t) for t in no_stop]
    return {
        "tokens": tokens,
        "tokens_without_stop_words": no_stop,
        "lemmas": lemmas,
        "report": {
            "steps": ["lowercase", "symbol/punctuation removal", "tokenization", "stop-word handling (negations kept)", "lemmatization"],
            "token_count": len(tokens),
            "after_stop_word_removal": len(no_stop),
            "stop_words_removed": len(tokens) - len(no_stop),
            "lemmatized_sample": lemmas[:15],
        },
    }
