"""Contextual call-to-action phrase detection."""
from .collocation_features import CollocationFeatures

CTA_PHRASES = ("click here", "verify your account", "reset your password", "update your payment",
               "provide your password", "confirm your identity", "open the attachment",
               "claim your reward", "account will be suspended", "payment overdue", "send your credentials")
COERCIVE = ("immediately", "urgent", "suspended", "expire", "overdue", "within 24 hours", "final warning", "act now")
BENIGN_CONTEXT = ("routine", "scheduled", "onboarding", "for your records", "per our policy", "as requested")


class CTAFeatures:
    def __init__(self): self.learned = CollocationFeatures(min_documents=2, max_patterns=500)

    def fit(self, texts, labels, *, learned=None):
        if learned is not None: self.learned = learned
        else: self.learned.fit(texts, labels)
        return self

    def score(self, text):
        normalized = " " + " ".join(text.lower().split()) + " "
        hits = {}
        benign_context = any(term in normalized for term in BENIGN_CONTEXT)
        for phrase in CTA_PHRASES:
            if " " + phrase + " " in normalized:
                coercion = any(word in normalized for word in COERCIVE)
                # Single mention only, bounded; lower weight without coercive context.
                hits[phrase] = 0.15 if benign_context else (0.8 if coercion else 0.45)
        _, learned = self.learned.score(text)
        for item in learned:
            if item["phrase"] not in hits and any(w in item["phrase"] for w in ("click", "verify", "payment", "password", "credential", "claim", "open")):
                hits[item["phrase"]] = item["contribution"] * 0.5
        score = sum(hits.values()) / max(1, len(hits))
        return min(0.15 if benign_context else 1.0, score), [{"phrase": k, "contribution": v} for k,v in sorted(hits.items())]
