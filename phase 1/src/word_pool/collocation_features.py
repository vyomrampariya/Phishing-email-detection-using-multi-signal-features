"""Learned phrase patterns plus configurable seed phrases."""
from .ngram_features import NgramFeatures

DEFAULT_PHRASES = ("verify your account", "unusual sign in activity", "urgent action required",
                   "confirm your identity", "update your payment information")
BENIGN_CONTEXT = ("routine", "scheduled", "onboarding", "for your records", "per our policy", "as requested")


class CollocationFeatures:
    def __init__(self, min_documents=2, max_patterns=500, patterns=DEFAULT_PHRASES):
        self.patterns = tuple(patterns); self.learned = NgramFeatures((2, 5), min_documents, max_patterns)

    def fit(self, texts, labels):
        self.learned.fit(texts, labels); return self

    def score(self, text):
        normalized = " " + " ".join(text.lower().split()) + " "
        context_present = any(term in normalized for term in BENIGN_CONTEXT)
        hits = {p: (0.35 if context_present else 0.75) for p in self.patterns if " " + p + " " in normalized}
        learned_score, learned = self.learned.score(text)
        for item in learned:
            if len(item["phrase"].split()) > 1:
                hits.setdefault(item["phrase"], item["contribution"])
        return min(1.0, sum(hits.values()) / max(1, len(hits))), [{"phrase": k, "contribution": v} for k,v in sorted(hits.items())]
