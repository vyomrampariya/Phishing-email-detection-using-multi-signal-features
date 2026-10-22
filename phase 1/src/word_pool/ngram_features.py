"""Training-derived n-gram evidence."""
from collections import Counter
from math import log

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer

from .preprocessing import normalize_text


class NgramFeatures:
    def __init__(self, ngram_range=(1, 3), min_documents=2, max_patterns=500):
        self.ngram_range, self.min_documents, self.max_patterns = ngram_range, min_documents, max_patterns
        self.evidence = {}

    def fit(self, texts, labels):
        labels = np.asarray(labels, dtype=int)
        self.vectorizer = CountVectorizer(ngram_range=self.ngram_range, min_df=1,
                                          max_features=100_000, binary=True, dtype=np.int8,
                                          token_pattern=r"(?u)\b\w[\w']*\b")
        try:
            matrix = self.vectorizer.fit_transform(texts)
        except ValueError as exc:
            if "empty vocabulary" not in str(exc).casefold():
                raise
            self.vectorizer = None
            self.evidence = {}
            return self
        y1, y0 = labels == 1, labels == 0
        df1 = np.asarray(matrix[y1].sum(axis=0)).ravel(); df0 = np.asarray(matrix[y0].sum(axis=0)).ravel()
        total0, total1 = int(y0.sum()), int(y1.sum())
        counts = Counter()
        for term, benign, malicious in zip(self.vectorizer.get_feature_names_out(), df0, df1):
            if benign + malicious < self.min_documents:
                continue
            p1 = (malicious + 1) / (total1 + 2); p0 = (benign + 1) / (total0 + 2)
            odds = max(0.0, log(p1 / p0))
            if odds: counts[term] = odds * (malicious + benign)
        self.evidence = {t: min(1.0, v / max(counts.values())) for t, v in counts.most_common(self.max_patterns)} if counts else {}
        return self

    def score(self, text):
        terms = normalize_text(text).split(); hits = {}
        for n in range(self.ngram_range[0], self.ngram_range[1] + 1):
            for i in range(max(0, len(terms)-n+1)):
                phrase = " ".join(terms[i:i+n])
                if phrase in self.evidence: hits[phrase] = self.evidence[phrase]
        return (sum(hits.values()) / len(hits) if hits else 0.0), [{"phrase": k, "contribution": v} for k,v in sorted(hits.items())]
