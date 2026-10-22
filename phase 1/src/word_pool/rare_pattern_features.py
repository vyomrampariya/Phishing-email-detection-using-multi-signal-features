"""Rare-wording evidence learned against benign and malicious training texts."""
from collections import Counter
from math import log

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer

from .preprocessing import normalize_text


class RarePatternFeatures:
    def __init__(self, max_patterns=500, min_phishing_documents=1):
        self.max_patterns, self.min_phishing_documents = max_patterns, min_phishing_documents
        self.patterns = {}; self.benign_document_count = 0

    def fit(self, texts, labels, *, vectorizer=None):
        labels = np.asarray(labels, dtype=int)
        if vectorizer is None:
            vectorizer = CountVectorizer(ngram_range=(1,3), min_df=1, max_features=50_000, binary=True,
                                         dtype=np.int8, token_pattern=r"(?u)\b\w[\w']*\b")
            matrix = vectorizer.fit_transform(texts)
        else:
            matrix = vectorizer.transform(texts)
        benign_mask, malicious_mask = labels == 0, labels == 1
        benign_docs, malicious_docs = int(benign_mask.sum()), int(malicious_mask.sum())
        benign_freq = np.asarray(matrix[benign_mask].sum(axis=0)).ravel()
        malicious_freq = np.asarray(matrix[malicious_mask].sum(axis=0)).ravel()
        self.benign_document_count = benign_docs
        evidence = []
        for phrase, benign_count, mal_count in zip(vectorizer.get_feature_names_out(), benign_freq, malicious_freq):
            if mal_count < self.min_phishing_documents: continue
            # Rarity is inverse frequency in benign training docs; evidence requires label association.
            rarity = log((benign_docs + 1) / (benign_count + 1)) / max(1.0, log(benign_docs + 1))
            mal_rate = (mal_count + 1) / (malicious_docs + 2)
            benign_rate = (benign_count + 1) / (benign_docs + 2)
            association = max(0.0, (mal_rate - benign_rate) / max(mal_rate, benign_rate))
            value = rarity * association
            if value > 0.02: evidence.append((phrase, min(1.0, value)))
        self.patterns = dict(sorted(evidence, key=lambda x: x[1], reverse=True)[:self.max_patterns])
        return self

    def score(self, text):
        terms = normalize_text(text).split(); found = {}
        candidates = set()
        for n in (1, 2, 3):
            candidates.update(" ".join(terms[i:i+n]) for i in range(max(0, len(terms)-n+1)))
        for phrase in candidates:
            if phrase in self.patterns: found[phrase] = self.patterns[phrase]
        return (sum(found.values()) / len(found) if found else 0.0), [{"phrase": k, "contribution": v} for k,v in sorted(found.items())]
