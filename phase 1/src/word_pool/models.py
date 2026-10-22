"""Fit, persist, and invoke the stable Phase 1 Word Pool interface."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import json
import hashlib

import joblib

from .collocation_features import CollocationFeatures
from .cta_features import CTAFeatures
from .ngram_features import NgramFeatures
from .preprocessing import prepare_email, lexical_pipeline
from .rare_pattern_features import RarePatternFeatures
from .scoring import WordPoolWeights, calculate_word_pool_score, weights_from_mapping
from .tfidf_model import TfidfPhishingModel


class WordPoolModel:
    def __init__(self, weights=None, seed=42, ngram_range=(1, 3), min_pattern_documents=2,
                 max_patterns=500, model_version="1.0.0"):
        self.weights = weights if isinstance(weights, WordPoolWeights) else weights_from_mapping(weights or asdict(WordPoolWeights()))
        self.seed, self.ngram_range = seed, ngram_range
        self.min_pattern_documents, self.max_patterns = min_pattern_documents, max_patterns
        self.model_version = model_version; self.fitted = False

    def fit(self, texts, labels):
        texts = list(texts); labels = list(labels)
        if len(texts) != len(labels) or not texts:
            raise ValueError("Training texts and labels must be non-empty and equal length")
        if set(map(int, labels)) != {0, 1}:
            raise ValueError("Training data must contain both classes")
        self.ngrams = NgramFeatures(self.ngram_range, self.min_pattern_documents, self.max_patterns).fit(texts, labels)
        self.collocations = CollocationFeatures(self.min_pattern_documents, self.max_patterns).fit(texts, labels)
        self.rare = RarePatternFeatures(self.max_patterns).fit(texts, labels, vectorizer=self.ngrams.vectorizer)
        self.cta = CTAFeatures().fit(texts, labels, learned=self.collocations.learned)
        self.tfidf = TfidfPhishingModel(self.seed).fit(texts, labels)
        self.fitted = True
        return self

    def analyze(self, subject="", body=""):
        if not self.fitted:
            raise RuntimeError("Word Pool model is not trained; train or load a model before analysis")
        message = prepare_email(subject, body)
        if not message["text"]:
            scores = {k: 0.0 for k in ("N", "C", "T", "R", "A")}
            return {"S_WP": 0.0, "component_scores": scores, "weights": asdict(self.weights),
                    "detected_ngrams": [], "detected_collocations": [], "tfidf_explanation": [],
                    "rare_patterns": [], "cta_matches": [],
                    "warnings": ["Empty email text: analysis is unavailable; score 0.0 is not evidence of safety."],
                    "model_version": self.model_version}
        N, ngrams = self.ngrams.score(message["text"])
        C, collocations = self.collocations.score(message["text"])
        T, explanation = self.tfidf.predict_score(message["text"])
        R, rare = self.rare.score(message["text"])
        A, cta = self.cta.score(message["text"])
        scores = {"N": N, "C": C, "T": T, "R": R, "A": A}
        # Lemma/stop-word-normalised matching: catches inflected or filler-padded variants of
        # learned phishing n-grams ("verified your accounts") that exact matching misses.
        pipeline = lexical_pipeline(message["text"])
        extra_hits = self._lemma_hits(pipeline["lemmas"], {h["phrase"] for h in ngrams})
        if extra_hits:
            ngrams = ngrams + extra_hits
            N = sum(h["contribution"] for h in ngrams) / len(ngrams)
            scores["N"] = N
        detected = {h["phrase"] for h in ngrams} | {h["phrase"] for h in collocations if isinstance(h, dict) and "phrase" in h} \
            | {h["phrase"] for h in cta if isinstance(h, dict) and "phrase" in h} \
            | {h["phrase"] for h in rare if isinstance(h, dict) and "phrase" in h}
        relevant = self._relevant_pattern_count(message["text"]) | detected
        pattern_ratio = len(detected) / len(relevant) if relevant else 0.0
        warnings = ["TF-IDF outputs are uncalibrated model probabilities and are not a guarantee of real-world risk."]
        if message.get("text_truncated"):
            warnings.append("Feature text was capped at 30,000 characters; original text is retained in the prepared input pipeline.")
        return {"S_WP": calculate_word_pool_score(scores, self.weights), "component_scores": scores,
                "weights": asdict(self.weights), "detected_ngrams": ngrams,
                "detected_collocations": collocations, "tfidf_explanation": explanation,
                "rare_patterns": rare, "cta_matches": cta, "warnings": warnings,
                "pattern_ratio_F": round(pattern_ratio, 6), "preprocessing": pipeline["report"],
                "model_version": self.model_version}

    def _lemma_index(self):
        index = getattr(self, "_lemma_idx", None)
        if index is None:
            from .preprocessing import normalize_text, _simple_lemma
            index = {}
            for phrase, weight in getattr(self.ngrams, "evidence", {}).items():
                key = " ".join(_simple_lemma(t) for t in normalize_text(phrase, remove_stop_words=True).split())
                if key and key != phrase:
                    index[key] = max(index.get(key, 0.0), weight)
            self._lemma_idx = index
        return index

    def _lemma_hits(self, lemmas, already):
        index, hits, seen = self._lemma_index(), [], set(already)
        for n in range(self.ngram_range[0], self.ngram_range[1] + 1):
            for i in range(max(0, len(lemmas) - n + 1)):
                key = " ".join(lemmas[i:i + n])
                if key in index and key not in seen:
                    seen.add(key)
                    hits.append({"phrase": key, "contribution": index[key] * 0.8, "matched_via": "lemmatized"})
        return hits

    def _relevant_pattern_count(self, text):
        vocab = getattr(getattr(self.ngrams, "vectorizer", None), "vocabulary_", None) or {}
        terms, found = text.split(), set()
        for n in range(self.ngram_range[0], self.ngram_range[1] + 1):
            for i in range(max(0, len(terms) - n + 1)):
                phrase = " ".join(terms[i:i + n])
                if phrase in vocab:
                    found.add(phrase)
        return found

    def save(self, path):
        path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(cls, path, *, expected_sha256=None):
        path = Path(path)
        if not path.is_file(): raise FileNotFoundError(f"Trained Word Pool model not found: {path}")
        if expected_sha256:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest.lower() != expected_sha256.lower():
                raise ValueError("Model checksum mismatch; refusing to load an unverified pickle artifact")
        model = joblib.load(path)
        if not isinstance(model, cls) or not model.fitted: raise ValueError("Model file is not a fitted WordPoolModel")
        return model


_DEFAULT_MODEL = None


def analyze_word_pool(subject="", body="", model=None, model_path="models/word_pool/model.joblib"):
    """Analyze one email; an untrained/missing model raises instead of guessing."""
    global _DEFAULT_MODEL
    if model is None:
        if _DEFAULT_MODEL is None:
            _DEFAULT_MODEL = WordPoolModel.load(model_path)
        model = _DEFAULT_MODEL
    return model.analyze(subject, body)
