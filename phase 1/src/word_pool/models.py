"""Fit, persist, and invoke the stable Phase 1 Word Pool interface."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import json

import joblib

from .collocation_features import CollocationFeatures
from .cta_features import CTAFeatures
from .ngram_features import NgramFeatures
from .preprocessing import prepare_email
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
        warnings = ["TF-IDF outputs are uncalibrated model probabilities and are not a guarantee of real-world risk."]
        if message.get("text_truncated"):
            warnings.append("Feature text was capped at 30,000 characters; original text is retained in the prepared input pipeline.")
        return {"S_WP": calculate_word_pool_score(scores, self.weights), "component_scores": scores,
                "weights": asdict(self.weights), "detected_ngrams": ngrams,
                "detected_collocations": collocations, "tfidf_explanation": explanation,
                "rare_patterns": rare, "cta_matches": cta, "warnings": warnings,
                "model_version": self.model_version}

    def save(self, path):
        path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(cls, path):
        path = Path(path)
        if not path.is_file(): raise FileNotFoundError(f"Trained Word Pool model not found: {path}")
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
