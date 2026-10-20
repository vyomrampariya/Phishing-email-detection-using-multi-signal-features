"""Supervised word-level TF-IDF classifier (fit on training text only)."""
from __future__ import annotations

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


class TfidfPhishingModel:
    def __init__(self, seed: int = 42):
        self.seed = seed
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=100_000,
                                          sublinear_tf=True, strip_accents="unicode")
        self.classifier = LogisticRegression(max_iter=300, solver="liblinear", class_weight="balanced", random_state=seed)
        self.fitted = False

    def fit(self, texts, labels):
        unique = set(int(x) for x in labels)
        if unique != {0, 1}:
            raise ValueError("TF-IDF model requires both classes (0 and 1) in training data")
        matrix = self.vectorizer.fit_transform(texts)
        self.classifier.fit(matrix, labels)
        self.feature_names = self.vectorizer.get_feature_names_out()
        self.fitted = True
        return self

    def predict_score(self, text: str) -> tuple[float, list[dict]]:
        if not self.fitted:
            raise RuntimeError("TF-IDF model is not trained; run the training command first")
        matrix = self.vectorizer.transform([text])
        probability = float(self.classifier.predict_proba(matrix)[0][list(self.classifier.classes_).index(1)])
        weights = self.classifier.coef_[0]
        terms = matrix.tocoo()
        explanation = []
        for col, value in zip(terms.col, terms.data):
            contribution = float(value * weights[col])
            if contribution > 0:
                explanation.append({"term": self.feature_names[col], "contribution": contribution})
        explanation.sort(key=lambda x: x["contribution"], reverse=True)
        return min(1.0, max(0.0, probability)), explanation[:10]
