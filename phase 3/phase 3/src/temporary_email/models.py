"""Structured public data models."""
from dataclasses import asdict, dataclass, field
from typing import Any

@dataclass
class ComponentResult:
    score: float | None
    status: str
    evidence: list[str] = field(default_factory=list)
    source: str | None = None
    explanation: str = ""

@dataclass
class AnalysisResult:
    S_TEMP: float | None
    normalized_domain: str | None
    classification: str
    component_scores: dict[str, float | None]
    weights: dict[str, float]
    effective_weights: dict[str, float]
    component_statuses: dict[str, str]
    disposable_match: bool | None
    matched_sources: list[str]
    provider_category: str
    domain_age_days: int | None
    reputation_findings: list[str]
    evidence: dict[str, Any]
    missing_signals: list[str]
    score_completeness: float
    warnings: list[str]
    model_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
