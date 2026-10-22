"""Temporary Email Analysis (Phase 3)."""
from .analysis import analyze_temporary_email
from .models import ComponentResult, AnalysisResult

__all__ = ["analyze_temporary_email", "ComponentResult", "AnalysisResult"]
