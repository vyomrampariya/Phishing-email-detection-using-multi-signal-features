"""Independent Sender and Header Analysis (Phase 2)."""
from .analyzer import analyze_sender_header
from .scoring import score_components, DEFAULT_WEIGHTS
__all__ = ["analyze_sender_header", "score_components", "DEFAULT_WEIGHTS"]
