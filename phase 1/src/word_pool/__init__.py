"""Phase 1 Word Pool email text analysis."""

from .models import WordPoolModel, analyze_word_pool
from .scoring import WordPoolWeights, calculate_word_pool_score

__all__ = ["WordPoolModel", "WordPoolWeights", "analyze_word_pool", "calculate_word_pool_score"]
