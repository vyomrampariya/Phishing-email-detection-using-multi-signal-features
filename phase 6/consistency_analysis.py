"""Phase 6: additional features - evidence consistency and thread/cross-email analysis."""
from intent import analyze_consistency, impersonated_brand, registered_domain, brands_in, BRANDS
from thread import analyze_thread, parse_message

MAX_RISK_BOOST = 0.12


def analyze_additional_features(ctx: dict, raw_email: str, related_raw_emails=None) -> dict:
    consistency = analyze_consistency(ctx)
    thread = analyze_thread(raw_email, related_raw_emails)
    scores = [s for s in (consistency["score"], thread["score"]) if s is not None]
    risk = max(scores) if scores else None
    return {
        "evidence_consistency": consistency,
        "thread_analysis": thread,
        "additional_risk": risk,
        "risk_boost": round(MAX_RISK_BOOST * risk, 4) if risk is not None else 0.0,
        "evidence_reliability": consistency["evidence_reliability"],
    }


__all__ = ["impersonated_brand", "registered_domain", "brands_in", "BRANDS", "analyze_additional_features", "analyze_consistency", "analyze_thread", "parse_message", "MAX_RISK_BOOST"]
