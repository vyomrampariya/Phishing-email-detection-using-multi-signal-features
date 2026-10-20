"""Rule-based, interpretable sender/header risk assessment; no network access by default."""
from __future__ import annotations
from typing import Any, Callable
from .parser import parse_email
from .domain_similarity import findings as domain_findings, registered_domain
from .scoring import DEFAULT_WEIGHTS, score_components

AUTH_RISK = {"PASS": 0.0, "FAIL": 1.0, "SOFTFAIL": .65, "NEUTRAL": .35, "NONE": .45, "TEMPERROR": .25, "PERMERROR": .55, "UNKNOWN": None, "UNAVAILABLE": None}

def analyze_sender_header(raw_email: str, trusted_domains: list[str] | None = None,
                          reputation_provider: Callable[[str], dict[str, Any]] | None = None,
                          weights: dict[str, float] | None = None) -> dict[str, Any]:
    parsed = parse_email(raw_email)
    trusted = [registered_domain(d) for d in (trusted_domains or [])]
    from_domain = parsed["from_domain"]
    reply_domain = parsed["reply_to_domain"]
    rp_domain = parsed["return_path_domain"]
    warnings: list[str] = []
    evidence: list[dict[str, Any]] = []
    # Reputation is unavailable unless supplied by a documented provider or an explicit trusted list.
    rep_score: float | None = None
    rep_status = "unavailable"
    if from_domain and registered_domain(from_domain) in trusted:
        rep_score, rep_status = 0.0, "observed"
        evidence.append({"source": "caller_trusted_domains", "domain": from_domain, "finding": "trusted-domain match"})
    elif reputation_provider and from_domain:
        try:
            record = reputation_provider(from_domain)
            if record and record.get("status") in {"malicious", "trusted", "neutral"}:
                rep_score = {"malicious": 1.0, "trusted": 0.0, "neutral": .25}[record["status"]]
                rep_status = "observed"
                evidence.append({"source": record.get("source", "custom_provider"), "domain": from_domain, "finding": record["status"]})
        except Exception as exc:
            warnings.append(f"Reputation provider failed: {type(exc).__name__}")
    # Mismatch risk: mismatch is a signal, not a verdict; mailing-list/delegated context softens it.
    mismatch: float | None = None
    if parsed["from_address"]:
        mismatch = 0.0
        if reply_domain and reply_domain != from_domain:
            mismatch = .65 if registered_domain(reply_domain) == registered_domain(from_domain) else .8
            if any(x in " ".join(parsed["headers"].get("list-id", []) + parsed["headers"].get("list-unsubscribe", [])) for x in ["<", "@"]): mismatch *= .75
            evidence.append({"source": "headers", "finding": "From and Reply-To domains differ", "from_domain": from_domain, "reply_to_domain": reply_domain})
        if rp_domain and from_domain and registered_domain(rp_domain) != registered_domain(from_domain):
            mismatch = max(mismatch, .35)
            if parsed["headers"].get("list-id"): mismatch = min(mismatch, .25)
    # Structural anomalies with graded weights; optional headers are not treated as fatal.
    anomaly_map = {"missing_from": 1.0, "malformed_from": .9, "duplicate_from": .75, "missing_message_id": .25,
                   "missing_date": .2, "duplicate_message_id": .4, "duplicate_date": .25,
                   "malformed_message_id": .45, "duplicate_reply_to": .45, "duplicate_return_path": .35}
    anomaly_vals = [anomaly_map.get(a, .35 if a.startswith("conflicting_") else .25) for a in parsed["header_anomalies"]]
    anomaly = min(1.0, sum(anomaly_vals) / max(1, len(anomaly_vals)) + (0.08 if len(anomaly_vals) > 2 else 0))
    # Authentication claims are parsed but not considered verified unless a trusted MTA is configured externally.
    auth_vals = [AUTH_RISK[s] for s in parsed["auth"].values()]
    available_auth = [v for v in auth_vals if v is not None]
    auth = (sum(available_auth) / len(available_auth)) if available_auth else None
    if auth is not None:
        warnings.append("Authentication-Results are parsed claims only; no trusted-receiver provenance or cryptographic verification was performed.")
    spoof_score = 0.0 if parsed["from_address"] else None
    spoof_indicators = []
    display = (parsed["from_display_name"] or "").lower()
    for brand in trusted_domains or []:
        brand_token = brand.split(".")[0].lower()
        if brand_token and brand_token in display and from_domain and registered_domain(from_domain) != registered_domain(brand):
            spoof_indicators.append({"type": "display_name_impersonation_candidate", "reference": brand, "explanation": "Display name contains a configured trusted-domain token but sender domain differs."})
    if spoof_score is not None and spoof_indicators: spoof_score = min(1.0, .65 + .1 * (len(spoof_indicators)-1))
    sim_findings = domain_findings(from_domain, trusted_domains)
    similarity = max([float(f.get("similarity", .0)) for f in sim_findings] or [0.0])
    if not from_domain: similarity = None
    component_scores = {"Rep": rep_score, "Mismatch": mismatch, "Anomaly": anomaly if parsed["from_values"] or parsed["header_anomalies"] else None,
                        "Auth": auth, "Spoof": spoof_score, "Similarity": similarity}
    scored = score_components(component_scores, weights or DEFAULT_WEIGHTS)
    alignment = {"spf_aligned": None, "dkim_aligned": None, "dmarc_aligned": None, "note": "Alignment cannot be verified from these headers alone."}
    return {"S_HDR": scored["S_HDR"], "score_status": scored["status"], "component_scores": component_scores,
            "weights": scored["weights"], "component_statuses": {k: ("unavailable" if v is None else "observed") for k, v in component_scores.items()},
            "from_address": parsed["from_address"], "from_domain": from_domain, "reply_to_address": parsed["reply_to_address"],
            "reply_to_domain": reply_domain, "return_path_domain": rp_domain, "spf_status": parsed["auth"]["spf"],
            "dkim_status": parsed["auth"]["dkim"], "dmarc_status": parsed["auth"]["dmarc"], "alignment_results": alignment,
            "header_anomalies": parsed["header_anomalies"], "spoofing_indicators": spoof_indicators,
            "domain_similarity_findings": sim_findings, "reputation_evidence": evidence,
            "evidence_sources": ["raw_headers"] + (["caller_trusted_domains"] if trusted_domains else []) + (["reputation_provider"] if reputation_provider else []),
            "missing_signals": scored["missing_components"], "warnings": warnings, "model_version": "phase2-rules-0.1.0",
            "score_completeness": scored["score_completeness"], "authentication_evidence_trust": parsed["authentication_evidence_trust"]}
