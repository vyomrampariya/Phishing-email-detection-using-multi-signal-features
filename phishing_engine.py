"""Unified six-phase email phishing assessment entry point."""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PHASE_PATHS = [
    ROOT / "phase 1" / "src",
    ROOT / "phase 2" / "sender_header_phase2" / "src",
    ROOT / "phase 3" / "phase 3" / "src",
    ROOT / "phase 4" / "src",
    ROOT / "phase 5" / "src",
]
for path in PHASE_PATHS:
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from word_pool.models import WordPoolModel
from sender_header import analyze_sender_header
from temporary_email import analyze_temporary_email
from url_analysis import analyze_email_urls
from website_analysis import analyze_website
from website_analysis.acquisition import inspect_live

STATUS = {"available", "not_applicable", "unavailable", "error"}
DEFAULTS = {
    "weights": {
        "word_pool": 0.30,
        "sender_header": 0.20,
        "temporary_email": 0.10,
        "url_analysis": 0.25,
        "website_analysis": 0.15,
    },
    "thresholds": {"suspicious": 0.40, "high_risk": 0.70},
    "url_aggregation": "maximum",
    "website_retrieval": {
        "enabled": True,
        "max_urls": 8,
        "connect_timeout_seconds": 3.0,
        "read_timeout_seconds": 4.0,
        "total_timeout_seconds": 12.0,
        "max_response_bytes": 1_048_576,
        "max_redirects": 4,
    },
}


def _component(status, score=None, evidence=None, details=None, message=None):
    if status not in STATUS:
        raise ValueError(f"Invalid component status: {status}")
    if status == "available" and (
        score is None or not 0 <= float(score) <= 1
    ):
        raise ValueError("Available components require a score in [0,1]")
    if status != "available":
        score = None
    return {
        "status": status,
        "score": round(float(score), 8) if score is not None else None,
        "evidence": evidence or [],
        "details": details or {},
        "message": message,
    }


def fuse(components, weights=None, thresholds=None):
    cfg = dict(weights) if weights is not None else dict(DEFAULTS["weights"])
    if set(cfg) != set(components) or any(
        not isinstance(value, (int, float)) or value < 0
        for value in cfg.values()
    ):
        raise ValueError(
            "Fusion weights must be nonnegative and cover each component exactly"
        )

    for component in components.values():
        status, score = component.get("status"), component.get("score")
        if status not in STATUS:
            raise ValueError("Invalid component status")
        if status == "available":
            if (
                score is None
                or not math.isfinite(float(score))
                or not 0 <= float(score) <= 1
            ):
                raise ValueError(
                    "Available components require a finite score in [0,1]"
                )
        elif score is not None:
            raise ValueError("Non-available components must not carry a score")

    eligible = {
        key: component["score"]
        for key, component in components.items()
        if component["status"] == "available" and component["score"] is not None
    }
    total = sum(cfg[key] for key in eligible)
    score = (
        sum(cfg[key] * value for key, value in eligible.items()) / total
        if total > 0
        else None
    )
    limits = {**DEFAULTS["thresholds"], **(thresholds or {})}
    if not (
        0 <= limits["suspicious"] < limits["high_risk"] <= 1
    ):
        raise ValueError(
            "Thresholds must satisfy 0 <= suspicious < high_risk <= 1"
        )

    label = (
        "insufficient_evidence"
        if score is None
        else "high_risk"
        if score >= limits["high_risk"]
        else "suspicious"
        if score >= limits["suspicious"]
        else "low_risk_review"
    )
    return {
        "score": round(score, 8) if score is not None else None,
        "classification": label,
        "weights": cfg,
        "effective_weights": {
            key: cfg[key] / total for key in eligible
        } if total else {},
        "evidence_coverage": (
            round(total / sum(cfg.values()), 8) if sum(cfg.values()) else 0.0
        ),
        "eligible_components": list(eligible),
        "excluded_components": [
            key for key in components if key not in eligible
        ],
    }


def _load_config(config):
    if config is None:
        return DEFAULTS

    import yaml

    data = yaml.safe_load(Path(config).read_text(encoding="utf-8")) or {}
    retrieval = data.get("website_retrieval")
    return {
        **DEFAULTS,
        **data,
        "weights": {**DEFAULTS["weights"], **data.get("weights", {})},
        "thresholds": {
            **DEFAULTS["thresholds"],
            **data.get("thresholds", {}),
        },
        "website_retrieval": {
            **DEFAULTS["website_retrieval"],
            **(retrieval if isinstance(retrieval, dict) else {}),
        },
    }


def analyze_email(raw_email: str, *, config=None, word_pool_model=None,
                  website_retriever=None):
    cfg = _load_config(config)
    if not isinstance(raw_email, str) or not raw_email.strip():
        raise ValueError("Provide a non-empty RFC 5322 email message")

    message = Parser(policy=policy.default).parsestr(raw_email)
    subject = str(message.get("Subject", ""))
    body_parts = []
    html_parts = []

    if message.is_multipart():
        for part in message.walk():
            if (
                part.get_content_maintype() == "multipart"
                or part.get_content_disposition() == "attachment"
            ):
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if part.get_content_type() == "text/html":
                html_parts.append(str(content))
            elif part.get_content_type() == "text/plain":
                body_parts.append(str(content))
    else:
        try:
            content = message.get_content()
        except Exception:
            content = ""
        if message.get_content_type() == "text/html":
            html_parts.append(str(content))
        else:
            body_parts.append(str(content))

    body = "\n".join(body_parts)
    html_body = "\n".join(html_parts) or None
    components = {}
    warnings = []

    try:
        model = word_pool_model or WordPoolModel.load(
            ROOT / "phase 1" / "models" / "word_pool" / "model.joblib"
        )
        if not (subject.strip() or body.strip()):
            components["word_pool"] = _component(
                "unavailable", message="No subject or readable text body"
            )
        else:
            result = model.analyze(subject, body)
            warnings += result.get("warnings", [])
            evidence = (
                result.get("detected_ngrams", [])
                + result.get("detected_collocations", [])
                + result.get("cta_matches", [])
            )
            components["word_pool"] = _component(
                "available", result["S_WP"], evidence, result
            )
    except FileNotFoundError as exc:
        components["word_pool"] = _component("unavailable", message=str(exc))
    except Exception as exc:
        components["word_pool"] = _component(
            "error", message=f"{type(exc).__name__}: {exc}"
        )

    try:
        result = analyze_sender_header(raw_email)
        if result.get("S_HDR") is not None:
            evidence = (
                result.get("header_anomalies", [])
                + result.get("spoofing_indicators", [])
                + result.get("domain_similarity_findings", [])
            )
            components["sender_header"] = _component(
                "available", result["S_HDR"], evidence, result
            )
        else:
            components["sender_header"] = _component(
                "unavailable",
                details=result,
                message="Insufficient parsed sender/header signals",
            )
        warnings += result.get("warnings", [])
    except Exception as exc:
        components["sender_header"] = _component(
            "error", message=f"{type(exc).__name__}: {exc}"
        )

    try:
        sender = parseaddr(str(message.get("From", "")))[1]
        if not sender:
            components["temporary_email"] = _component(
                "unavailable", message="Sender address is missing"
            )
        else:
            result = analyze_temporary_email(sender)
            details = result.to_dict() if hasattr(result, "to_dict") else result
            score = details.get("S_TEMP")
            if score is not None:
                evidence = (
                    details.get("matched_sources", [])
                    + details.get("reputation_findings", [])
                )
                components["temporary_email"] = _component(
                    "available", score, evidence, details
                )
            else:
                components["temporary_email"] = _component(
                    "unavailable",
                    details=details,
                    message="No usable temporary-email scoring evidence",
                )
            warnings += details.get("warnings", [])
    except Exception as exc:
        components["temporary_email"] = _component(
            "error", message=f"{type(exc).__name__}: {exc}"
        )

    url_result = None
    try:
        url_result = analyze_email_urls(subject, body, html_body)
        if not url_result["url_count"]:
            components["url_analysis"] = _component(
                "not_applicable", message="No URLs in the email"
            )
        elif url_result.get("S_URL") is None:
            components["url_analysis"] = _component(
                "unavailable",
                details=url_result,
                message="URLs were found but none could be scored",
            )
        else:
            components["url_analysis"] = _component(
                "available",
                url_result["S_URL"],
                url_result.get("original_urls", []),
                url_result,
            )
        warnings += url_result.get("warnings", [])
    except Exception as exc:
        components["url_analysis"] = _component(
            "error", message=f"{type(exc).__name__}: {exc}"
        )

    urls = (url_result or {}).get("individual_url_scores", [])
    if not urls:
        components["website_analysis"] = _component(
            "not_applicable", message="No suitable URL target"
        )
    else:
        fetch_cfg = dict(cfg["website_retrieval"])
        env_value = os.environ.get(
            "PHISHING_WEBSITE_RETRIEVAL", ""
        ).strip().lower()
        fetch_enabled = bool(fetch_cfg.get("enabled", True)) and (
            env_value not in {"0", "false", "no", "off"}
        )

        website_results = []
        candidates = urls[:max(0, int(fetch_cfg.get("max_urls", 8)))]

        for item in candidates:
            target = item.get("normalized_url") or item.get("original_url")
            if not target:
                continue

            if not fetch_enabled:
                website_results.append({
                    "retrieval": {
                        "status": "unavailable",
                        "original_url": target,
                        "fetched": False,
                        "reason": "Website retrieval is disabled by configuration",
                    },
                    "static_analysis": None,
                })
                continue

            try:
                fetch = (website_retriever or inspect_live)(
                    target, config=fetch_cfg
                )
                if (
                    fetch.get("status") != "available"
                    or not fetch.get("fetched")
                ):
                    website_results.append({
                        "retrieval": {
                            key: value for key, value in fetch.items()
                            if key != "html"
                        },
                        "static_analysis": None,
                    })
                    continue

                report = analyze_website(
                    fetch.get("final_url") or target,
                    cached_evidence={
                        "html": fetch.get("html", ""),
                        "analysis_mode": "safe_server_retrieval",
                    },
                )
                page_components = report.get("component_scores", {})
                static_keys = ("C", "F", "S")
                static_weights = {
                    key: {"C": 0.15, "F": 0.20, "S": 0.10}[key]
                    for key in static_keys
                    if page_components.get(key, {}).get("score") is not None
                }
                static_total = sum(static_weights.values())
                static_score = (
                    sum(
                        static_weights[key]
                        * page_components[key]["score"]
                        for key in static_weights
                    ) / static_total
                    if static_total
                    else None
                )

                static_report = {
                    "S_WEB_STATIC_ONLY": (
                        round(static_score, 8)
                        if static_score is not None
                        else None
                    ),
                    "score_basis": (
                        "Static HTML C/F/S only; URL/domain D/N/I are excluded "
                        "to prevent overlap with Phase 4."
                    ),
                    "component_scores": {
                        key: page_components[key]
                        for key in static_keys
                    },
                    "page_metadata": report.get("page_metadata", {}),
                    "content_findings": report.get("content_findings", []),
                    "form_findings": report.get("form_findings", []),
                    "structure_findings": report.get("structure_findings", {}),
                    "warnings": report.get("warnings", []),
                    "analysis_mode": report.get("analysis_mode"),
                }
                fetch_meta = {
                    key: value for key, value in fetch.items()
                    if key != "html"
                }
                fetch_meta["page_title"] = (
                    static_report.get("page_metadata") or {}
                ).get("title")
                website_results.append({
                    "retrieval": fetch_meta,
                    "static_analysis": static_report,
                })
            except Exception as exc:
                website_results.append({
                    "retrieval": {
                        "status": "error",
                        "original_url": target,
                        "fetched": False,
                        "reason": (
                            "Unexpected retrieval or parsing error "
                            f"({type(exc).__name__})"
                        ),
                    },
                    "static_analysis": None,
                })

        if len(urls) > len(candidates):
            website_results.append({
                "retrieval": {
                    "status": "unavailable",
                    "fetched": False,
                    "reason": (
                        f"URL retrieval limit reached "
                        f"({len(candidates)} of {len(urls)} URLs checked)"
                    ),
                },
                "static_analysis": None,
            })

        assessed = [
            website["static_analysis"]["S_WEB_STATIC_ONLY"]
            for website in website_results
            if website.get("static_analysis")
            and website["static_analysis"].get("S_WEB_STATIC_ONLY") is not None
        ]
        summary = {
            "websites": website_results,
            "fetched_count": sum(
                1 for website in website_results
                if website.get("retrieval", {}).get("fetched")
            ),
            "url_count": len(urls),
            "retrieval_enabled": fetch_enabled,
            "static_scoring": (
                "C/F/S only; URL-level D/N/I signals are excluded to avoid "
                "double-counting Phase 4 evidence."
            ),
        }

        if assessed:
            web_score = 0.70 * max(assessed) + 0.30 * (
                sum(assessed) / len(assessed)
            )
            evidence = [
                entry
                for website in website_results
                if website.get("static_analysis")
                for key in ("C", "F", "S")
                for entry in website["static_analysis"]
                    .get("component_scores", {})
                    .get(key, {})
                    .get("evidence", [])
            ]
            components["website_analysis"] = _component(
                "available",
                web_score,
                evidence,
                summary,
                message=(
                    f"Static website content assessed for "
                    f"{summary['fetched_count']} of {len(urls)} URL(s)"
                ),
            )
        else:
            failures = [
                website.get("retrieval", {}).get("status")
                for website in website_results
            ]
            status = "error" if "error" in failures else "unavailable"
            components["website_analysis"] = _component(
                status,
                details=summary,
                message=(
                    "No website HTML was successfully fetched; website "
                    "evidence was excluded from scoring"
                ),
            )

    fusion = fuse(components, cfg["weights"], cfg["thresholds"])
    limitations = [
        "Scores are risk heuristics, not calibrated phishing probabilities.",
        (
            "Website retrieval uses bounded HTTP(S) requests with public-IP "
            "checks and redirect validation; deployment egress rules should "
            "also block private, reserved, and metadata networks."
        ),
        (
            "Website content is parsed as static HTML only; scripts, forms, "
            "and attachments are not executed or opened."
        ),
        (
            "Authentication-Results are unverified claims; SPF/DKIM/DMARC are "
            "not cryptographically checked."
        ),
    ]
    return {
        "score": fusion["score"],
        "classification": fusion["classification"],
        "components": components,
        "evidence_coverage": fusion["evidence_coverage"],
        "eligible_components": fusion["eligible_components"],
        "excluded_components": fusion["excluded_components"],
        "effective_weights": fusion["effective_weights"],
        "extracted_urls": [
            item.get("original_url") for item in urls
        ],
        "limitations": limitations,
        "warnings": list(dict.fromkeys(warnings)),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Unified six-phase phishing email risk assessment"
    )
    parser.add_argument(
        "email",
        nargs="?",
        help="Path to an RFC 5322 .eml file; defaults to stdin",
    )
    parser.add_argument("--config", help="Optional YAML configuration")
    args = parser.parse_args(argv)
    raw = (
        Path(args.email).read_text(encoding="utf-8", errors="replace")
        if args.email
        else sys.stdin.read()
    )
    print(
        json.dumps(
            analyze_email(raw, config=args.config),
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
