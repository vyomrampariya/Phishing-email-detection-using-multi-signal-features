"""Unified multi-signal email phishing assessment entry point."""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
WORD_POOL_MODEL_SHA256 = "d4eaf378c84f5e135cc0e1817bb2c174de67cc505ed0fc9598161075371dce6a"
PHASE_PATHS = [
    ROOT / "phase 1" / "src",
    ROOT / "phase 2" / "src",
    ROOT / "phase 3" / "src",
    ROOT / "phase 4" / "src",
    ROOT / "phase 5" / "src",
    ROOT / "phase 6",
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
from website_analysis.intelligence import (
    collect_optional_context, rdap_registration, visual_brand_signals,
)
from sender_header.reputation import lexical_reputation
from consistency_analysis import analyze_additional_features, impersonated_brand, registered_domain as _reg_domain, brands_in

STATUS = {"available", "not_applicable", "unavailable", "error"}
DEFAULTS = {
    "weights": {
        "word_pool": 0.25,
        "sender_header": 0.15,
        "temporary_email": 0.10,
        "url_analysis": 0.20,
        "website_analysis": 0.20,
        "attachment_analysis": 0.10,
    },
    "thresholds": {"suspicious": 0.30, "phishy": 0.60},
    "website_weights": {"domain": 0.30, "brand": 0.25, "language": 0.20, "credentials": 0.25},
    # Human Review gate: any one of these sends the message to a person instead of
    # applying the Safe / Suspicious / Phishy thresholds.
    "minimum_evidence_coverage": 0.60,
    "minimum_eligible_components": 4,
    "risk_indicators": {
        "cap": 0.55,
        "weights": {
            "brand_impersonation": 0.15,
            "misspelled_brand_domain": 0.25,
            "brand_claim_mismatch": 0.15,
            "reply_to_lookalike": 0.10,
            "sender_identity_mismatch": 0.10,
            "link_obfuscation": 0.10,
            "multi_risk_links": 0.05,
            "credential_token_in_link": 0.05,
            "disposable_sender": 0.10,
            "pressure_language": 0.05,
        },
    },
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


VERDICTS = ("safe", "suspicious", "phishy", "human_review")
VERDICT_LABELS = {"safe": "Safe", "suspicious": "Suspicious", "phishy": "Phishy", "human_review": "Human Review"}


def human_review_reasons(evidence_coverage, eligible_count, consistency_status, *,
                         minimum_evidence_coverage=0.60, minimum_components=4):
    """Why a message must go to a person. Empty list = normal thresholds apply.

    IF evidence_coverage < 0.6 OR eligible components < 4
       OR evidence_consistency.status == "insufficient_evidence"  -> Human Review
    """
    reasons = []
    if evidence_coverage is None or evidence_coverage < minimum_evidence_coverage:
        reasons.append(f"evidence coverage {0 if evidence_coverage is None else evidence_coverage:.0%} is below {minimum_evidence_coverage:.0%}")
    if eligible_count is not None and eligible_count < minimum_components:
        reasons.append(f"only {eligible_count} usable components (need {minimum_components})")
    if consistency_status == "insufficient_evidence":
        reasons.append("evidence consistency could not be judged (insufficient evidence)")
    return reasons


def classify(score, evidence_coverage, minimum_evidence_coverage, limits, *,
             eligible_count=None, minimum_components=0, consistency_status=None):
    """Verdict categories: Safe 0.00-<0.30, Suspicious 0.30-<0.60, Phishy 0.60-1.00;
    Human Review when evidence is insufficient for any of the above."""
    if score is None or human_review_reasons(
        evidence_coverage, eligible_count, consistency_status,
        minimum_evidence_coverage=minimum_evidence_coverage, minimum_components=minimum_components,
    ):
        return "human_review"
    if score >= limits["phishy"]:
        return "phishy"
    if score >= limits["suspicious"]:
        return "suspicious"
    return "safe"


_PRESSURE_RE = re.compile(
    r"\b(?:urgent(?:ly)?|immediately|act now|final notice|failure to (?:act|respond|verify)|"
    r"within \d+\s*hours?|(?:will|may) (?:be )?(?:limited|suspended|locked|closed|terminated|expire[sd]?)|"
    r"expires? in \d+|account (?:has been |will be )?(?:suspended|locked|limited|restricted))\b", re.I)
_CREDENTIAL_RE = re.compile(
    r"\b(?:confirm|verify|validate|update|re-?enter|provide|submit|enter)\s+(?:your\s+)?"
    r"(?:identity|password|credentials|card(?:\s+details?)?|billing(?:\s+details?)?|payment(?:\s+details?)?|login|account)\b", re.I)
_TOKEN_PARAMS = {"token", "access_token", "id_token", "jwt", "session", "sessionid", "sid", "auth", "otp", "key", "code"}
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}")


def risk_indicators(text, urls, header, temp_details, header_cfg=None, cfg=None, from_display=""):
    """Bounded, explainable evidence rules that a weighted average would dilute.

    Each rule fires at most once, carries its own evidence, and the total is capped, so
    no single heuristic can decide the verdict alone. Weights live in configs/integrated.yaml.
    """
    from urllib.parse import urlsplit, parse_qsl
    cfg = cfg or DEFAULTS["risk_indicators"]
    weights, found = cfg["weights"], {}
    scores = (header or {}).get("component_scores") or {}

    # --- brand impersonation: sender / reply-to / link domains / header spoof findings
    hits = []
    for role, dom in (("sender", (header or {}).get("from_domain")), ("reply-to", (header or {}).get("reply_to_domain"))):
        m = impersonated_brand(dom)
        if m:
            hits.append({"where": role, **m})
    risky_urls = []
    for item in urls:
        feats = item.get("features") or {}
        host = (feats.get("normalization") or {}).get("hostname") or urlsplit(item.get("normalized_url") or item.get("original_url") or "").hostname
        kinds = []
        m = impersonated_brand(host)
        if m:
            hits.append({"where": "link", **m}); kinds.append("brand_lookalike")
        if feats.get("is_ip"):
            kinds.append("ip_host")
            path = urlsplit(item.get("normalized_url") or "").path
            for brand in brands_in(path.replace("-", " ").replace("_", " ").replace("/", " ")):
                hits.append({"where": "link path on IP host", "brand": brand, "domain": host, "kind": "brand_on_ip"})
        for ind in item.get("redirect_indicators") or []:
            kinds.append(ind.get("type"))
        if feats.get("at_in_authority"): kinds.append("userinfo")
        if feats.get("punycode"): kinds.append("punycode")
        if feats.get("unusual_port"): kinds.append("unusual_port")
        risky_urls.append((item, kinds))
    if (scores.get("Spoof") or 0) >= 0.5 or (scores.get("Similarity") or 0) >= 0.7:
        hits.append({"where": "header", "kind": "spoof_or_lookalike", "spoof": scores.get("Spoof"), "similarity": scores.get("Similarity")})
    if hits:
        # A deliberately misspelled brand (microsft, paypa1) is stronger evidence than a
        # brand plus a lure word (paypal-secure), so it replaces the lower-tier rule.
        misspelled = [h for h in hits if h.get("kind") in {"lookalike", "homoglyph"}]
        found["misspelled_brand_domain" if misspelled else "brand_impersonation"] = (misspelled or hits)[:6]

    # --- the brand named in the display name / subject / body is imitated by the sender or a link
    claimed = brands_in(f"{from_display} {text}")
    imitated = {h["brand"] for h in hits if h.get("where") in {"sender", "link", "reply-to"} and h.get("brand")}
    mismatch_claims = sorted(claimed & imitated)
    if mismatch_claims:
        found["brand_claim_mismatch"] = [{"brand": b, "claimed_in": "display name / subject / body"} for b in mismatch_claims]

    # --- Reply-To is a look-alike of the From domain (reply hijack), even when From is genuine
    if scores.get("Mismatch") == 1.0 and (scores.get("Similarity") or 0) >= 0.7:
        found["reply_to_lookalike"] = [{"from": (header or {}).get("from_domain"), "reply_to": (header or {}).get("reply_to_domain")}]
    elif scores.get("Mismatch") == 1.0 and impersonated_brand((header or {}).get("reply_to_domain")):
        found["reply_to_lookalike"] = [{"from": (header or {}).get("from_domain"), "reply_to": (header or {}).get("reply_to_domain")}]

    # --- From vs Reply-To registered domain differ
    if scores.get("Mismatch") == 1.0:
        found["sender_identity_mismatch"] = [{"from": (header or {}).get("from_domain"), "reply_to": (header or {}).get("reply_to_domain")}]

    # --- link obfuscation / many risky links
    obfuscation = {"shortener_domain", "redirect_parameter", "nested_url_parameter", "ip_host", "userinfo", "punycode", "unusual_port"}
    flagged = [(it.get("original_url"), sorted(set(k for k in kinds if k in obfuscation))) for it, kinds in risky_urls if any(k in obfuscation for k in kinds)]
    if flagged:
        found["link_obfuscation"] = [{"url": u, "signals": k} for u, k in flagged[:6]]
    risky_count = sum(1 for _, kinds in risky_urls if kinds)
    domains = {_reg_domain(((it.get("features") or {}).get("normalization") or {}).get("hostname")) for it, _ in risky_urls}
    if risky_count >= 2 or (len(domains - {None}) >= 3 and risky_count >= 1):
        found["multi_risk_links"] = [{"risky_links": risky_count, "distinct_domains": len(domains - {None})}]

    # --- credential-bearing tokens in a link to an unrecognised host
    token_hits = []
    for item, _ in risky_urls:
        q = urlsplit(item.get("normalized_url") or item.get("original_url") or "").query
        for k, v in parse_qsl(q, keep_blank_values=True):
            if _JWT_RE.search(v) or k.lower() in _TOKEN_PARAMS and len(v) >= 6:
                token_hits.append({"url": item.get("original_url"), "parameter": k})
                break
    if token_hits:
        found["credential_token_in_link"] = token_hits[:4]

    if (temp_details or {}).get("disposable_match"):
        found["disposable_sender"] = [{"domain": (temp_details or {}).get("normalized_domain")}]

    pressure = _PRESSURE_RE.findall(text) + _CREDENTIAL_RE.findall(text)
    if pressure:
        found["pressure_language"] = [{"matched": sorted({p.lower() for p in pressure})[:5]}]

    total = round(min(cfg.get("cap", 0.45), sum(weights[k] for k in found)), 4)
    return {"total": total, "fired": {k: {"weight": weights[k], "evidence": v} for k, v in found.items()}}


def fuse(components, weights=None, thresholds=None, minimum_evidence_coverage=0.0):
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
        0 <= limits["suspicious"] < limits["phishy"] <= 1
    ):
        raise ValueError(
            "Thresholds must satisfy 0 <= suspicious < phishy <= 1"
        )
    if not 0 <= minimum_evidence_coverage <= 1:
        raise ValueError("Minimum evidence coverage must be in [0, 1]")
    evidence_coverage = total / sum(cfg.values()) if sum(cfg.values()) else 0.0

    label = classify(score, evidence_coverage, minimum_evidence_coverage, limits)
    return {
        "score": round(score, 8) if score is not None else None,
        "classification": label,
        "weights": cfg,
        "effective_weights": {
            key: cfg[key] / total for key in eligible
        } if total else {},
        "evidence_coverage": round(evidence_coverage, 8),
        "minimum_evidence_coverage": minimum_evidence_coverage,
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
        "risk_indicators": {
            **DEFAULTS["risk_indicators"],
            **(data.get("risk_indicators") or {}),
            "weights": {
                **DEFAULTS["risk_indicators"]["weights"],
                **((data.get("risk_indicators") or {}).get("weights") or {}),
            },
        },
    }


def _load_phase_config(relative_path):
    path = ROOT / relative_path
    if not path.is_file():
        return {}
    import yaml
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _website_component(urls, cfg, fetch_enabled, website_retriever, registration_provider,
                       screenshot_provider, search_provider):
    """Section 6: S_WEB = w1*S_domain + w2*S_brand + w3*S_lang + w4*S_cred, per page,
    renormalised over the signals that were actually observed."""
    from word_pool.preprocessing import readable_text

    fetch_cfg = dict(cfg["website_retrieval"])
    web_cfg = _load_phase_config(Path("phase 5") / "configs" / "website_analysis.yaml")
    brands = web_cfg.get("brands", [])
    web_w = {**DEFAULTS["website_weights"], **cfg.get("website_weights", {})}
    candidates = urls[:max(0, int(fetch_cfg.get("max_urls", 8)))]
    results, pages = [], []

    for item in candidates:
        target = item.get("normalized_url") or item.get("original_url")
        if not target:
            continue
        retrieval = {"status": "unavailable", "original_url": target, "fetched": False,
                     "reason": "Website retrieval is disabled by configuration"}
        html, evidence = None, {}
        try:
            host = (urlparse(target).hostname or "").lower()
            lex = lexical_reputation(host)
            if lex["score"] is not None:
                evidence["reputation_findings"] = [
                    {"risk": lex["score"], "source": "offline_lexical_heuristic", "label": "; ".join(lex["findings"])}
                ]
            if fetch_enabled:
                registration = (registration_provider or rdap_registration)(host)
                if registration:
                    evidence.update(registration)
                fetch = (website_retriever or inspect_live)(target, config=fetch_cfg)
                retrieval = {k: v for k, v in fetch.items() if k != "html"}
                if fetch.get("status") == "available" and fetch.get("fetched"):
                    html = fetch.get("html", "")
                    evidence["html"] = html
                    evidence["analysis_mode"] = "safe_server_retrieval"
            report = analyze_website(target, config=web_cfg, cached_evidence=evidence)
            comp = report.get("component_scores", {})

            def sc(key):
                return (comp.get(key) or {}).get("score")

            extra = collect_optional_context(target, report.get("registered_domain") or host,
                                             screenshot_provider if fetch_enabled else None,
                                             search_provider if fetch_enabled else None)
            logo = visual_brand_signals(html, retrieval.get("final_url") or target, brands) if html else {"score": None, "findings": []}

            def avg(vals):
                vals = [v for v in vals if v is not None]
                return sum(vals) / len(vals) if vals else None

            search_risk = (extra["search_context"].get("negative_mentions") if extra["search_context"]["status"] == "observed" else None)
            if extra["search_context"]["status"] == "observed" and extra["search_context"].get("indexed") is False:
                search_risk = max(search_risk or 0.0, 0.4)
            shot_risk = extra["screenshot"].get("brand_match") if extra["screenshot"]["status"] == "observed" else None
            signals = {
                "domain": avg([sc("D"), sc("N"), search_risk]),
                "brand": max([v for v in (sc("I"), logo["score"], shot_risk) if v is not None], default=None),
                "language": sc("C"),
                "credentials": (None if sc("F") is None else (sc("F") if sc("S") is None else 0.75 * sc("F") + 0.25 * sc("S"))),
            }
            weights = {k: web_w[k] for k, v in signals.items() if v is not None}
            total = sum(weights.values())
            page_score = sum(weights[k] * signals[k] for k in weights) / total if total else None
            meta = report.get("page_metadata") or {}
            retrieval["page_title"] = meta.get("title")
            analysis = {
                "S_WEB": round(page_score, 8) if page_score is not None else None,
                "signals": {k: (round(v, 4) if v is not None else None) for k, v in signals.items()},
                "weights": web_w,
                "domain_findings": report.get("domain_findings"),
                "brand_findings": (report.get("brand_findings") or []) + logo["findings"],
                "content_findings": report.get("content_findings", []),
                "form_findings": report.get("form_findings", []),
                "structure_findings": report.get("structure_findings", {}),
                "registration_findings": report.get("registration_findings"),
                "screenshot": extra["screenshot"], "search_context": extra["search_context"],
                "warnings": report.get("warnings", []),
                "analysis_mode": report.get("analysis_mode"),
            }
            results.append({"retrieval": retrieval, "analysis": analysis})
            if html:
                pages.append({"url": target, "title": meta.get("title"), "text": readable_text(html)[:1500]})
        except Exception as exc:
            results.append({"retrieval": {"status": "error", "original_url": target, "fetched": False,
                                          "reason": f"Unexpected retrieval or parsing error ({type(exc).__name__})"},
                            "analysis": None})

    if len(urls) > len(candidates):
        results.append({"retrieval": {"status": "unavailable", "fetched": False,
                                      "reason": f"URL retrieval limit reached ({len(candidates)} of {len(urls)} URLs checked)"},
                        "analysis": None})
    assessed = [r["analysis"]["S_WEB"] for r in results if r.get("analysis") and r["analysis"]["S_WEB"] is not None]
    fetched = sum(1 for r in results if r["retrieval"].get("fetched"))
    summary = {
        "websites": results, "fetched_count": fetched, "url_count": len(urls),
        "retrieval_enabled": fetch_enabled,
        "score_basis": "S_WEB = w1*S_domain + w2*S_brand + w3*S_lang + w4*S_cred, renormalised over observed signals; "
                       "language and credential signals require a fetched page.",
    }
    if assessed:
        score = 0.70 * max(assessed) + 0.30 * (sum(assessed) / len(assessed))
        evidence = []
        for r in results:
            a = r.get("analysis")
            if a:
                evidence += a["brand_findings"] + a["content_findings"] + [f for f in a["form_findings"] if isinstance(f, dict)][:3]
                dom = (a.get("domain_findings") or {}).get("reputation") or []
                evidence += dom
        note = (f"Page content assessed for {fetched} of {len(urls)} URL(s)" if fetched
                else "Domain and brand signals only (page retrieval is off or failed); language and credential signals were not observed")
        return _component("available", score, evidence, summary, message=note), pages
    failures = [r["retrieval"].get("status") for r in results]
    return _component("error" if "error" in failures else "unavailable", details=summary,
                      message="No website evidence could be scored"), pages


def _retrieval_enabled(cfg, override):
    env_value = os.environ.get("PHISHING_WEBSITE_RETRIEVAL", "").strip().lower()
    blocked = env_value in {"0", "false", "no", "off"}
    if override is not None:
        return bool(override) and not blocked
    return bool(cfg["website_retrieval"].get("enabled", True)) and not blocked


def analyze_email(raw_email: str, *, config=None, word_pool_model=None,
                  website_retriever=None, website_retrieval_enabled=None,
                  related_emails=None, registration_provider=None,
                  screenshot_provider=None, search_provider=None):
    cfg = _load_config(config)
    if not isinstance(raw_email, str) or not raw_email.strip():
        raise ValueError("Provide a non-empty RFC 5322 email message")

    message = Parser(policy=policy.default).parsestr(raw_email)
    subject = str(message.get("Subject", ""))
    body_parts = []
    html_parts = []
    attachments = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment" or part.get_filename():
                payload = part.get_payload(decode=True) or b""
                attachments.append({"filename": part.get_filename() or "(unnamed attachment)",
                                    "content_type": part.get_content_type().lower(),
                                    "size_bytes": len(payload),
                                    "inline": part.get_content_disposition() != "attachment"})
                continue
            if (
                part.get_content_maintype() == "multipart"
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
    if not body.strip() and html_parts:
        from word_pool.preprocessing import readable_text
        body = "\n".join(readable_text(part) for part in html_parts)
    html_body = "\n".join(html_parts) or None
    components = {}
    warnings = []
    fetch_enabled = _retrieval_enabled(cfg, website_retrieval_enabled)
    free_mail = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com", "aol.com", "live.com"}

    try:
        model = word_pool_model or WordPoolModel.load(
            ROOT / "phase 1" / "models" / "word_pool" / "model.joblib",
            expected_sha256=WORD_POOL_MODEL_SHA256,
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
        header_cfg = _load_phase_config(Path("phase 2") / "configs" / "sender_header.yaml")
        url_cfg = _load_phase_config(Path("phase 4") / "configs" / "url_analysis.yaml")
        protected = header_cfg.get("trusted_domains") or url_cfg.get("trusted_domains", [])
        result = analyze_sender_header(raw_email, trusted_domains=protected)
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
        reply_addr = parseaddr(str(message.get("Reply-To", "")))[1]
        if not sender:
            components["temporary_email"] = _component(
                "unavailable", message="Sender address is missing"
            )
        else:
            temp_cfg = ROOT / "phase 3" / "configs" / "temporary_email.yaml"
            targets = [("from", sender)]
            if reply_addr and "@" in reply_addr and reply_addr.split("@")[-1].lower() != sender.split("@")[-1].lower():
                targets.append(("reply_to", reply_addr))
            analyses = {}
            for role, address in targets:
                domain = address.split("@")[-1].lower()
                age_days = None
                if fetch_enabled and domain not in free_mail:
                    registration = (registration_provider or rdap_registration)(domain)
                    age_days = (registration or {}).get("registration_age_days")
                outcome = analyze_temporary_email(address, config=temp_cfg, domain_age_days=age_days)
                analyses[role] = outcome.to_dict() if hasattr(outcome, "to_dict") else outcome
            scored = {r: d for r, d in analyses.items() if d.get("S_TEMP") is not None}
            if scored:
                worst = max(scored, key=lambda r: scored[r]["S_TEMP"])
                details = dict(analyses[worst])
                details["analyzed_addresses"] = {r: analyses[r].get("domain") for r in analyses}
                details["worst_address"] = worst
                evidence = []
                for role, d in analyses.items():
                    for item in d.get("matched_sources", []) + d.get("reputation_findings", []):
                        evidence.append(f"{role}: {item}" if isinstance(item, str) else item)
                    if d.get("disposable_match"):
                        evidence.append(f"{role} address uses a known disposable provider ({dict(targets)[role].split('@')[-1]})")
                components["temporary_email"] = _component(
                    "available", scored[worst]["S_TEMP"], evidence, details
                )
            else:
                components["temporary_email"] = _component(
                    "unavailable",
                    details=analyses.get("from", {}),
                    message="No usable temporary-email scoring evidence",
                )
            for d in analyses.values():
                warnings += d.get("warnings", [])
    except Exception as exc:
        components["temporary_email"] = _component(
            "error", message=f"{type(exc).__name__}: {exc}"
        )

    # Assess attachment metadata only; do not unpack or execute untrusted files.
    attachment_findings = []
    risky_extensions = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img", ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".html", ".htm", ".lnk", ".jar"}
    for item in attachments:
        if item.get("inline") and item["content_type"].startswith("image/"):
            continue
        name = (item["filename"] or "").lower()
        suffixes = Path(name).suffixes
        reasons = []
        risk = 0.0
        if any(s in risky_extensions for s in suffixes):
            risk = 0.65
            reasons.append("potentially risky file type")
        if len(suffixes) > 1 and suffixes[-1] in risky_extensions and suffixes[-2] in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt", ".rtf", ".xls", ".xlsx"}:
            risk = 1.0
            reasons.append("double extension may disguise executable content")
        expected_mime = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
        ext = Path(name).suffix
        if ext in expected_mime and item["content_type"] not in {expected_mime[ext], "application/octet-stream"}:
            risk = max(risk, 0.7)
            reasons.append("file extension and declared MIME type differ")
        if reasons:
            attachment_findings.append({**item, "risk": risk, "findings": reasons})
    components["attachment_analysis"] = _component(
        "available" if attachments else "not_applicable",
        max((x["risk"] for x in attachment_findings), default=0.0) if attachments else None,
        attachment_findings,
        {"attachment_count": len(attachments), "metadata_only": True, "attachments": attachments},
        "Filename, declared MIME type, and size only; file contents were not opened." if attachments else "No MIME attachments found",
    )

    url_result = None
    try:
        url_cfg = _load_phase_config(Path("phase 4") / "configs" / "url_analysis.yaml")
        url_result = analyze_email_urls(subject, body, html_body, config=url_cfg)
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
    website_pages = []
    if not urls:
        components["website_analysis"] = _component(
            "not_applicable", message="No suitable URL target"
        )
    else:
        components["website_analysis"], website_pages = _website_component(
            urls, cfg, fetch_enabled, website_retriever,
            registration_provider, screenshot_provider, search_provider,
        )

    fusion = fuse(components, cfg["weights"], cfg["thresholds"],
                  cfg.get("minimum_evidence_coverage", 0.60))
    # A mismatched visible link plus explicit credential-harvesting language is
    # a conjunctive high-confidence heuristic; it cannot be canceled by weak
    # unrelated components. This is an explainable rule, not a calibrated claim.
    body_for_rules = (subject + " " + body).casefold()
    credential_language = bool(re.search(
        r"\b(?:verify|confirm|secure|restore|unlock|validate)\s+(?:your\s+)?(?:account|identity|email|password|payment)\b|"
        r"\b(?:enter|provide|submit)\s+(?:your\s+)?(?:password|credentials|payment details)\b|"
        r"\b(?:sign in|log in)\s+to\s+(?:verify|confirm|restore)\b",
        body_for_rules,
    ))
    anchor_mismatch = any(
        item.get("anchor_mismatch")
        for item in (url_result or {}).get("individual_url_scores", [])
    )
    strong_signal_override = bool(anchor_mismatch and credential_language)

    # Section 7: evidence consistency (do sender, wording, links and page share one intent?)
    # and thread / cross-email analysis. Bounded additive adjustment, like the rule above.
    display_name, from_address = parseaddr(str(message.get("From", "")))
    additional = analyze_additional_features(
        {
            "from_display": display_name, "from_address": from_address,
            "reply_to": parseaddr(str(message.get("Reply-To", "")))[1],
            "subject": subject, "body": body,
            "urls": [u.get("normalized_url") or u.get("original_url") for u in urls],
            "websites": website_pages,
        },
        raw_email, related_emails,
    )
    adjustments = {}
    if strong_signal_override:
        adjustments["link_mismatch_with_credential_request"] = 0.15
    if additional["risk_boost"]:
        adjustments["evidence_consistency_and_thread"] = additional["risk_boost"]
    # Bounded evidence rules (brand impersonation, identity mismatch, link obfuscation, ...).
    indicators = risk_indicators(
        subject + "\n" + body, urls,
        (components.get("sender_header") or {}).get("details"),
        (components.get("temporary_email") or {}).get("details"),
        cfg=cfg.get("risk_indicators"), from_display=display_name,
    )
    if indicators["total"]:
        adjustments["risk_indicators"] = indicators["total"]
    if fusion["score"] is not None and adjustments:
        fusion["score"] = round(min(1.0, fusion["score"] + sum(adjustments.values())), 8)

    # Human Review gate, then the normal Safe / Suspicious / Phishy thresholds.
    min_cov = cfg.get("minimum_evidence_coverage", 0.60)
    min_comp = cfg.get("minimum_eligible_components", 4)
    consistency_status = additional["evidence_consistency"]["status"]
    review_reasons = human_review_reasons(
        fusion["evidence_coverage"], len(fusion["eligible_components"]), consistency_status,
        minimum_evidence_coverage=min_cov, minimum_components=min_comp,
    )
    fusion["classification"] = classify(
        fusion["score"], fusion["evidence_coverage"], min_cov, cfg["thresholds"],
        eligible_count=len(fusion["eligible_components"]), minimum_components=min_comp,
        consistency_status=consistency_status,
    )
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
        "verdict": VERDICT_LABELS[fusion["classification"]],
        "components": components,
        "additional_features": additional,
        "score_adjustments": adjustments,
        "risk_indicators": indicators,
        "human_review_reasons": review_reasons,
        "evidence_coverage": fusion["evidence_coverage"],
        "eligible_components": fusion["eligible_components"],
        "excluded_components": fusion["excluded_components"],
        "strong_signal_override": {
            "applied": strong_signal_override,
            "reason": "A visible link domain mismatched its destination and credential or payment solicitation language was present." if strong_signal_override else None,
        },
        "effective_weights": fusion["effective_weights"],
        "extracted_urls": [
            item.get("original_url") for item in urls
        ],
        "limitations": limitations,
        "warnings": list(dict.fromkeys(warnings)),
    }


DATASET_RAW_KEYS = ("raw_email", "raw", "email", "message", "eml")


def _rfc822_from_row(row):
    """Build a minimal RFC 5322 message from tabular columns."""
    def pick(*names):
        for n in names:
            for k in row:
                if str(k).lower() == n and row[k] not in (None, ""):
                    return str(row[k])
        return ""
    lines = []
    for header, names in (("From", ("from", "sender")), ("To", ("to", "recipient")),
                          ("Reply-To", ("reply_to", "reply-to")), ("Subject", ("subject",)),
                          ("Date", ("date",)), ("Message-ID", ("message_id", "message-id")),
                          ("In-Reply-To", ("in_reply_to", "in-reply-to")), ("References", ("references",))):
        value = pick(*names).replace("\r", " ").replace("\n", " ")
        if value:
            lines.append(f"{header}: {value}")
    body = pick("body", "text", "content", "message_body")
    return "\n".join(lines) + "\n\n" + body


def load_email_dataset(path, limit=500):
    """Load an email dataset: a folder of .eml/.txt files, .mbox, .csv, .json or .jsonl.
    Returns a list of {"id", "raw", "label"} in file order."""
    import csv
    import mailbox

    path = Path(path)
    rows = []
    if path.is_dir():
        for f in sorted(list(path.glob("*.eml")) + list(path.glob("*.txt")))[:limit]:
            rows.append({"id": f.name, "raw": f.read_text(encoding="utf-8", errors="replace"), "label": None})
        return rows
    suffix = path.suffix.lower()
    if suffix == ".mbox":
        for i, msg in enumerate(mailbox.mbox(str(path))):
            if i >= limit:
                break
            rows.append({"id": msg.get("Message-ID") or f"mbox-{i + 1}", "raw": msg.as_string(), "label": None})
        return rows
    if suffix in {".eml"}:
        return [{"id": path.name, "raw": path.read_text(encoding="utf-8", errors="replace"), "label": None}]
    records = []
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if suffix == ".csv":
        csv.field_size_limit(10_000_000)
        records = list(csv.DictReader(text.splitlines(True)))
    elif suffix == ".jsonl":
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    elif suffix == ".json":
        data = json.loads(text)
        records = data if isinstance(data, list) else data.get("emails", [])
    else:
        raise ValueError(f"Unsupported dataset type: {suffix or 'unknown'} (use a folder of .eml, .mbox, .csv, .json or .jsonl)")
    for i, row in enumerate(records[:limit]):
        if isinstance(row, str):
            row = {"raw_email": row}
        raw = next((str(row[k]) for k in row if str(k).lower() in DATASET_RAW_KEYS and row[k]), None)
        rows.append({
            "id": str(row.get("id") or row.get("message_id") or f"row-{i + 1}"),
            "raw": raw or _rfc822_from_row(row),
            "label": row.get("label"),
        })
    return rows


def _thread_groups(rows):
    """Group emails into threads by Message-ID/In-Reply-To/References or normalised subject."""
    from consistency_analysis import parse_message
    parsed = [parse_message(r["raw"]) for r in rows]
    parent = list(range(len(rows)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner = {}
    keys = []
    for i, p in enumerate(parsed):
        ks = {("id", p["message_id"])} if p["message_id"] else set()
        ks |= {("id", x) for x in p["in_reply_to"] + p["references"]}
        if p["subject_norm"]:
            ks.add(("subject", p["subject_norm"]))
        keys.append(ks)
        for k in ks:
            if k in owner:
                parent[find(i)] = find(owner[k])
            else:
                owner[k] = i
    groups = {}
    for i in range(len(rows)):
        groups.setdefault(find(i), []).append(i)
    return groups


_EMAIL_SEPARATOR_RE = re.compile(r"^[ \t]*={5,}[ \t]*$", re.M)


def split_pasted_emails(text):
    """Split pasted text holding several emails separated by a line of 5+ '=' characters."""
    return [part.strip("\r\n") for part in _EMAIL_SEPARATOR_RE.split(text or "") if part.strip()]


def mbox_to_raw_emails(data: bytes):
    """Return each message of an mbox (given as bytes) as raw text."""
    import mailbox
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "thread.mbox"
        path.write_bytes(data)
        return [m.as_string() for m in mailbox.mbox(str(path))]


def prepare_thread(raws):
    """Describe and order the emails of a thread. Sorted oldest to newest by Date header when
    every message has a usable Date; otherwise the given order is kept.
    Returns a list of {"raw", "from", "subject", "date"} dicts."""
    from datetime import timezone
    from email.utils import parsedate_to_datetime
    items = []
    for raw in raws:
        msg = Parser(policy=policy.default).parsestr(raw, headersonly=True)
        try:
            when = parsedate_to_datetime(str(msg.get("Date", "")))
            when = when.replace(tzinfo=timezone.utc) if when.tzinfo is None else when.astimezone(timezone.utc)
        except Exception:
            when = None
        items.append({"raw": raw, "from": str(msg.get("From", "")) or "(no From)",
                      "subject": str(msg.get("Subject", "")) or "(no subject)", "date": when})
    if items and all(i["date"] for i in items):
        items.sort(key=lambda i: i["date"])
    return items


def analyze_dataset(path_or_rows, *, config=None, word_pool_model=None, limit=500,
                    website_retrieval_enabled=None, include_full=False, max_related=5, progress=None):
    """Assess every email in a dataset. Emails that belong to the same thread are analysed
    with their earlier thread members as related_emails (cross-email analysis)."""
    rows = load_email_dataset(path_or_rows, limit) if not isinstance(path_or_rows, list) else path_or_rows[:limit]
    cfg = _load_config(config)
    model = word_pool_model
    if model is None:
        model = WordPoolModel.load(ROOT / "phase 1" / "models" / "word_pool" / "model.joblib",
                                   expected_sha256=WORD_POOL_MODEL_SHA256)
    groups = _thread_groups(rows)
    member_of = {i: members for members in groups.values() for i in members}
    results, counts = [], {v: 0 for v in VERDICTS}
    counts["error"] = 0
    for i, row in enumerate(rows):
        if progress:
            progress(i, len(rows))
        related = [rows[j]["raw"] for j in member_of[i] if j < i][-max_related:]
        try:
            res = analyze_email(row["raw"], config=config, word_pool_model=model,
                                website_retrieval_enabled=website_retrieval_enabled, related_emails=related)
        except Exception as exc:
            counts["error"] += 1
            results.append({"id": row["id"], "label": row.get("label"), "verdict": "Error", "error": f"{type(exc).__name__}: {exc}"})
            continue
        counts[res["classification"]] += 1
        item = {
            "id": row["id"], "label": row.get("label"), "verdict": res["verdict"], "classification": res["classification"],
            "score": res["score"], "evidence_coverage": res["evidence_coverage"],
            "component_scores": {k: v["score"] for k, v in res["components"].items()},
            "consistency_risk": res["additional_features"]["additional_risk"],
            "thread_size": len(related) + 1,
        }
        if include_full:
            item["assessment"] = res
        results.append(item)
    if progress:
        progress(len(rows), len(rows))
    return {"total": len(rows), "summary": counts, "thread_count": len(groups), "results": results}


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
    parser.add_argument("--dataset", help="Folder of .eml files, or a .mbox/.csv/.json/.jsonl email dataset")
    parser.add_argument("--limit", type=int, default=500, help="Maximum emails to read from a dataset")
    parser.add_argument("--related", nargs="*", default=[], help="Earlier .eml files from the same thread (cross-email analysis)")
    parser.add_argument("--fetch-websites", action="store_true", help="Opt in to bounded page retrieval and RDAP lookups")
    args = parser.parse_args(argv)
    if args.dataset:
        out = analyze_dataset(args.dataset, config=args.config, limit=args.limit,
                              website_retrieval_enabled=True if args.fetch_websites else None)
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return 0
    related = [Path(p).read_text(encoding="utf-8", errors="replace") for p in args.related]
    raw = (
        Path(args.email).read_text(encoding="utf-8", errors="replace")
        if args.email
        else sys.stdin.read()
    )
    print(
        json.dumps(
            analyze_email(raw, config=args.config, related_emails=related,
                          website_retrieval_enabled=True if args.fetch_websites else None),
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
