from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from phishing_engine import WordPoolModel, analyze_email

COMPONENT_LABELS = {
    "word_pool": "Email wording",
    "sender_header": "Sender and email details",
    "temporary_email": "Sender email provider",
    "url_analysis": "Links in the email",
    "website_analysis": "Website page content",
}
COMPONENT_DESCRIPTIONS = {
    "word_pool": "Checks the message wording for patterns often found in phishing emails.",
    "sender_header": "Checks the sender address and message headers for unusual details.",
    "temporary_email": "Checks whether the sender uses a disposable or suspicious email provider.",
    "url_analysis": "Checks link structure and possible brand-name lookalikes.",
    "website_analysis": "Checks fetched page text, forms, and layout. Page scripts are not run.",
}
STATUS_LABELS = {
    "available": "Checked",
    "not_applicable": "Not needed",
    "unavailable": "Could not check",
    "error": "Check failed",
}


def _friendly_evidence(item):
    """Turn internal evidence records into short phrases for app users."""
    if isinstance(item, str):
        return item.replace("_", " ").strip().capitalize()
    if not isinstance(item, dict):
        return None

    if item.get("phrase"):
        return f'Phrase found: “{item["phrase"]}”'
    if item.get("page_title"):
        return f'Page title: {item["page_title"]}'
    if item.get("brand"):
        domain = item.get("domain") or item.get("registered_domain")
        suffix = f" ({domain})" if domain else ""
        return f'Possible brand-name similarity: {item["brand"]}{suffix}'
    if item.get("description"):
        return str(item["description"])
    if item.get("finding"):
        return str(item["finding"])
    if item.get("reason"):
        return str(item["reason"])
    return None


def _evidence_items(component):
    evidence = component.get("evidence")
    if evidence is None:
        details = component.get("details") or {}
        evidence = details.get("evidence") or details.get("matched_sources") or []
    if isinstance(evidence, (str, dict)):
        evidence = [evidence]
    return evidence if isinstance(evidence, list) else []


st.set_page_config(page_title="VYOM | Phishing Email Analysis", page_icon=":material/shield:", layout="wide")

with st.sidebar:
    st.subheader("Analysis flow")
    st.image(
        str(ROOT / "flowchart.png"),
        caption="Project research flowchart",
        width="stretch",
        alt="Research flowchart for the six-phase phishing email analysis pipeline",
    )

mode = st.segmented_control("Email input", ["Paste email", "Upload .eml or .txt"], default="Paste email")
raw_email = ""
if mode == "Paste email":
    raw_email = st.text_area(
        "Paste the complete email, including headers when available",
        height=260,
        placeholder="From: sender@example.com\nSubject: Example\nDate: ...\n\nEmail text…",
    )
else:
    uploaded = st.file_uploader("Choose an email file", type=["eml", "txt"], max_upload_size=1)
    if uploaded is not None:
        raw_email = uploaded.getvalue().decode("utf-8", errors="replace")
        st.caption(f"Loaded {uploaded.name} ({uploaded.size:,} bytes). Attachments are not extracted or opened.")

current_digest = hashlib.sha256(raw_email.encode("utf-8", errors="replace")).hexdigest() if raw_email else None
if st.session_state.get("assessment_digest") != current_digest:
    st.session_state.pop("assessment", None)
    st.session_state["assessment_digest"] = current_digest


@st.cache_resource
def load_word_pool_model():
    return WordPoolModel.load(ROOT / "phase 1" / "models" / "word_pool" / "model.joblib")


if st.button("Analyze email", type="primary", disabled=not raw_email.strip()):
    try:
        result = analyze_email(
            raw_email,
            config=ROOT / "configs" / "integrated.yaml",
            word_pool_model=load_word_pool_model(),
        )
        st.session_state["assessment"] = result
    except Exception as exc:
        st.error(f"Analysis could not be completed ({type(exc).__name__}). Check that the uploaded file is a readable email.")

result = st.session_state.get("assessment")
if result:
    st.divider()
    left, mid, right = st.columns(3)
    label = result["classification"].replace("_", " ").title()
    left.metric("Classification", label)
    mid.metric("Risk score", f"{result['score']:.3f}" if result["score"] is not None else "Insufficient evidence")
    right.metric("Evidence coverage", f"{result['evidence_coverage']:.0%}")

    if result["classification"] == "high_risk":
        st.error("High risk signals were detected. Verify the message through a separate trusted channel.")
    elif result["classification"] == "suspicious":
        st.warning("Suspicious signals were detected. Review the findings before acting.")
    elif result["classification"] == "insufficient_evidence":
        st.warning("There was not enough information to assess this message.")

    st.subheader("Assessment by area")
    st.caption("Each bar is a model risk signal, not a probability that the message is phishing.")
    for name, component in result["components"].items():
        title = COMPONENT_LABELS.get(name, name.replace("_", " ").title())
        status = STATUS_LABELS.get(component["status"], component["status"].replace("_", " ").title())
        score = component.get("score")
        with st.expander(f"{title} · {status}", expanded=component["status"] in {"error", "unavailable"}):
            st.write(COMPONENT_DESCRIPTIONS.get(name, "This area contributes one set of signals to the assessment."))

            if score is not None:
                st.progress(float(score))
                st.caption(f"Risk signal: {float(score) * 100:.0f} / 100")
            else:
                st.caption("No score was produced for this area.")

            if component.get("message"):
                st.info(component["message"])

            details = component.get("details") or {}
            if name == "website_analysis":
                fetched = details.get("fetched_count", 0)
                total = details.get("url_count", 0)
                if total:
                    st.write(f"Website pages fetched: {fetched} of {total}")
                for website in details.get("websites", []):
                    retrieval = website.get("retrieval") or {}
                    title_text = retrieval.get("page_title")
                    if retrieval.get("fetched") and title_text:
                        st.write(f"Page checked: {title_text}")
                    elif retrieval.get("reason"):
                        st.write(f"Page could not be checked: {retrieval['reason']}")

            findings = []
            for item in _evidence_items(component):
                text = _friendly_evidence(item)
                if text and text not in findings:
                    findings.append(text)
            if findings:
                st.markdown("**What was noticed**")
                for finding in findings[:8]:
                    st.markdown(f"- {finding}")
            elif component["status"] == "available":
                st.write("No notable indicators were found in the available information.")

    if result["extracted_urls"]:
        st.markdown("**Links found in the email**")
        for url in result["extracted_urls"]:
            st.code(url, language=None)

    st.download_button(
        "Download assessment JSON",
        json.dumps(result, indent=2, ensure_ascii=False),
        file_name="email_assessment.json",
        mime="application/json",
    )
