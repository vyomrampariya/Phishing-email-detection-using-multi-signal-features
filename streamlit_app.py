from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from phishing_engine import WordPoolModel, analyze_email

st.set_page_config(page_title="VYOM | Phishing Email Analysis", page_icon=":material/shield:", layout="wide")
st.title("Email phishing assessment", anchor=False)
st.caption("One assessment across email text, sender and headers, sender domain, URLs, and static website signals.")


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
        st.warning("Suspicious signals were detected. Review the component evidence before acting.")
    elif result["classification"] == "insufficient_evidence":
        st.warning("There was not enough successfully evaluated evidence to score this email.")
    else:
        
    st.subheader("Component results")
    for name, component in result["components"].items():
        status = component["status"].replace("_", " ").title()
        score = f"{component['score']:.3f}" if component["score"] is not None else "—"
        with st.expander(f"{name.replace('_', ' ').title()} · {status} · {score}", expanded=component["status"] in {"error", "unavailable"}):
            if component.get("message"):
                st.write(component["message"])
            if component.get("evidence"):
                st.markdown("**Evidence**")
                st.json(component["evidence"])
            details = component.get("details") or {}
            if details:
                st.markdown("**Analysis details**")
                st.json(details)
    if result["extracted_urls"]:
        st.markdown("**URLs found**")
        for url in result["extracted_urls"]:
            st.code(url, language=None)
    
    st.download_button(
        "Download assessment JSON",
        json.dumps(result, indent=2, ensure_ascii=False),
        file_name="email_assessment.json",
        mime="application/json",
    )
