from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import tempfile

from phishing_engine import WORD_POOL_MODEL_SHA256, WordPoolModel, analyze_dataset, analyze_email, prepare_thread

COMPONENT_LABELS = {
    "word_pool": "Email wording",
    "sender_header": "Sender and email details",
    "temporary_email": "Sender email provider",
    "url_analysis": "Links in the email",
    "website_analysis": "Website intelligence",
    "attachment_analysis": "Attachments (metadata only)",
}
COMPONENT_DESCRIPTIONS = {
    "word_pool": "Checks the message wording for patterns often found in phishing emails.",
    "sender_header": "Checks the sender address and message headers for unusual details.",
    "temporary_email": "Checks whether the sender uses a disposable or suspicious email provider.",
    "url_analysis": "Checks link structure and possible brand-name lookalikes.",
    "website_analysis": "Domain age/reputation, brand look-alikes, urgent wording and login/payment forms. Linked pages are always fetched (bounded, public addresses only) for static analysis; scripts are never run.",
    "attachment_analysis": "Checks attachment filenames, declared types and sizes. File contents are never opened.",
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


@st.cache_resource
def load_word_pool_model():
    return WordPoolModel.load(
        ROOT / "phase 1" / "models" / "word_pool" / "model.joblib",
        expected_sha256=WORD_POOL_MODEL_SHA256,
    )

load_word_pool_model_cached = load_word_pool_model


st.set_page_config(page_title="VYOM | Phishing Email Analysis", page_icon=":material/shield:", layout="wide")

mode = st.segmented_control(
    "Email input",
    ["Paste email", "Upload .eml or .txt", "Upload email dataset"],
    default="Paste email",
)
raw_email = ""
related_raw = []
if mode == "Paste email":
    raw_email = st.text_area(
        "Paste the complete email, including headers when available",
        height=260,
        placeholder="From: sender@example.com\nSubject: Example\nDate: ...\n\nEmail text…",
    )
elif mode == "Upload email dataset":
    dataset_file = st.file_uploader("Choose a dataset (.csv, .jsonl, .json or .mbox)", type=["csv", "jsonl", "json", "mbox"], max_upload_size=20)
    dataset_limit = st.number_input("Maximum emails to analyze", min_value=1, max_value=500, value=100)
    if dataset_file is None:
        st.session_state.pop("dataset_result", None)
    elif st.button("Analyze dataset", type="primary"):
        st.session_state.pop("dataset_result", None)
        bar = st.progress(0.0, text="Starting analysis\u2026")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ("dataset" + Path(dataset_file.name).suffix.lower())
            path.write_bytes(dataset_file.getvalue())
            try:
                st.session_state["dataset_result"] = analyze_dataset(
                    path, config=ROOT / "configs" / "integrated.yaml", word_pool_model=load_word_pool_model_cached(),
                    limit=int(dataset_limit),
                    website_retrieval_enabled=True,
                    progress=lambda done, total: bar.progress(done / max(total, 1), text=f"Analyzed {done} of {total} emails"),
                )
            except Exception as exc:
                st.error(f"Dataset could not be analyzed ({type(exc).__name__}: {exc}).")
        bar.empty()
    batch = st.session_state.get("dataset_result")
    if batch:
        import pandas as pd
        st.divider()
        if not batch["total"]:
            st.warning("No emails were found in the file. Check the column names listed above.")
        if batch["summary"].get("error"):
            st.error(f"{batch['summary']['error']} email(s) could not be analyzed; see the error column.")
        cols = st.columns(5)
        cols[0].metric("Emails", batch["total"])
        for col, key, name in zip(cols[1:], ["safe", "suspicious", "phishy", "human_review"], ["Safe", "Suspicious", "Phishy", "Human Review"]):
            col.metric(name, batch["summary"].get(key, 0))
        table = pd.DataFrame([
            {"id": r["id"], "verdict": r["verdict"], "score": r.get("score"), "coverage": r.get("evidence_coverage"),
             "consistency risk": r.get("consistency_risk"), "thread size": r.get("thread_size"), "label": r.get("label"),
             "error": r.get("error")}
            for r in batch["results"]
        ])
        st.dataframe(table, width="stretch")
        st.download_button("Download results CSV", table.to_csv(index=False), file_name="dataset_assessment.csv", mime="text/csv")
        st.download_button("Download results JSON", json.dumps(batch, indent=2, ensure_ascii=False, default=str), file_name="dataset_assessment.json", mime="application/json")
    st.stop()
else:
    st.caption("Upload one email to assess it on its own, or upload several emails from the same conversation "
               "(2 or more): the newest one is assessed and compared with the earlier ones: sender changes, look-alike domains, reply-chain breaks, shifting links and intent.")
    uploaded_files = st.file_uploader("Choose email files (.eml or .txt)", type=["eml", "txt"],
                                      accept_multiple_files=True, max_upload_size=1, key="email_files")
    raws = [f.getvalue().decode("utf-8", errors="replace") for f in uploaded_files or []]
    if len(raws) == 1:
        raw_email = raws[0]
        st.caption(f"Loaded {uploaded_files[0].name} ({uploaded_files[0].size:,} bytes). Attachments are not extracted or opened. "
                   "Upload more emails from the same conversation to enable thread analysis.")
    elif len(raws) >= 2:
        thread = prepare_thread(raws)
        st.markdown(f"**{len(thread)} emails found** (oldest first)")
        st.dataframe(
            [{"#": n + 1, "date": t["date"].strftime("%Y-%m-%d %H:%M") if t["date"] else "n/a",
              "from": t["from"], "subject": t["subject"]} for n, t in enumerate(thread)],
            width="stretch", hide_index=True,
        )
        raw_email = thread[-1]["raw"]
        related_raw = [t["raw"] for t in thread[:-1]]

current_digest = (
    hashlib.sha256("\x00".join([raw_email, *related_raw]).encode("utf-8", errors="replace")).hexdigest()
    if raw_email else None
)
if st.session_state.get("assessment_digest") != current_digest:
    st.session_state.pop("assessment", None)
    st.session_state["assessment_digest"] = current_digest




if raw_email.strip() and st.button("Analyze email", type="primary"):
    try:
        result = analyze_email(
            raw_email,
            config=ROOT / "configs" / "integrated.yaml",
            word_pool_model=load_word_pool_model(),
            related_emails=related_raw,
        )
        st.session_state["assessment"] = result
    except Exception as exc:
        st.error(f"Analysis could not be completed ({type(exc).__name__}). Check that the uploaded file is a readable email.")

result = st.session_state.get("assessment")
if result:
    st.divider()
    left, mid, right = st.columns(3)
    left.metric("Verdict", result["verdict"])
    mid.metric("Risk score", f"{result['score']:.3f}" if result["score"] is not None else "Insufficient evidence")
    right.metric("Evidence coverage", f"{result['evidence_coverage']:.0%}")

    if result["classification"] == "phishy":
        st.error("Phishy (high risk, score 0.60–1.00). Verify the message through a separate trusted channel.")
    elif result["classification"] == "suspicious":
        st.warning("Suspicious (medium risk, score 0.30–0.60). Review the findings before acting.")
    elif result["classification"] == "human_review":
        st.warning("Human Review: there was not enough evidence to place this message in Safe, Suspicious or Phishy.")
        for reason in result.get("human_review_reasons") or []:
            st.markdown(f"- {reason[:1].upper() + reason[1:]}")
    else:
        st.success("Safe (low risk, score below 0.30). Scores are heuristics, not guarantees.")
    fired = (result.get("risk_indicators") or {}).get("fired") or {}
    if fired:
        st.caption("Evidence rules that fired: " + ", ".join(f"{k.replace('_', ' ')} (+{v['weight']:.2f})" for k, v in fired.items()) + f". Combined rule boost is capped at {(result['risk_indicators'])['total']:.2f}.")
    if result.get("score_adjustments"):
        st.caption("Bounded score adjustments applied: " + ", ".join(f"{k.replace('_', ' ')} +{v:.2f}" for k, v in result["score_adjustments"].items()))

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
                        st.write(f"Page content not retrieved: {retrieval['reason']}")
                    analysis = website.get("analysis") or {}
                    signals = analysis.get("signals") or {}
                    if signals:
                        st.caption("Domain {} · Brand {} · Language {} · Credentials {}".format(*[
                            "n/a" if signals.get(k) is None else f"{signals[k]:.2f}" for k in ("domain", "brand", "language", "credentials")]))
                    reg = (analysis.get("domain_findings") or {}).get("registration_age_days")
                    if reg is not None:
                        st.write(f"Domain registered {int(reg)} days ago (RDAP)")
                    for key, label in (("screenshot", "Screenshot render"), ("search_context", "Search-result context")):
                        st.caption(f"{label}: {(analysis.get(key) or {}).get('status', 'not_collected').replace('_', ' ')}")

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

    extra = result.get("additional_features") or {}
    if extra:
        st.subheader("Additional checks")
        cons, thread = extra["evidence_consistency"], extra["thread_analysis"]
        with st.expander(f"Evidence consistency · reliability {extra['evidence_reliability']:.0%}"):
            st.write("Checks that the sender, wording, links and website all describe the same intent and organisation.")
            for src, intents in cons["intents_by_source"].items():
                st.markdown(f"- **{src.title()}**: {', '.join(intents) if intents else 'no clear topic'}")
            if cons["score"] is None:
                st.info("Not enough independent evidence to judge consistency.")
            else:
                st.progress(float(cons["score"]))
                for f in cons["findings"]:
                    st.markdown(f"- {f['finding']}")
                if cons["consistent_intent"]:
                    st.write("All available evidence points to the same intent.")
        with st.expander(f"Thread and cross-email analysis · {thread['status'].replace('_', ' ')}"):
            if thread["status"] == "not_applicable":
                st.info(thread.get("message"))
            else:
                st.caption(f"Related emails compared: {thread['emails_compared']} (linked to this thread: {thread.get('linked_emails', 0)})")
                st.progress(float(thread["score"]))
                for f in thread["findings"]:
                    st.markdown(f"- {f['finding']}")

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
