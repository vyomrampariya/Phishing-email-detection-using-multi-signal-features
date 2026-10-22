# VYOM Phishing Email Assessment — GitHub and Streamlit bundle

This folder is a self-contained deployment copy of the integrated research app. It includes the six analysis phases (text, sender/header, temporary email, URL, website intelligence, additional features), the trained Phase 1 model, Phase 3's local disposable-domain data, the integrated scoring configuration, and the project's flowchart files (`flowchart.png`, `flowchart.svg`; no longer shown in the app sidebar). The original research papers and training datasets are not required to run inference and are not included.

## Run locally

Use Python 3.12, then from this folder:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

On Linux or macOS, run from the project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Upload to GitHub and deploy

1. Create a GitHub repository and upload all the contents of this folder to the repository root. Include both flowchart files and the `phase 1` through `phase 6` runtime folders.
2. In Streamlit Community Cloud, create an app and select the repository, branch, and entrypoint file `streamlit_app.py`.
3. In Advanced settings, select Python 3.12, then deploy. The included `requirements.txt` installs the required packages.

## Privacy and safe handling

The app runs analysis on the host where Streamlit is running. Anyone who can access a public deployment can submit email content for analysis. Do not upload confidential email to a public hosted instance unless you are authorized to process it there. The app does not save submitted messages to files or print them to logs. Attachments are assessed from filename, declared MIME type, and size only; their contents are never opened. Linked pages are **always fetched** for static HTML analysis (bounded requests to public URLs only, no scripts or forms). Set `website_retrieval.enabled: false` in `configs/integrated.yaml` or `PHISHING_WEBSITE_RETRIEVAL=0` on the host to switch this off for a deployment. The fetcher does not execute scripts or submit forms. When retrieval is enabled, the remote site can observe the hosting server's request.

## Scoring notes

Only successfully evaluated components contribute to the final adaptive weighted score; `not_applicable`, `unavailable`, and `error` components are excluded and the remaining weights are renormalized. The default weights are wording 0.25, sender/header 0.15, sender provider 0.10, URLs 0.20, website 0.20, and attachment metadata 0.10. Classification requires at least 0.30 of the configured evidence weight; below that the verdict is **Human Review**.

**Verdicts:** Safe `0.00 ≤ P < 0.30`, Suspicious `0.30 ≤ P < 0.60`, Phishy `0.60 ≤ P ≤ 1.00`, Human Review when evidence is insufficient.

**Bounded adjustments** (they raise the score; they never set a verdict directly): a mismatched visible link plus credential solicitation adds +0.15; Section 7 adds up to +0.12 (`0.12 × additional_risk`).

**Section 7 — additional features** (`phase 6/`): *evidence consistency* compares the intent of the sender, wording, links and fetched page (a bank sender with a car-dealership site is flagged; brand named but no sender/link domain belongs to it; too many unrelated domains), and reports an evidence-reliability figure. *Thread / cross-email analysis* flags `Re:`/`Fwd:` subjects without thread headers, and, when earlier emails are supplied, sender-domain changes and look-alikes, reused display names, new Reply-To or link domains, and intent shifts toward credentials/payment.

**Section 6 — website intelligence:** `S_WEB = w1·S_domain + w2·S_brand + w3·S_lang + w4·S_cred` (0.30/0.25/0.20/0.25, renormalized over observed signals). Domain and brand signals (URL structure, look-alikes, offline lexical reputation) work offline. The app also queries RDAP for domain age and fetches static HTML for language, login/payment forms and a static look-alike-logo check. Screenshot rendering and search-result context are **hooks** (`screenshot_provider`, `search_provider` arguments to `analyze_email`) that report `not_collected` unless you supply a provider; no browser or search API is bundled.

**Input:** paste an email, upload one or more `.eml`/`.txt` files (several files are treated as a thread), or upload a dataset (`.csv`, `.json`, `.jsonl`, `.mbox`, or a folder of `.eml` via the CLI). Emails in the same dataset thread are analyzed with their earlier thread members.

```bash
python phishing_engine.py message.eml --related earlier1.eml earlier2.eml
python phishing_engine.py --dataset emails.csv --limit 200
```

Scores are heuristics, not calibrated phishing probabilities. No labeled benchmark corpus is bundled, so accuracy and calibration are not claimed. Sender authentication headers are treated as unverified claims.

The bundled disposable-provider file is a ~150-domain seed list, not a maintained or exhaustive source; update it from a vetted source before relying on it operationally. Stop-word removal and lemmatization run in the Word Pool pipeline: the shipped model was trained on exact n-grams, so lemmatized matches are added as a discounted supplement (the model file itself is unchanged). The Pattern Ratio `F` (phishing patterns detected / relevant patterns) is reported in the Word Pool details.

The bundled `joblib` model is a pickle artifact. The application verifies its pinned SHA-256 digest before loading it and refuses a changed file. Only use model artifacts from a trusted source.

The as-built flow is shown in `flowchart.svg` and `flowchart.md`.

## Verdicts and the Human Review gate

A message goes to **Human Review** (`classification: human_review`) when any one of these holds:

- `evidence_coverage < 0.60`
- fewer than 4 eligible components
- `evidence_consistency.status == "insufficient_evidence"`

Otherwise the thresholds apply: **Safe** below 0.30, **Suspicious** 0.30 to below 0.60, **Phishy** 0.60 and above. The reasons are listed in `human_review_reasons`. Both limits are set in `configs/integrated.yaml`.

Bounded evidence rules (`risk_indicators`: brand impersonation, From/Reply-To mismatch, link obfuscation, credential tokens in links, disposable sender, pressure language) add at most 0.45 to the weighted score. Their weights are in the same file. The expected verdicts for `tests/examples/eg1-7.eml` are checked in `tests/test_engine.py`.

Several emails from the same thread can be uploaded together (2 or more `.eml`/`.txt` files) in the **Upload .eml or .txt** input mode in the app (or passed with `--related` on the command line) for cross-email analysis.

## Training the Word Pool model on more diverse data

The Word Pool model (`phase 1`) can be retrained on a broader mix of corpora. Put additional labeled CSV files (one per source, unique file names) in one or more directories and run, from `phase 1/`:

```
PYTHONPATH=src python -m word_pool.train --data-dir datasets --data-dir more_datasets --balance-sources 20000 --cross-dataset all
```

- `--data-dir` can be repeated to combine several directories.
- `--balance-sources N` keeps at most N messages per source and label, so one large corpus cannot dominate.
- `--cross-dataset all` holds out each source in turn and reports how well the model generalizes to a source it never saw.
- Label columns such as `label`, `class`, `category` or `Email Type`, and text labels such as `spam`/`ham` or `Phishing Email`/`Safe Email`, are recognized automatically.

After retraining, update `WORD_POOL_MODEL_SHA256` in `phishing_engine.py` to the SHA-256 of the new `model.joblib`.
