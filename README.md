# VYOM Phishing Email Assessment — GitHub and Streamlit bundle

This folder is a self-contained deployment copy of the integrated research app. It includes the five existing analysis phases, the trained Phase 1 model, Phase 3's local disposable-domain data, the integrated scoring configuration, and the project's flowchart (`flowchart.png` and `flowchart.svg`). The original research papers and training datasets are not required to run inference and are not included.

## Run locally

Use Python 3.12, then from this folder:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Upload to GitHub and deploy

1. Create a GitHub repository and upload all the contents of this folder to the repository root. Include both flowchart files and the `phase 1` through `phase 5` runtime folders.
2. In Streamlit Community Cloud, create an app and select the repository, branch, and entrypoint file `streamlit_app.py`.
3. In Advanced settings, select Python 3.12, then deploy. The included `requirements.txt` installs the required packages.

## Privacy and safe handling

The app runs analysis on the host where Streamlit is running. Anyone who can access a public deployment can submit email content for analysis. Do not upload confidential email to a public hosted instance unless you are authorized to process it there. The app does not save submitted messages to files or print them to logs. It does not open attachments, visit suspicious URLs, execute website scripts, or submit forms. Website analysis is static and offline.

## Scoring notes

Only successfully evaluated components contribute to the final adaptive weighted score; `not_applicable`, `unavailable`, and `error` components are excluded. The final labels use configurable thresholds. Scores are research heuristics and are not calibrated phishing probabilities. The low-score label says “Low risk review,” not “safe.” Sender authentication headers are treated as unverified claims.

The original flowchart is available in both PNG and SVG formats in this folder.
