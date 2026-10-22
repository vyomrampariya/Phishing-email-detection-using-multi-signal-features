# Implementation summary

## Fixed

- Restored the missing regular-expression import so URL extraction with links works.
- Matched top-level fusion weights to the flowchart: wording 0.25, sender/header 0.15, temporary sender 0.10, URL 0.20, website 0.20, attachment 0.10.
- Changed the link mismatch plus credential solicitation override from a high-risk floor to a bounded +0.15 boost and broadened account-verification language matching.
- Tightened URL and sender domain similarity checks to reduce broad brand-token and short-string matches.
- Restored equal 0.20 weights for all five Word Pool feature groups so collocation, rare-pattern, and CTA features participate; updated the model integrity digest.
- Added a 0.30 minimum evidence-coverage gate so one low-weight signal cannot alone produce a suspicious/high-risk classification.
- Corrected double-extension direction (`invoice.pdf.exe`), added HTML/HTM/LNK/JAR, ignored inline images, and used the highest attachment risk rather than diluting it with benign attachments.
- Added regression cases for URL parsing, fusion weights, attachments, and link override behavior.

## Remaining limits

- The shipped Word Pool pickle was trained on a corpus that is not included. Its learned TF-IDF and pattern artifacts cannot be safely retrained or de-biased without the source training data. The model remains uncalibrated; benign newsletter false positives and corpus artifacts need a properly sourced retraining and evaluation set.
- No labeled benchmark is included, so thresholds remain policy defaults rather than empirically calibrated thresholds. Scores are heuristics, not phishing probabilities.
- External threat intelligence/RDAP, dynamic JavaScript page rendering, attachment content scanning, and cryptographic SPF/DKIM/DMARC verification remain outside this bundle.

## Specification alignment update

- Verdict categories now follow the specification: Safe < 0.30, Suspicious 0.30–0.60, Phishy ≥ 0.60, Human Review for insufficient evidence (labels `safe`/`suspicious`/`phishy`/`human_review`).
- Added `phase 6` (Section 7): evidence consistency/intent check and thread/cross-email analysis, applied as a bounded boost of up to +0.12.
- Added dataset input (`analyze_dataset`, `--dataset`, Streamlit dataset mode) with thread grouping.
- Word Pool pipeline now runs stop-word handling and lemmatization (lemma-level matching supplements the trained n-grams) and reports Pattern Ratio F.
- From/Reply-To mismatch is a binary flag; an offline lexical domain-reputation heuristic fills the reputation term.
- Temporary-email analysis also checks the Reply-To address, uses RDAP domain age when lookups are enabled, and ships ~150 disposable domains.
- Website analysis follows `S_WEB = w1·S_domain + w2·S_brand + w3·S_lang + w4·S_cred`; domain/brand work offline, RDAP, language/credential forms and static logo matching run with opt-in retrieval.

## Still not bundled

- Screenshot rendering and search-result context (provider hooks only), threat-intelligence feeds, cryptographic SPF/DKIM/DMARC verification, and a labeled benchmark for calibration.
- Retraining the Word Pool model with stop-word/lemma preprocessing needs the original training corpus.
