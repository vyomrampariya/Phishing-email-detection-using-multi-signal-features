"""Schema-tolerant CSV ingestion with provenance and duplicate grouping."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable

import pandas as pd

from .preprocessing import prepare_email


# Text labels used by common public corpora, so more varied sources can be added without editing code.
DEFAULT_LABEL_MAPPING = {
    "0": 0, "1": 1,
    "ham": 0, "legitimate": 0, "legit": 0, "safe": 0, "safe email": 0, "not spam": 0, "benign": 0, "normal": 0,
    "spam": 1, "phishing": 1, "phish": 1, "phishing email": 1, "malicious": 1, "fraud": 1, "scam": 1,
}


def _column(columns: Iterable[str], candidates: tuple[str, ...]) -> str | None:
    lookup = {str(c).strip().casefold(): c for c in columns}
    return next((lookup[c] for c in candidates if c in lookup), None)


def load_email_csv(path: str | Path, *, source_dataset: str | None = None,
                   label_mapping: dict | None = None, label_column: str | None = None,
                   include_original: bool = True) -> pd.DataFrame:
    path = Path(path)
    try:
        frame = pd.read_csv(path, encoding="utf-8-sig", encoding_errors="replace", on_bad_lines="skip", low_memory=False)
    except Exception as exc:
        raise ValueError(f"Could not load dataset {path}: {exc}") from exc
    cols = list(frame.columns)
    subject_col = _column(cols, ("subject", "email_subject"))
    body_col = _column(cols, ("body", "email_body", "body_text", "message", "text", "text_combined", "email", "email text", "email_text", "content", "mail"))
    label_col = label_column or _column(cols, ("label", "class", "target", "category", "spam", "email type", "email_type", "type"))
    if body_col is None:
        raise ValueError(f"{path.name}: no recognizable email body/text column")
    if label_col is None:
        raise ValueError(f"{path.name}: no label column; unlabeled records cannot train the classifier")
    mapping = {str(k).strip().casefold(): int(v) for k, v in (label_mapping or DEFAULT_LABEL_MAPPING).items()}
    records = []
    for values in frame.itertuples(index=True, name=None):
        ix, *row_values = values
        row = dict(zip(cols, row_values))
        raw_label = str(row[label_col]).strip().casefold()
        if raw_label not in mapping:
            continue
        subject = row[subject_col] if subject_col else ""
        body = row[body_col]
        prepared = prepare_email(subject, body)
        if not prepared["text"]:
            continue
        digest = hashlib.sha256(re.sub(r"\s+", " ", prepared["text"]).encode("utf-8")).hexdigest()
        record = {"email_id": f"{path.stem}:{ix}", "source_dataset": source_dataset or path.stem,
                  "text": prepared["text"], "label": mapping[raw_label], "label_source": f"{path.name}:{label_col}",
                  "duplicate_group": digest}
        if include_original:
            record.update({"subject": prepared["subject"], "body": prepared["body"]})
        records.append(record)
    columns = ["email_id", "source_dataset"] + (["subject", "body"] if include_original else []) + ["text", "label", "label_source", "duplicate_group"]
    return pd.DataFrame.from_records(records, columns=columns)


def balance_sources(frame: pd.DataFrame, max_per_source_label: int | None = None, seed: int = 42) -> pd.DataFrame:
    """Cap every (source, label) group so no single corpus dominates training.

    Sources smaller than the cap are kept whole; larger ones are sampled deterministically.
    """
    if not max_per_source_label or frame.empty:
        return frame
    parts = [g.sample(n=min(len(g), max_per_source_label), random_state=seed)
             for _, g in frame.groupby(["source_dataset", "label"], sort=True)]
    return pd.concat(parts, ignore_index=True)


def combine_datasets(paths: Iterable[str | Path], *, exclude: Iterable[str] = (), include_original: bool = False) -> pd.DataFrame:
    excluded = {str(x).casefold() for x in exclude}
    frames = [load_email_csv(p, include_original=include_original) for p in paths if Path(p).name.casefold() not in excluded and Path(p).stem.casefold() not in excluded]
    if not frames:
        return pd.DataFrame(columns=["email_id", "source_dataset", "subject", "body", "text", "label", "label_source", "duplicate_group"])
    result = pd.concat(frames, ignore_index=True)
    # Exact normalized duplicates retain first provenance record and are grouped before split.
    return result.loc[~result.duplicated("duplicate_group", keep="first")].reset_index(drop=True)
