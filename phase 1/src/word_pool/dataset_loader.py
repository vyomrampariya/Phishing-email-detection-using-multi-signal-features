"""Schema-tolerant CSV ingestion with provenance and duplicate grouping."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable

import pandas as pd

from .preprocessing import prepare_email


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
    body_col = _column(cols, ("body", "email_body", "message", "text", "text_combined", "email", "content"))
    label_col = label_column or _column(cols, ("label", "class", "target", "category", "spam"))
    if body_col is None:
        raise ValueError(f"{path.name}: no recognizable email body/text column")
    if label_col is None:
        raise ValueError(f"{path.name}: no label column; unlabeled records cannot train the classifier")
    mapping = {str(k).strip().casefold(): int(v) for k, v in (label_mapping or {"0": 0, "1": 1}).items()}
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


def combine_datasets(paths: Iterable[str | Path], *, exclude: Iterable[str] = (), include_original: bool = False) -> pd.DataFrame:
    excluded = {str(x).casefold() for x in exclude}
    frames = [load_email_csv(p, include_original=include_original) for p in paths if Path(p).name.casefold() not in excluded and Path(p).stem.casefold() not in excluded]
    if not frames:
        return pd.DataFrame(columns=["email_id", "source_dataset", "subject", "body", "text", "label", "label_source", "duplicate_group"])
    result = pd.concat(frames, ignore_index=True)
    # Exact normalized duplicates retain first provenance record and are grouped before split.
    return result.loc[~result.duplicated("duplicate_group", keep="first")].reset_index(drop=True)
