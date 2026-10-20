"""Dataset helpers that preserve provenance and avoid fabricating absent headers."""
from __future__ import annotations
import csv, hashlib, json
from pathlib import Path
from typing import Any

def sha256_text(text: str) -> str: return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

def load_csv_records(path: str | Path, raw_email_column: str, label_column: str | None = None,
                     source_dataset: str | None = None) -> list[dict[str, Any]]:
    records = []
    with Path(path).open(newline="", encoding="utf-8", errors="replace") as f:
        for i, row in enumerate(csv.DictReader(f), 1):
            raw = row.get(raw_email_column, "") or ""
            records.append({"raw_email": raw, "raw_sha256": sha256_text(raw), "email_label": row.get(label_column) if label_column else None,
                            "source_type": "real", "source_dataset": source_dataset or Path(path).stem,
                            "source_record_id": str(i), "available_headers": [], "header_evidence_status": "not_parsed"})
    return records

def deduplicate(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    seen = set(); unique = []
    for row in records:
        digest = row.get("raw_sha256") or sha256_text(str(row.get("raw_email", "")))
        if digest in seen: continue
        seen.add(digest); unique.append(row)
    return unique, len(records)-len(unique)
