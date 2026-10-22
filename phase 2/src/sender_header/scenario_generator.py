"""Deterministic synthetic header scenarios; synthetic data is never represented as real mail."""
from __future__ import annotations
import itertools, json, random
from pathlib import Path

DIMENSIONS = {
 "email_label": ["legitimate", "phishing", "uncertain"],
 "identity": ["consistent", "reply_same_org", "reply_unrelated"],
 "spf": ["PASS", "FAIL", "SOFTFAIL", "NONE", "UNAVAILABLE"],
 "dkim": ["PASS", "FAIL", "NONE", "UNAVAILABLE"],
 "dmarc": ["PASS", "FAIL", "NONE", "UNAVAILABLE"],
 "header_quality": ["complete", "missing_date", "duplicate_from"],
 "impersonation": [False, True],
 "reputation": ["unknown", "trusted", "suspicious"],
 "domain_similarity": ["none", "lookalike", "unicode"],
 "context": ["ordinary", "forwarded", "mailing_list"],
}

def generate_scenarios(count: int = 3000, seed: int = 1729) -> list[dict[str, object]]:
    if count < 1: raise ValueError("count must be positive")
    rng = random.Random(seed)
    # Seed edge cases first, then deterministic randomized covering rows instead of Cartesian explosion.
    edge = [
      {"email_label":"legitimate","identity":"consistent","spf":"PASS","dkim":"PASS","dmarc":"PASS","header_quality":"complete","impersonation":False,"reputation":"trusted","domain_similarity":"none","context":"ordinary"},
      {"email_label":"phishing","identity":"reply_unrelated","spf":"FAIL","dkim":"FAIL","dmarc":"FAIL","header_quality":"duplicate_from","impersonation":True,"reputation":"suspicious","domain_similarity":"lookalike","context":"ordinary"},
      {"email_label":"legitimate","identity":"reply_unrelated","spf":"PASS","dkim":"PASS","dmarc":"PASS","header_quality":"complete","impersonation":False,"reputation":"unknown","domain_similarity":"none","context":"mailing_list"},
      {"email_label":"uncertain","identity":"consistent","spf":"UNAVAILABLE","dkim":"PASS","dmarc":"NONE","header_quality":"missing_date","impersonation":False,"reputation":"unknown","domain_similarity":"unicode","context":"forwarded"},
    ]
    rows = edge[:count]
    keys = list(DIMENSIONS)
    while len(rows) < count:
        row = {k: rng.choice(DIMENSIONS[k]) for k in keys}
        # Keep some useful semantic constraints while retaining intentionally inconsistent cases.
        if row["email_label"] == "legitimate" and row["impersonation"] and rng.random() < .7: row["impersonation"] = False
        if row["context"] == "mailing_list" and row["identity"] == "reply_unrelated" and rng.random() < .5: row["identity"] = "reply_same_org"
        row["source_type"] = "synthetic"
        row["source_dataset"] = "synthetic_header_scenarios"
        row["scenario_id"] = f"syn-{len(rows)+1:06d}"
        rows.append(row)
    # Make all rows consistently labeled synthetic, including the edge cases.
    for i, row in enumerate(rows):
        row.setdefault("source_type", "synthetic"); row.setdefault("source_dataset", "synthetic_header_scenarios"); row.setdefault("scenario_id", f"syn-{i+1:06d}")
        row["spoofing_label"] = "known_spoofing" if row["impersonation"] and row["domain_similarity"] != "none" else "unknown"
        row["header_anomaly_labels"] = [row["header_quality"]] if row["header_quality"] != "complete" else []
    return rows

def coverage_report(rows: list[dict[str, object]]) -> dict[str, object]:
    report = {"record_count": len(rows), "source_type_counts": {}, "dimension_coverage": {}, "pairwise_observed": {}}
    for row in rows:
        st = str(row.get("source_type", "unknown")); report["source_type_counts"][st] = report["source_type_counts"].get(st, 0) + 1
    for dim in DIMENSIONS:
        report["dimension_coverage"][dim] = sorted({str(r[dim]) for r in rows})
    for a, b in itertools.combinations(DIMENSIONS, 2):
        pairs = {(str(r[a]), str(r[b])) for r in rows}
        possible = len(DIMENSIONS[a]) * len(DIMENSIONS[b])
        report["pairwise_observed"][f"{a}__{b}"] = {"observed": len(pairs), "possible": possible, "coverage": round(len(pairs)/possible, 4)}
    return report

def write_scenarios(output: str | Path, count: int = 3000, seed: int = 1729) -> dict[str, object]:
    path = Path(output); path.parent.mkdir(parents=True, exist_ok=True)
    rows = generate_scenarios(count, seed)
    with path.open("w", encoding="utf-8") as f:
        for row in rows: f.write(json.dumps(row, ensure_ascii=False) + "\n")
    report = coverage_report(rows)
    report_path = path.with_name("scenario_coverage.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
