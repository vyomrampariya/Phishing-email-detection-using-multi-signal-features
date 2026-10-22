"""Command line training/evaluation entry point for the Word Pool phase."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml

from .dataset_loader import balance_sources, combine_datasets
from .evaluation import cross_dataset_evaluation, run_evaluation
from .scoring import weights_from_mapping


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", action="append", help="Directory containing CSV corpora; repeat to combine several directories (default: datasets)")
    parser.add_argument("--balance-sources", type=int, metavar="N", help="Keep at most N messages per (source, label) so no single corpus dominates the training mix")
    parser.add_argument("--config", default="configs/word_pool.yaml")
    parser.add_argument("--manifest", default="data/manifests/dataset_manifest.json")
    parser.add_argument("--report", default="reports/word_pool_experiment.json")
    parser.add_argument("--model", default="models/word_pool/model.joblib")
    parser.add_argument("--max-rows", type=int, help="Optional deterministic source/label-stratified cap for constrained machines")
    parser.add_argument("--exclude", action="append", default=["phishing_email.csv"], help="Additional file to exclude")
    parser.add_argument("--cross-dataset", help="Hold out one source_dataset name for cross-source evaluation, or 'all' to hold out each source in turn")
    args = parser.parse_args(argv)
    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    weights = weights_from_mapping(config["weights"], normalize=bool(config.get("normalize_invalid_weights", False)))
    data_dirs = [Path(d) for d in (args.data_dir or ["datasets"])]
    data_dir = data_dirs[0] if len(data_dirs) == 1 else ", ".join(map(str, data_dirs))
    paths = sorted(p for d in data_dirs for p in d.glob("*.csv"))
    if not paths: parser.error(f"No CSV files found in {data_dir}")
    stems = [p.stem for p in paths]
    if len(set(stems)) != len(stems): parser.error("CSV file names must be unique across data directories")
    print(f"Loading {len(paths)} CSV files (excluding {', '.join(args.exclude)}); exact duplicate removal enabled.", flush=True)
    frame = combine_datasets(paths, exclude=args.exclude, include_original=False)
    if args.balance_sources:
        before = len(frame)
        frame = balance_sources(frame, args.balance_sources, seed=int(config.get("seed", 42)))
        print(f"Source balancing (max {args.balance_sources} per source/label): {before:,} -> {len(frame):,} messages from {frame.source_dataset.nunique()} sources.", flush=True)
    population_count = len(frame)
    print(f"Loaded {population_count:,} usable unique messages; preparing grouped evaluation.", flush=True)
    if frame.empty: parser.error("No labeled, non-empty email records could be loaded")
    manifest_path = Path(args.manifest); manifest_path.parent.mkdir(parents=True, exist_ok=True)
    source_details = {}
    for source, group in frame.groupby("source_dataset"):
        source_file = next((p for p in paths if p.stem == source), None)
        columns = list(__import__("pandas").read_csv(source_file, nrows=0).columns) if source_file else []
        source_details[str(source)] = {"file": str(source_file), "records_after_validation_and_exact_deduplication": int(len(group)),
                                       "columns": columns,
                                       "class_counts": {str(k): int(v) for k,v in group.label.value_counts().sort_index().items()},
                                       "label_mapping": {"0": "source-native non-spam/benign label; verify source-specific semantics",
                                                         "1": "source-native spam/malicious label; not always confirmed phishing"},
                                       "license": "unknown; project did not include dataset-level license metadata"}
    manifest = {"generated_by": "word_pool.train", "data_dir": str(data_dir), "source_balance_cap_per_source_label": args.balance_sources, "excluded_files": args.exclude,
                "usable_unique_records_after_schema_validation_and_exact_deduplication": len(frame),
                "class_counts": {str(k): int(v) for k,v in frame.label.value_counts().sort_index().items()},
                "source_counts_after_exact_deduplication": {str(k): int(v) for k,v in frame.source_dataset.value_counts().items()},
                "source_details": source_details,
                "label_note": "1/0 reproduce each source's binary label. Several sources define spam vs ham, not phishing vs legitimate.",
                "license_note": "Dataset-level licenses were not supplied in the project and could not be verified from Kaggle's page-rendered metadata. See README.",
                "duplicate_policy": "Exact normalized text duplicates are removed in sorted input-path order; provenance of retained row is preserved. Near duplicates not clustered.",
                "preprocessing": "UTF-8-sig with replacement decoding; malformed CSV lines skipped by pandas; unknown labels and empty normalized messages skipped; HTML converted to readable text; Unicode/whitespace/case normalized; original local CSVs unchanged."}
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if args.max_rows and len(frame) > args.max_rows:
        fraction = args.max_rows / len(frame)
        frame = (frame.groupby(["source_dataset", "label"], group_keys=False)
                 .sample(frac=fraction, random_state=int(config.get("seed", 42)))
                 .reset_index(drop=True))
        manifest["evaluation_population_records"] = population_count
        manifest["deterministic_sample_records"] = len(frame)
        manifest["sampling_strategy"] = "Source/label-stratified fixed-fraction sample; only used because --max-rows was explicitly given."
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Fitting and evaluating on {len(frame):,} messages.", flush=True)
    model_path = Path(args.model); model_path.parent.mkdir(parents=True, exist_ok=True)
    model, report = run_evaluation(frame, weights=weights, seed=int(config.get("seed", 42)),
                                   threshold=float(config.get("threshold", 0.5)), model_path=model_path)
    if args.cross_dataset:
        held_out = sorted(frame.source_dataset.unique()) if args.cross_dataset == "all" else [args.cross_dataset]
        results = [cross_dataset_evaluation(frame, held_out_source=h, weights=weights, seed=int(config.get("seed", 42)),
                                            threshold=float(config.get("threshold", 0.5))) for h in held_out]
        report["cross_dataset"] = results if args.cross_dataset == "all" else results[0]
    report.update({"default_configured_weights": weights.__dict__, "model_path": str(model_path), "manifest_path": str(manifest_path),
                   "population_records_after_deduplication": population_count, "evaluation_records": len(frame),
                   "sampled_evaluation": bool(args.max_rows and population_count > args.max_rows),
                   "source_label_mapping": "Source-native binary labels; do not interpret all positive labels as confirmed phishing."})
    report_path = Path(args.report); report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path), "report": str(report_path), "model": str(model_path),
                      "parsed_records": len(frame), "test": report["test"]}, indent=2))


if __name__ == "__main__":
    main()
