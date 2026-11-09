"""Three-class scoring for independently reviewed CVE applicability cases."""
from __future__ import annotations

from collections import Counter
from typing import Any

from benchmarks.cpe.src.applicability_gold import (
    GOLD_SCHEMA, TRUTH, canonical_hash, iter_jsonl, stable_case_id,
    validate_gold_file, validate_gold_row,
)


def _prf(tp: int, fp: int, fn: int) -> dict[str, float | int | None]:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def _predictions(path: str) -> tuple[dict[str, list[str]], Counter, dict[tuple[str, str, str], set[str]]]:
    by_case: dict[str, list[str]] = {}
    stats: Counter = Counter()
    by_record_cve: dict[tuple[str, str, str], set[str]] = {}
    for line, row, error in iter_jsonl(path):
        if error:
            stats["malformed_prediction_rows"] += 1
            continue
        if not isinstance(row, dict) or row.get("schema_version") != "online-assessment-v1":
            stats["invalid_prediction_rows"] += 1
            continue
        record_id, source_hash = row.get("record_id"), row.get("source_hash")
        if not isinstance(record_id, str) or not isinstance(source_hash, str):
            stats["unlinked_prediction_rows"] += 1
            continue
        retrieved = row.get("cve_retrieval", {})
        configs_by_cve: dict[str, str] = {}
        for item in retrieved.get("cves", []) if isinstance(retrieved, dict) else []:
            if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
                continue
            cve = item["cve"]
            cve_id = cve.get("id")
            if not isinstance(cve_id, str):
                continue
            present = "configurations" in cve
            configs_by_cve[cve_id] = canonical_hash({"present": present, "value": cve.get("configurations") if present else None})
        for assessment in row.get("applicability_assessments", []):
            if not isinstance(assessment, dict):
                stats["invalid_assessments"] += 1
                continue
            cve_id = assessment.get("cve_id")
            value = assessment.get("logic_value")
            if (assessment.get("source_record_id") != record_id or not isinstance(cve_id, str)
                    or value not in TRUTH or cve_id not in configs_by_cve):
                stats["invalid_assessments"] += 1
                continue
            config_hash = configs_by_cve[cve_id]
            case_id = stable_case_id(record_id, source_hash, cve_id, config_hash)
            by_case.setdefault(case_id, []).append(value)
            by_record_cve.setdefault((record_id, cve_id, source_hash), set()).add(config_hash)
            stats["prediction_entries"] += 1
    return by_case, stats, by_record_cve


def _source_hashes(path: str) -> dict[str, str]:
    from benchmarks.cpe.src.applicability_gold import _source_hashes as read_source_hashes
    return read_source_hashes(path)[0]


def evaluate_applicability_gold(gold_path: str, manifest_path: str, predictions_path: str,
                                source_path: str) -> dict[str, Any]:
    integrity = validate_gold_file(gold_path, manifest_path, source_path)
    manifest_rows = {row.get("case_id"): row for _, row, error in iter_jsonl(manifest_path)
                     if not error and isinstance(row, dict)}
    source_hashes = _source_hashes(source_path)
    predictions, prediction_stats, prediction_configs = _predictions(predictions_path)
    gold_rows: list[dict] = []
    excluded = Counter()
    stale_source = stale_configs = 0
    gold_all: dict[str, dict] = {}
    for _, row, error in iter_jsonl(gold_path):
        if error or not isinstance(row, dict):
            excluded["invalid_gold_rows"] += 1
            continue
        case_id = row.get("case_id")
        if isinstance(case_id, str):
            if case_id in gold_all:
                excluded["duplicate_gold_cases"] += 1
                continue
            gold_all[case_id] = row
        status = row.get("annotation_status")
        if status in {"unreviewed", "disputed", "insufficient_evidence", "out_of_scope"}:
            excluded[status] += 1
            continue
        manifest_row = manifest_rows.get(case_id)
        errors = validate_gold_row(row, manifest_row)
        source_digest = source_hashes.get(row.get("source_record_id"))
        if source_digest != row.get("source_hash"):
            stale_source += 1
            excluded["stale_source"] += 1
            continue
        if not manifest_row or row.get("cve_snapshot", {}).get("configurations_hash") != manifest_row.get("cve_snapshot", {}).get("configurations_hash"):
            stale_configs += 1
            excluded["stale_cve_config"] += 1
            continue
        if errors or row.get("schema_version") != GOLD_SCHEMA or row.get("expected_applicability") not in TRUTH:
            excluded["invalid_reviewed_gold"] += 1
            continue
        gold_config_hash = row["cve_snapshot"]["configurations_hash"]
        seen_prediction_configs = prediction_configs.get((row["source_record_id"], row["cve_snapshot"]["cve_id"], row["source_hash"]), set())
        if seen_prediction_configs and gold_config_hash not in seen_prediction_configs:
            stale_configs += 1
            excluded["stale_prediction_cve_config"] += 1
            continue
        gold_rows.append(row)
    eligible_ids = {row["case_id"] for row in gold_rows}
    prediction_by_case: dict[str, str] = {}
    duplicate_prediction_cases = 0
    invalid_prediction_values = 0
    for case_id, values in predictions.items():
        if case_id not in eligible_ids:
            continue
        if len(values) != 1:
            duplicate_prediction_cases += 1
            continue
        if values[0] not in TRUTH:
            invalid_prediction_values += 1
            continue
        prediction_by_case[case_id] = values[0]

    labels = ("true", "false", "unknown")
    matrix = {actual: {predicted: 0 for predicted in labels} for actual in labels}
    supports = Counter()
    for row in gold_rows:
        supports[row["expected_applicability"]] += 1
        predicted = prediction_by_case.get(row["case_id"])
        if predicted is not None:
            matrix[row["expected_applicability"]][predicted] += 1
    per_class: dict[str, dict[str, Any]] = {}
    for label in labels:
        tp = matrix[label][label]
        fp = sum(matrix[actual][label] for actual in labels if actual != label)
        fn = supports[label] - tp
        metrics = _prf(tp, fp, fn)
        metrics["support"] = supports[label]
        per_class[label] = metrics
    total_tp = sum(matrix[label][label] for label in labels)
    total_fp = sum(matrix[actual][pred] for actual in labels for pred in labels if pred != actual)
    total_fn = len(gold_rows) - total_tp
    micro = _prf(total_tp, total_fp, total_fn)
    class_f1 = [row["f1"] for row in per_class.values() if row["f1"] is not None]
    macro_f1 = sum(class_f1) / len(class_f1) if class_f1 else None
    positive_support = supports["true"]
    positive_tp = matrix["true"]["true"]
    positive_fp = matrix["false"]["true"] + matrix["unknown"]["true"]
    positive_fn = positive_support - positive_tp
    positive = _prf(positive_tp, positive_fp, positive_fn)
    positive["gold_true_predicted_unknown"] = matrix["true"]["unknown"]
    positive["gold_true_predicted_false"] = matrix["true"]["false"]
    positive["gold_true_missing_prediction"] = sum(1 for row in gold_rows if row["expected_applicability"] == "true" and row["case_id"] not in prediction_by_case)
    predicted_total = len(prediction_by_case)
    definite = sum(1 for value in prediction_by_case.values() if value in {"true", "false"})
    definite_correct = sum(1 for row in gold_rows if prediction_by_case.get(row["case_id"]) in {"true", "false"} and prediction_by_case[row["case_id"]] == row["expected_applicability"])
    eligible_count = len(gold_rows)
    return {
        "schema_version": "applicability-evaluation-report-v1",
        "scope": "conditional applicability correctness on independently selected asset/CVE cases; this does not estimate CVE retrieval recall",
        "pilot_evaluation": True,
        "gold_integrity": {key: value for key, value in integrity.items() if key != "errors"},
        "eligible_reviewed_cases": eligible_count,
        "class_distribution": {label: supports[label] for label in labels},
        "confusion_matrix": matrix,
        "per_class": per_class,
        "macro_f1": macro_f1,
        "micro": micro,
        "security_positive_true": positive,
        "prediction_coverage": predicted_total / eligible_count if eligible_count else None,
        "decision_coverage": definite / eligible_count if eligible_count else None,
        "unknown_prediction_rate": sum(value == "unknown" for value in prediction_by_case.values()) / eligible_count if eligible_count else None,
        "missing_prediction_rate": (eligible_count - predicted_total) / eligible_count if eligible_count else None,
        "accuracy_on_definite_decisions": definite_correct / definite if definite else None,
        "predicted_cases": predicted_total,
        "missing_predictions": eligible_count - predicted_total,
        "stale_source_cases": stale_source,
        "stale_cve_config_cases": stale_configs,
        "duplicate_prediction_cases": duplicate_prediction_cases,
        "invalid_prediction_values": invalid_prediction_values,
        "excluded_cases": dict(excluded),
        "prediction_input": dict(prediction_stats),
        "independent_accuracy_available": bool(eligible_count),
    }
