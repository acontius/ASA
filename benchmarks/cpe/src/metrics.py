"""Separate extraction identity metrics from end-to-end CPE resolution metrics."""
from __future__ import annotations

from collections import Counter
from benchmarks.cpe.src.identity import identity_value_matches


IDENTITY_FIELDS = ("product_name", "vendor", "version", "update", "part")


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp/(tp+fp) if tp+fp else None
    r = tp/(tp+fn) if tp+fn else None
    return {"precision": p, "recall": r, "f1": 2*p*r/(p+r) if p is not None and r is not None and p+r else None}


def _extraction_prediction(row: dict) -> dict:
    value = row.get("extraction_prediction", row.get("prediction")) or {}
    return value if isinstance(value, dict) else {}


def _extraction_predictions(row: dict) -> list[dict]:
    values = row.get("extraction_predictions")
    if isinstance(values, list) and values:
        return [value for value in values if isinstance(value, dict)]
    pred = _extraction_prediction(row)
    return [pred] if pred else []


def _final_cpes(row: dict) -> list[str]:
    """Read the explicit final-resolution contract, with legacy-file fallback."""
    if "final_cpe_resolutions" in row:
        return sorted({x["cpe23"] for x in row["final_cpe_resolutions"]
                       if isinstance(x, dict) and isinstance(x.get("cpe23"), str)
                       and x.get("identity_valid") is not False})
    pred = row.get("prediction") or {}
    return sorted(set(pred.get("cpe_candidates", []))) if isinstance(pred, dict) else []


def evaluate(rows: list[dict], gold_by_id: dict[str, dict]) -> dict:
    scored = [r for r in rows if r.get("record_id") in gold_by_id and gold_by_id[r["record_id"]].get("scoring_status") in {"reviewed", "ambiguous"}]
    components = {field: [0, 0, 0] for field in IDENTITY_FIELDS}
    missing = Counter()
    exact_records = cpe_records = invalid_cpe_identity = hallucinated = invalid = schema_invalid = abstain = false_positive = 0
    resolution_statuses = Counter()
    cpe_scored_records = 0

    for row in scored:
        gold = gold_by_id[row["record_id"]]
        predictions = _extraction_predictions(row)
        pred = _extraction_prediction(row)
        explicit_abstain = any(bool(p.get("abstain")) for p in predictions) or (not predictions and bool(pred.get("abstain")))
        abstain += int(explicit_abstain)
        invalid += int(bool(row.get("invalid_json", False)))
        schema_invalid += int(not row.get("schema_valid", True))
        false_positive += int(bool(predictions) and not explicit_abstain and bool(gold.get("abstain_expected")))
        for field in IDENTITY_FIELDS:
            values = [p.get(field) for p in predictions]
            concrete = [value for value in values if value is not None and not (isinstance(value, str) and (not value.strip() or value.strip() == "*"))]
            if not concrete:
                missing[field] += 1
            gold_field = "product" if field == "product_name" else field
            expected = gold.get("expected_" + gold_field)
            if expected is None or expected == "*":
                # Null in Gold means this component is unknown/optional and is not scored.
                continue
            counts = components[field]
            matching = sum(identity_value_matches(field, value, expected) is True for value in concrete)
            if matching:
                counts[0] += 1
                counts[1] += len(concrete) - matching
            else:
                counts[2] += 1
                counts[1] += len(concrete)

        final_cpes = _final_cpes(row)
        resolutions = row.get("final_cpe_resolutions", [])
        for resolution in resolutions:
            if isinstance(resolution, dict):
                resolution_statuses[str(resolution.get("resolution_status", "unknown"))] += 1
                invalid_cpe_identity += int(resolution.get("identity_valid") is False)
        if final_cpes:
            cpe_records += 1
        target_cpes = set(([gold["expected_cpe23"]] if gold.get("expected_cpe23") else []) + gold.get("acceptable_cpes", []))
        # Exact-CPE quality is scored only when Gold provides an explicit CPE target.
        if target_cpes:
            cpe_scored_records += 1
            exact_records += int(bool(target_cpes & set(final_cpes)))
        allowed = set(row.get("dictionary_cpes", []))
        hallucinated += int(bool(set(final_cpes) - allowed)) if allowed else int(bool(final_cpes) and row.get("evaluation_track") == "end_to_end_cpe")

    extraction_metrics = {field + "_metrics": prf(*counts) for field, counts in components.items()}
    total = [sum(c[i] for c in components.values()) for i in range(3)]
    extraction_metrics.update({
        "scored_records": len(scored),
        "missing_identity_fields": dict(missing),
        "abstentions": abstain,
        "abstention_rate": abstain/len(scored) if scored else None,
        "coverage": sum(any(bool(p.get("product_name")) and not p.get("abstain", True) for p in _extraction_predictions(r)) for r in scored)/len(scored) if scored else None,
        "component_micro": prf(*total),
    })
    macro_values = [extraction_metrics[field + "_metrics"]["f1"] for field in IDENTITY_FIELDS if extraction_metrics[field + "_metrics"]["f1"] is not None]
    extraction_metrics["component_macro_f1"] = sum(macro_values)/len(macro_values) if macro_values else None

    end_to_end = {
        "scored_records_with_cpe_gold": cpe_scored_records,
        "records_with_final_cpe": cpe_records,
        "exact_cpe_accuracy": exact_records/cpe_scored_records if cpe_scored_records else None,
        "hallucinated_cpe_rate": hallucinated/len(scored) if scored else None,
        "identity_invalid_resolution_count": invalid_cpe_identity,
        "resolution_status_counts": dict(resolution_statuses),
    }
    # Keep historical keys available to existing summaries: component scores
    # describe extraction; exact CPE/hallucination describe end-to-end results.
    out = {
        "scored_records": len(scored), "sample_records": len(rows),
        "evaluation_tracks": {"extraction_only": extraction_metrics, "end_to_end_cpe": end_to_end},
        "coverage": extraction_metrics["coverage"],
        "exact_cpe_accuracy": end_to_end["exact_cpe_accuracy"],
        "hallucinated_cpe_rate": end_to_end["hallucinated_cpe_rate"],
        "abstention_rate": extraction_metrics["abstention_rate"],
        "false_positive_rate": false_positive/len(scored) if scored else None,
        "invalid_json_rate": invalid/len(scored) if scored else None,
        "schema_validity_rate": 1-schema_invalid/len(scored) if scored else None,
        "missing_identity_fields": dict(missing),
        "abstentions": abstain,
    }
    out.update(extraction_metrics)
    # Aliases retained for existing report callers.
    out["scored_records"] = len(scored)
    out["sample_records"] = len(rows)
    out["exact_cpe_accuracy"] = end_to_end["exact_cpe_accuracy"]
    out["hallucinated_cpe_rate"] = end_to_end["hallucinated_cpe_rate"]
    return out
