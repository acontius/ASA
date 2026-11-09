"""Set-based, one-to-one Gold v2 metrics with explicit legacy v1 support."""
from __future__ import annotations

from collections import Counter

from benchmarks.cpe.src.identity import identity_value_matches

IDENTITY_FIELDS = ("product_name", "vendor", "version", "update", "part")
GOLD_FIELD = {"product_name": "expected_product", "vendor": "expected_vendor", "version": "expected_version", "update": "expected_update", "part": "expected_part"}


def prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    return {"precision": precision, "recall": recall, "f1": f1}


def _predictions(row: dict) -> list[dict]:
    values = row.get("extraction_predictions")
    if isinstance(values, list) and values:
        return [value for value in values if isinstance(value, dict)]
    if isinstance(row.get("extraction_prediction"), dict):
        return [row["extraction_prediction"]]
    value = row.get("extraction_prediction", row.get("prediction"))
    if value is None:
        value = row.get("prediction")
    return [value] if isinstance(value, dict) else []


def _gold_identities(gold: dict) -> list[dict]:
    if gold.get("schema_version") == "2.0":
        return [identity for identity in gold.get("expected_identities", []) if isinstance(identity, dict)]
    if gold.get("_source_format") == "v1" or "expected_identities" not in gold:
        if isinstance(gold.get("expected_product"), str) and gold["expected_product"].strip():
            return [{
                "identity_id": gold.get("record_id", "legacy") + "-1",
                "expected_product": gold["expected_product"],
                "expected_vendor": gold.get("expected_vendor"),
                "expected_version": gold.get("expected_version"),
                "expected_update": gold.get("expected_update"),
                "expected_part": gold.get("expected_part"),
                "cpe_mapping_status": "mapped" if gold.get("expected_cpe23") or gold.get("acceptable_cpes") else "unreviewed",
                "expected_cpe23": gold.get("expected_cpe23"),
                "acceptable_cpes": gold.get("acceptable_cpes", []),
            }]
    return []


def _get(identity: dict | None, field: str):
    return identity.get(field, identity.get(GOLD_FIELD[field])) if identity else None


def _concrete(value) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.strip() != "*"


def _compatible(prediction: dict, gold: dict) -> bool:
    if identity_value_matches("product_name", _get(prediction, "product_name"), _get(gold, "product_name")) is not True:
        return False
    # Known vendor/version/update/part components constrain identity pairing;
    # unknown components remain eligible and are scored as missing below.
    for field in ("vendor", "version", "update", "part"):
        actual, expected = _get(prediction, field), _get(gold, field)
        if _concrete(actual) and _concrete(expected) and identity_value_matches(field, actual, expected) is not True:
            return False
    return True


def _maximum_matching(predictions: list[dict], identities: list[dict]) -> dict[int, int]:
    """Maximize identity matches, then field agreements, with deterministic ties."""
    prediction_count, gold_count = len(predictions), len(identities)
    if not prediction_count or not gold_count:
        return {}
    cardinality_bonus = 5 * min(prediction_count, gold_count) + 1
    weights: list[list[int]] = []
    valid_edges: set[tuple[int, int]] = set()
    for pred_index, prediction in enumerate(predictions):
        row = []
        for gold_index, identity in enumerate(identities):
            if not _compatible(prediction, identity):
                row.append(-cardinality_bonus)
                continue
            valid_edges.add((pred_index, gold_index))
            agreements = sum(
                identity_value_matches(field, _get(prediction, field), _get(identity, field)) is True
                for field in IDENTITY_FIELDS
            )
            row.append(cardinality_bonus + agreements)
        # Dummy columns let predictions remain unmatched at zero weight.
        row.extend([0] * prediction_count)
        weights.append(row)

    # Rectangular Hungarian assignment (rows <= columns), minimizing negated
    # weights. Valid identity cardinality dominates all possible field-score
    # differences; field agreement breaks ties among maximum-cardinality sets.
    row_count, column_count = prediction_count, gold_count + prediction_count
    u, v = [0] * (row_count + 1), [0] * (column_count + 1)
    column_row, previous = [0] * (column_count + 1), [0] * (column_count + 1)
    for row_index in range(1, row_count + 1):
        column_row[0] = row_index
        min_value = [float("inf")] * (column_count + 1)
        used = [False] * (column_count + 1)
        column = 0
        while True:
            used[column] = True
            active_row = column_row[column]
            delta, next_column = float("inf"), 0
            for candidate_column in range(1, column_count + 1):
                if used[candidate_column]:
                    continue
                cost = -weights[active_row - 1][candidate_column - 1] - u[active_row] - v[candidate_column]
                if cost < min_value[candidate_column]:
                    min_value[candidate_column] = cost
                    previous[candidate_column] = column
                if min_value[candidate_column] < delta:
                    delta, next_column = min_value[candidate_column], candidate_column
            for candidate_column in range(column_count + 1):
                if used[candidate_column]:
                    u[column_row[candidate_column]] += delta
                    v[candidate_column] -= delta
                else:
                    min_value[candidate_column] -= delta
            column = next_column
            if column_row[column] == 0:
                break
        while True:
            prior_column = previous[column]
            column_row[column] = column_row[prior_column]
            column = prior_column
            if column == 0:
                break
    matching = {}
    for column in range(1, column_count + 1):
        pred_index, gold_index = column_row[column] - 1, column - 1
        if pred_index >= 0 and gold_index < gold_count and (pred_index, gold_index) in valid_edges:
            matching[pred_index] = gold_index
    return matching


def _resolution_cpes(row: dict) -> list[str]:
    resolutions = row.get("final_cpe_resolutions")
    if isinstance(resolutions, list):
        return [item["cpe23"] for item in resolutions
                if isinstance(item, dict) and isinstance(item.get("cpe23"), str)
                and item.get("identity_valid") is not False]
    if row.get("method") == "llm":
        # Historical Direct rows may lack the final-resolution field. Never
        # reinterpret their model-proposed CPEs as M3 output.
        return []
    return [name for prediction in _predictions(row)
            for name in prediction.get("cpe_candidates", [])
            if isinstance(name, str)]


def _scorable(gold: dict) -> bool:
    if gold.get("schema_version") == "2.0":
        annotation = gold.get("annotation", {})
        return (gold.get("annotation_status") in {"reviewed", "no_software_identity"}
                and isinstance(annotation, dict)
                and annotation.get("adjudication_status") in {"reviewed", "adjudicated"})
    # Legacy v1 rows retain explicit reviewed/ambiguous semantics; empty v1
    # abstention labels are never reinterpreted as v2 confirmed negatives.
    return gold.get("scoring_status") in {"reviewed", "ambiguous"}


def evaluate(rows: list[dict], gold_by_id: dict[str, dict]) -> dict:
    status_counts = Counter()
    for gold in gold_by_id.values():
        status_counts[gold.get("annotation_status", "legacy_" + str(gold.get("scoring_status", "unknown")))] += 1
    stale: set[str] = set()
    for row in rows:
        gold = gold_by_id.get(row.get("record_id"), {})
        if gold.get("schema_version") == "2.0" and row.get("record_id"):
            # Old result rows without hashes cannot be used against v2 labels.
            if row.get("source_hash") != gold.get("source_hash"):
                stale.add(row["record_id"])
    present = {row.get("record_id") for row in rows if row.get("record_id") in gold_by_id}
    scored = [row for row in rows if row.get("record_id") in gold_by_id and row.get("record_id") not in stale and _scorable(gold_by_id[row["record_id"]])]

    field_counts = {field: [0, 0, 0] for field in IDENTITY_FIELDS}
    missing = Counter()
    identity_tp = identity_fp = identity_fn = 0
    cpe_exact = cpe_total = cpe_invalid_identity = 0
    cpe_predictions = unmatched_cpe_predictions = 0
    cpe_status_counts = Counter()
    unmapped_identity_counts = Counter()
    explicit_abstentions = no_identity_correct = 0

    for row in scored:
        gold = gold_by_id[row["record_id"]]
        predictions = _predictions(row)
        identities = _gold_identities(gold)
        identity_predictions = [prediction for prediction in predictions if _concrete(_get(prediction, "product_name"))]
        explicit_abstentions += int(bool(predictions) and all(bool(pred.get("abstain")) for pred in predictions))
        matches = _maximum_matching(identity_predictions, identities)
        matched_gold = set(matches.values())
        identity_tp += len(matches)
        identity_fp += len(identity_predictions) - len(matches)
        identity_fn += len(identities) - len(matched_gold)
        if gold.get("annotation_status") == "no_software_identity":
            no_identity_correct += int(not identity_predictions)

        matched_by_gold = {gold_index: identity_predictions[pred_index] for pred_index, gold_index in matches.items()}
        for field in IDENTITY_FIELDS:
            counts = field_counts[field]
            for gold_index, identity in enumerate(identities):
                expected = _get(identity, field)
                if expected is None or expected == "*":
                    continue
                prediction = matched_by_gold.get(gold_index)
                actual = _get(prediction, field)
                if identity_value_matches(field, actual, expected) is True:
                    counts[0] += 1
                else:
                    counts[2] += 1
                    counts[1] += int(_concrete(actual))
            for pred_index, prediction in enumerate(identity_predictions):
                if pred_index not in matches and _concrete(_get(prediction, field)):
                    counts[1] += 1
            if not any(_concrete(_get(prediction, field)) for prediction in predictions):
                missing[field] += 1

        for resolution in row.get("final_cpe_resolutions", []):
            if isinstance(resolution, dict) and resolution.get("identity_valid") is False:
                cpe_invalid_identity += 1
        mapped_targets: list[set[str]] = []
        for identity in identities:
            mapping_status = identity.get("cpe_mapping_status", "unreviewed")
            if mapping_status != "mapped":
                continue
            target = set(([identity["expected_cpe23"]] if identity.get("expected_cpe23") else []) + identity.get("acceptable_cpes", []))
            if not target:
                continue
            cpe_total += 1
            mapped_targets.append(target)
        actual_cpes = _resolution_cpes(row)
        cpe_predictions += len(actual_cpes)
        # Exact CPEs use an independent one-to-one bipartite match. This keeps
        # the end-to-end track separate from extraction identity field scores.
        gold_to_cpe: dict[int, int] = {}
        def assign(pred_index: int, seen: set[int]) -> bool:
            for gold_index, target in enumerate(mapped_targets):
                if actual_cpes[pred_index] not in target or gold_index in seen:
                    continue
                seen.add(gold_index)
                if gold_index not in gold_to_cpe or assign(gold_to_cpe[gold_index], seen):
                    gold_to_cpe[gold_index] = pred_index
                    return True
            return False
        for pred_index in range(len(actual_cpes)):
            assign(pred_index, set())
        cpe_exact += len(gold_to_cpe)
        unmatched_cpe_predictions += len(actual_cpes) - len(gold_to_cpe)

    for gold in gold_by_id.values():
        for identity in _gold_identities(gold):
            mapping_status = identity.get("cpe_mapping_status", "unreviewed")
            cpe_status_counts[mapping_status] += 1
            if mapping_status != "mapped":
                unmapped_identity_counts[mapping_status] += 1

    field_metrics = {field + "_metrics": prf(*counts) for field, counts in field_counts.items()}
    total_counts = [sum(counts[i] for counts in field_counts.values()) for i in range(3)]
    no_identity_records = sum(gold_by_id[row["record_id"]].get("annotation_status") == "no_software_identity" for row in scored)
    extraction_track = {
        **field_metrics,
        "identity_metrics": prf(identity_tp, identity_fp, identity_fn),
        "gold_identities": sum(len(_gold_identities(gold_by_id[row["record_id"]])) for row in scored),
        "predicted_identities": sum(sum(_concrete(_get(prediction, "product_name")) for prediction in _predictions(row)) for row in scored),
        "missing_identity_fields": dict(missing),
        "explicit_abstentions": explicit_abstentions,
        "abstentions": explicit_abstentions,
        "component_micro": prf(*total_counts),
        "no_software_identity_records": no_identity_records,
        "no_software_identity_correct_records": no_identity_correct,
        "scored_records_without_identities": no_identity_records,
    }
    available_f1 = [value["f1"] for value in field_metrics.values() if value["f1"] is not None]
    extraction_track["component_macro_f1"] = sum(available_f1) / len(available_f1) if available_f1 else None
    end_to_end = {
        "mapped_gold_identities": cpe_total,
        "exact_cpe_correct_identities": cpe_exact,
        "exact_cpe_accuracy": cpe_exact / cpe_total if cpe_total else None,
        "predicted_cpe_resolutions": cpe_predictions,
        "unmatched_predicted_cpe_resolutions": unmatched_cpe_predictions,
        "unmapped_identity_counts": dict(unmapped_identity_counts),
        "cpe_mapping_status_counts": dict(cpe_status_counts),
        "identity_invalid_resolution_count": cpe_invalid_identity,
    }
    scored_records = len(scored)
    result = {
        "scored_records": scored_records,
        "sample_records": len(rows),
        "gold_records_present": len(present),
        "gold_coverage": len(present) / len(rows) if rows else None,
        "scored_record_coverage": scored_records / len(rows) if rows else None,
        "stale_source_records": len(stale),
        "gold_status_counts": dict(status_counts),
        "gold_adjudication_status_counts": dict(Counter(
            row.get("annotation", {}).get("adjudication_status", "legacy")
            for row in gold_by_id.values() if isinstance(row.get("annotation", {}), dict)
        )),
        "evaluation_tracks": {"extraction_only": extraction_track, "end_to_end_cpe": end_to_end},
        "exact_cpe_accuracy": end_to_end["exact_cpe_accuracy"],
        "hallucinated_cpe_rate": None,
        "coverage": extraction_track["identity_metrics"]["recall"],
        "abstention_rate": explicit_abstentions / scored_records if scored_records else None,
        "missing_identity_fields": dict(missing),
        "abstentions": explicit_abstentions,
        "component_micro": extraction_track["component_micro"],
        "component_macro_f1": extraction_track["component_macro_f1"],
        "identity_metrics": extraction_track["identity_metrics"],
        "scored_records_without_identities": no_identity_records,
    }
    result.update(field_metrics)
    return result
