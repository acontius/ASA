"""Independent CVE-applicability Gold contracts and validation tools.

This module never calls the ASA evaluator and never derives expected labels.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterator

GOLD_SCHEMA = "applicability-gold-v1"
MANIFEST_SCHEMA = "applicability-manifest-v1"
TRUTH = {"true", "false", "unknown"}
STATUSES = {"unreviewed", "reviewed", "adjudicated", "disputed", "insufficient_evidence", "out_of_scope"}
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
HASH = re.compile(r"^[a-f0-9]{64}$")
CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MANIFEST_FIELDS = {"schema_version", "case_id", "source_record_id", "source_hash", "asset_snapshot", "cve_snapshot", "sample_strata"}
GOLD_FIELDS = MANIFEST_FIELDS | {"expected_applicability", "annotation_status", "reviews", "adjudication", "annotation_history"}
REVIEW_FIELDS = {"reviewer_id", "reviewed_at", "expected_applicability", "reason_codes", "notes", "supporting_evidence_paths", "supporting_identity_ids", "reviewed_configuration_references"}
ADJUDICATION_FIELDS = {"adjudicator_id", "adjudicated_at", "expected_applicability", "notes", "reviewed_configuration_references"}
HISTORY_FIELDS = {"saved_at", "actor_id", "action", "expected_applicability", "annotation_status", "reviews", "adjudication"}


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def stable_case_id(source_record_id: str, source_hash: str, cve_id: str, configurations_hash: str) -> str:
    return canonical_hash([source_record_id, source_hash, cve_id, configurations_hash])


def source_record_id(document: dict[str, Any], line_number: int) -> str:
    source = document.get("_source")
    if not isinstance(source, dict):
        source = {}
    for value in (source.get("id"), document.get("_id")):
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            return str(value)
    return f"line-{line_number}"


def iter_jsonl(path: str | Path) -> Iterator[tuple[int, Any | None, str | None]]:
    with Path(path).open("rb") as stream:
        for line_number, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                yield line_number, None, f"invalid JSON: {getattr(exc, 'msg', 'invalid UTF-8')}"
                continue
            yield line_number, value, None


def _exact_fields(row: Any, expected: set[str], label: str) -> list[str]:
    if not isinstance(row, dict):
        return [f"{label} must be an object"]
    errors = []
    missing, extra = expected - row.keys(), row.keys() - expected
    if missing:
        errors.append(f"{label} missing fields: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{label} has unexpected fields: {', '.join(sorted(extra))}")
    return errors


def validate_manifest_row(row: Any) -> list[str]:
    errors = _exact_fields(row, MANIFEST_FIELDS, "manifest row")
    if not isinstance(row, dict):
        return errors
    if row.get("schema_version") != MANIFEST_SCHEMA:
        errors.append(f"schema_version must be {MANIFEST_SCHEMA}")
    if not isinstance(row.get("case_id"), str) or not HASH.fullmatch(row["case_id"]):
        errors.append("case_id must be a SHA-256 hex digest")
    if not isinstance(row.get("source_record_id"), str) or not row.get("source_record_id"):
        errors.append("source_record_id must be a non-empty string")
    if not isinstance(row.get("source_hash"), str) or not HASH.fullmatch(row["source_hash"]):
        errors.append("source_hash must be a SHA-256 hex digest")
    strata = row.get("sample_strata")
    if not isinstance(strata, list) or any(not isinstance(v, str) for v in strata) or len(strata) != len(set(strata)):
        errors.append("sample_strata must be an array of unique strings")
    asset = row.get("asset_snapshot")
    if not isinstance(asset, dict) or set(asset) != {"inventory_completeness", "identities", "evidence_paths", "identity_references"}:
        errors.append("asset_snapshot has invalid fields")
    else:
        if asset.get("inventory_completeness") != "passive_incomplete":
            errors.append("asset inventory must be marked passive_incomplete")
        if not isinstance(asset.get("identities"), list):
            errors.append("asset identities must be an array")
        if not isinstance(asset.get("evidence_paths"), list) or any(not isinstance(x, str) for x in asset["evidence_paths"]):
            errors.append("asset evidence_paths must be an array of strings")
        if not isinstance(asset.get("identity_references"), list) or any(not isinstance(x, str) for x in asset["identity_references"]):
            errors.append("asset identity_references must be an array of strings")
        seen_identity_ids = set()
        for index, identity in enumerate(asset.get("identities", [])):
            expected = {"identity_id", "extracted_identity", "cpe23", "resolution_status", "inferred_components", "evidence_paths"}
            errors.extend(_exact_fields(identity, expected, f"asset identities[{index}]"))
            if isinstance(identity, dict):
                iid = identity.get("identity_id")
                if not isinstance(iid, str) or not iid:
                    errors.append(f"asset identities[{index}].identity_id is required")
                elif iid in seen_identity_ids:
                    errors.append("asset identity IDs must be unique")
                seen_identity_ids.add(iid)
                if not isinstance(identity.get("resolution_status"), str):
                    errors.append(f"asset identities[{index}].resolution_status is required")
    cve = row.get("cve_snapshot")
    cve_fields = {"cve_id", "published", "last_modified", "configurations_hash", "configurations_present", "configurations", "nvd_source", "descriptions", "metrics"}
    if not isinstance(cve, dict) or set(cve) != cve_fields:
        errors.append("cve_snapshot has invalid fields")
    else:
        if not isinstance(cve.get("cve_id"), str) or not CVE_ID.fullmatch(cve["cve_id"]):
            errors.append("cve_id is invalid")
        if not isinstance(cve.get("configurations_hash"), str) or not HASH.fullmatch(cve["configurations_hash"]):
            errors.append("configurations_hash must be a SHA-256 hex digest")
        if cve.get("configurations_hash") != canonical_hash({"present": cve.get("configurations_present"), "value": cve.get("configurations")}):
            errors.append("CVE configurations snapshot hash mismatch")
        if not isinstance(cve.get("configurations_present"), bool):
            errors.append("configurations_present must be boolean")
        if cve.get("configurations") is not None and not isinstance(cve.get("configurations"), list):
            errors.append("configurations must be an array or null")
        if cve.get("nvd_source") != CVE_ENDPOINT:
            errors.append("nvd_source must be the official NVD CVE API endpoint")
        if not isinstance(cve.get("descriptions"), list) or not isinstance(cve.get("metrics"), dict):
            errors.append("CVE descriptions/metrics have invalid types")
    if isinstance(row.get("case_id"), str) and isinstance(row.get("source_record_id"), str) and isinstance(row.get("source_hash"), str) and isinstance(cve, dict) and isinstance(cve.get("cve_id"), str) and isinstance(cve.get("configurations_hash"), str):
        if row["case_id"] != stable_case_id(row["source_record_id"], row["source_hash"], cve["cve_id"], cve["configurations_hash"]):
            errors.append("case_id does not match its source/CVE snapshot")
    return errors


def _valid_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        return True
    except ValueError:
        return False


def validate_gold_row(row: Any, manifest_row: dict[str, Any] | None = None) -> list[str]:
    errors = _exact_fields(row, GOLD_FIELDS, "Gold row")
    if not isinstance(row, dict):
        return errors
    manifest_view = {key: row.get(key) for key in MANIFEST_FIELDS}
    manifest_view["schema_version"] = MANIFEST_SCHEMA
    errors.extend(validate_manifest_row(manifest_view))
    if row.get("schema_version") != GOLD_SCHEMA:
        errors.append(f"schema_version must be {GOLD_SCHEMA}")
    if manifest_row:
        for key in ("case_id", "source_record_id", "source_hash", "asset_snapshot", "cve_snapshot", "sample_strata"):
            if row.get(key) != manifest_row.get(key):
                errors.append(f"Gold {key} differs from the manifest")
    status, label, reviews, adjudication = row.get("annotation_status"), row.get("expected_applicability"), row.get("reviews"), row.get("adjudication")
    history = row.get("annotation_history")
    if not isinstance(history, list):
        errors.append("annotation_history must be an array")
        history = []
    for index, event in enumerate(history):
        errors.extend(_exact_fields(event, HISTORY_FIELDS, f"annotation_history[{index}]"))
        if isinstance(event, dict):
            if not _valid_datetime(event.get("saved_at")) or not isinstance(event.get("actor_id"), str) or not event.get("actor_id").strip():
                errors.append(f"annotation_history[{index}] requires actor_id and ISO-8601 saved_at")
            if event.get("action") not in {"review", "non_scored", "adjudicate"}:
                errors.append(f"annotation_history[{index}].action is invalid")
    if status not in STATUSES:
        errors.append("invalid annotation_status")
    if label is not None and label not in TRUTH:
        errors.append("expected_applicability must be true, false, unknown, or null")
    if not isinstance(reviews, list):
        errors.append("reviews must be an array")
        reviews = []
    reviewer_ids: set[str] = set()
    labels = []
    for index, review in enumerate(reviews):
        errors.extend(_exact_fields(review, REVIEW_FIELDS, f"reviews[{index}]"))
        if not isinstance(review, dict):
            continue
        reviewer = review.get("reviewer_id")
        if not isinstance(reviewer, str) or not reviewer.strip():
            errors.append(f"reviews[{index}].reviewer_id is required")
        elif reviewer in reviewer_ids:
            errors.append("reviewer IDs must be unique within a case")
        reviewer_ids.add(reviewer)
        if not _valid_datetime(review.get("reviewed_at")):
            errors.append(f"reviews[{index}].reviewed_at must be ISO-8601")
        review_label = review.get("expected_applicability")
        if review_label is not None and review_label not in TRUTH:
            errors.append(f"reviews[{index}].expected_applicability is invalid")
        labels.append(review_label)
        for key in ("reason_codes", "supporting_evidence_paths", "supporting_identity_ids", "reviewed_configuration_references"):
            value = review.get(key)
            if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
                errors.append(f"reviews[{index}].{key} must be an array of non-empty strings")
        if isinstance(review.get("notes"), str) is False:
            errors.append(f"reviews[{index}].notes must be a string")
        if not review.get("reason_codes"):
            errors.append(f"reviews[{index}] requires at least one reason code")
        if review_label is not None and not (review.get("supporting_evidence_paths") or review.get("supporting_identity_ids") or review.get("reviewed_configuration_references")):
            errors.append(f"reviews[{index}] requires supporting evidence or configuration references")
    if adjudication is not None:
        errors.extend(_exact_fields(adjudication, ADJUDICATION_FIELDS, "adjudication"))
        if isinstance(adjudication, dict):
            if not isinstance(adjudication.get("adjudicator_id"), str) or not adjudication["adjudicator_id"].strip():
                errors.append("adjudication.adjudicator_id is required")
            if adjudication.get("adjudicator_id") in reviewer_ids:
                errors.append("adjudicator must be independent from first/second reviewers")
            if not _valid_datetime(adjudication.get("adjudicated_at")):
                errors.append("adjudication.adjudicated_at must be ISO-8601")
            if adjudication.get("expected_applicability") not in TRUTH:
                errors.append("adjudication label must be true, false, or unknown")
            if not isinstance(adjudication.get("notes"), str) or not adjudication.get("notes", "").strip():
                errors.append("adjudication notes are required")
            if not isinstance(adjudication.get("reviewed_configuration_references"), list):
                errors.append("adjudication reviewed_configuration_references must be an array")
    labels_conflict = len(set(labels)) > 1
    if status == "unreviewed":
        if reviews or adjudication is not None or label is not None:
            errors.append("unreviewed cases cannot carry labels, reviews, or adjudication")
    elif status == "reviewed":
        if not reviews or any(value not in TRUTH for value in labels) or labels_conflict or adjudication is not None:
            errors.append("reviewed cases require agreeing human labels and no adjudication")
        elif label != labels[0]:
            errors.append("expected_applicability must equal the human review label")
    elif status == "adjudicated":
        if len(reviews) < 2 or adjudication is None:
            errors.append("adjudicated cases require at least two reviews and an independent adjudicator")
        elif label != adjudication.get("expected_applicability"):
            errors.append("expected_applicability must equal the adjudication label")
    elif status == "disputed":
        if len(reviews) < 2 or not labels_conflict or adjudication is not None or label is not None:
            errors.append("disputed cases require conflicting reviews and no primary Gold label")
    elif status in {"insufficient_evidence", "out_of_scope"}:
        if label is not None or not reviews or any(value is not None for value in labels):
            errors.append(f"{status} cases require a review but no truth label")
        if not any(isinstance(review, dict) and review.get("notes", "").strip() for review in reviews):
            errors.append(f"{status} cases require explanatory notes")
    return errors


def _read_unique(path: str | Path, schema: str, errors: list[dict]) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for line, row, error in iter_jsonl(path):
        if error:
            errors.append({"line": line, "errors": [error]})
            continue
        if not isinstance(row, dict):
            errors.append({"line": line, "errors": ["JSONL row must be an object"]})
            continue
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            errors.append({"line": line, "errors": ["case_id is required"]})
            continue
        if case_id in rows:
            errors.append({"line": line, "case_id": case_id, "errors": ["duplicate case_id"]})
            continue
        row_errors = validate_manifest_row(row) if schema == MANIFEST_SCHEMA else validate_gold_row(row)
        if row.get("schema_version") != schema:
            row_errors.append(f"schema_version must be {schema}")
        if row_errors:
            errors.append({"line": line, "case_id": case_id, "errors": row_errors})
        rows[case_id] = row
    return rows


def _source_hashes(path: str | Path) -> tuple[dict[str, str], int]:
    values: dict[str, str] = {}
    duplicates = 0
    for line, document, error in iter_jsonl(path):
        if error or not isinstance(document, dict):
            continue
        rid = source_record_id(document, line)
        if rid in values:
            duplicates += 1
            continue
        values[rid] = canonical_hash(document)
    return values, duplicates


def validate_gold_file(gold_path: str | Path, manifest_path: str | Path, source_path: str | Path) -> dict[str, Any]:
    errors: list[dict] = []
    manifest = _read_unique(manifest_path, MANIFEST_SCHEMA, errors)
    gold = _read_unique(gold_path, GOLD_SCHEMA, errors)
    source_hashes, duplicate_source_ids = _source_hashes(source_path)
    status_counts = Counter()
    stale_source = stale_config = 0
    eligible = 0
    seen_pairs: set[tuple[str, str]] = set()
    for case_id, row in gold.items():
        status_counts[row.get("annotation_status", "invalid")] += 1
        manifest_row = manifest.get(case_id)
        row_errors = validate_gold_row(row, manifest_row)
        source_digest = source_hashes.get(row.get("source_record_id"))
        if source_digest != row.get("source_hash"):
            stale_source += 1
            row_errors.append("source record is missing or source_hash is stale")
        cve = row.get("cve_snapshot") if isinstance(row.get("cve_snapshot"), dict) else {}
        configs_hash = cve.get("configurations_hash")
        current_configs_hash = canonical_hash({"present": cve.get("configurations_present"), "value": cve.get("configurations")})
        if configs_hash != current_configs_hash or (manifest_row and configs_hash != manifest_row.get("cve_snapshot", {}).get("configurations_hash")):
            stale_config += 1
            row_errors.append("CVE configuration snapshot is stale or differs from manifest")
        pair = (str(row.get("source_record_id")), str(cve.get("cve_id")))
        if pair in seen_pairs:
            row_errors.append("duplicate source_record_id/CVE assessment key")
        seen_pairs.add(pair)
        if row_errors:
            errors.append({"case_id": case_id, "errors": row_errors})
        elif row.get("annotation_status") in {"reviewed", "adjudicated"}:
            eligible += 1
    counts = Counter(row.get("annotation_status", "invalid") for row in gold.values())
    return {
        "total_cases": len(gold),
        "reviewed_cases": counts["reviewed"],
        "adjudicated_cases": counts["adjudicated"],
        "unreviewed_cases": counts["unreviewed"],
        "disputed_cases": counts["disputed"],
        "insufficient_evidence_cases": counts["insufficient_evidence"],
        "out_of_scope_cases": counts["out_of_scope"],
        "stale_source_cases": stale_source,
        "stale_cve_config_cases": stale_config,
        "duplicate_source_record_ids": duplicate_source_ids,
        "valid_scoring_cases": eligible,
        "invalid_rows": len(errors),
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate independent human-reviewed CVE applicability Gold.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--gold", required=True)
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--source", required=True, help="Original local scan JSONL used for source-hash verification")
    args = parser.parse_args(argv)
    result = validate_gold_file(args.gold, args.manifest, args.source)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["invalid_rows"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
