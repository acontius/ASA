"""Create a source-linked, prediction-blind CVE applicability review manifest."""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import json
import random
from pathlib import Path
from typing import Any, Iterator

from benchmarks.cpe.src.applicability_gold import (
    CVE_ENDPOINT, MANIFEST_SCHEMA, canonical_hash, iter_jsonl, source_record_id,
    stable_case_id, validate_manifest_row,
)


def _source_index(path: str | Path) -> tuple[dict[str, str], Counter]:
    sources: dict[str, str] = {}
    stats: Counter = Counter()
    for line, document, error in iter_jsonl(path):
        if error:
            stats["malformed_source_rows"] += 1
            continue
        if not isinstance(document, dict):
            stats["non_object_source_rows"] += 1
            continue
        record_id = source_record_id(document, line)
        if record_id in sources:
            stats["duplicate_source_ids"] += 1
            continue
        sources[record_id] = canonical_hash(document)
        stats["source_records"] += 1
    return sources, stats


def _feature_strata(configurations: Any, identities: list[dict[str, Any]]) -> list[str]:
    features: set[str] = set()
    if not isinstance(configurations, list) or not configurations:
        features.add("no_configuration_tree")
        configurations = []
    if len(configurations) > 1:
        features.add("multiple_configurations")
    operators: set[str] = set()
    criteria_count = range_count = environmental_count = negated_count = 0
    stack: list[tuple[Any, int]] = [(config, 0) for config in configurations]
    while stack:
        node, depth = stack.pop()
        if depth > 64 or not isinstance(node, dict):
            features.add("malformed_or_deep_tree")
            continue
        operator = node.get("operator")
        if isinstance(operator, str) and operator.upper() in {"AND", "OR"}:
            operators.add(operator.upper())
        if node.get("negate") is True:
            negated_count += 1
        matches = node.get("cpeMatch", [])
        if isinstance(matches, list):
            for match in matches:
                criteria_count += 1
                if isinstance(match, dict):
                    if any(key in match for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")):
                        range_count += 1
                    if match.get("vulnerable") is False:
                        environmental_count += 1
                else:
                    features.add("malformed_or_deep_tree")
        else:
            features.add("malformed_or_deep_tree")
        children = node.get("nodes", [])
        if isinstance(children, list):
            stack.extend((child, depth + 1) for child in children)
        elif "nodes" in node:
            features.add("malformed_or_deep_tree")
    if criteria_count == 1:
        features.add("single_criterion")
    elif criteria_count > 1:
        features.add("multiple_criteria")
    if range_count:
        features.add("version_range")
    if environmental_count:
        features.add("environmental_prerequisite")
    if negated_count:
        features.add("negated_node")
    if operators == {"AND"}:
        features.add("and_only")
    elif operators == {"OR"}:
        features.add("or_only")
    elif operators:
        features.add("mixed_operators")
    if len(identities) > 1:
        features.add("multi_identity_asset")
    if any(identity.get("resolution_status") != "exact_match" or identity.get("inferred_components") for identity in identities):
        features.add("uncertain_inventory")
    if not any(identity.get("evidence_paths") for identity in identities):
        features.add("missing_identity_evidence_path")
    if not any(isinstance(identity.get("extracted_identity"), dict) and identity["extracted_identity"].get("version") for identity in identities):
        features.add("version_evidence_missing")
    return sorted(features)


def _assessment_cases(path: str | Path, source_hashes: dict[str, str], stats: Counter) -> Iterator[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    for line, assessment, error in iter_jsonl(path):
        if error:
            stats["malformed_assessment_rows"] += 1
            continue
        if not isinstance(assessment, dict):
            stats["non_object_assessment_rows"] += 1
            continue
        stats["assessment_rows"] += 1
        record_id = assessment.get("record_id")
        current_hash = source_hashes.get(record_id) if isinstance(record_id, str) else None
        if not current_hash or assessment.get("source_hash") != current_hash:
            stats["stale_or_unlinked_assessment_rows"] += 1
            continue
        resolutions = assessment.get("cpe_resolution", {}).get("identities", [])
        if not isinstance(resolutions, list):
            resolutions = []
        identities = []
        evidence_paths: set[str] = set()
        for index, resolution in enumerate(resolutions):
            if not isinstance(resolution, dict):
                continue
            extracted = resolution.get("extracted_identity")
            if not isinstance(extracted, dict):
                extracted = None
            paths = []
            if isinstance(resolution.get("source_path"), str) and resolution["source_path"]:
                paths.append(resolution["source_path"])
            # The output extraction contract has safe evidence references; preserve them as paths only.
            extraction_rows = assessment.get("extraction", {}).get("identities", [])
            candidate_id = resolution.get("candidate_id")
            for extraction in extraction_rows if isinstance(extraction_rows, list) else []:
                if isinstance(extraction, dict) and extraction.get("identity_id") == candidate_id:
                    paths.extend(p for p in extraction.get("evidence_paths", []) if isinstance(p, str))
                    break
            paths = list(dict.fromkeys(paths))
            evidence_paths.update(paths)
            metadata = resolution.get("nvd_metadata") or {}
            identities.append({
                "identity_id": str(candidate_id or f"{record_id}:{index}"),
                "extracted_identity": copy.deepcopy(extracted),
                "cpe23": resolution.get("cpe23") or resolution.get("cpe_name"),
                "resolution_status": str(resolution.get("resolution_status", "unknown")),
                "inferred_components": list(metadata.get("inferred_components", [])) if isinstance(metadata, dict) else [],
                "evidence_paths": paths,
            })
        retrieval = assessment.get("cve_retrieval", {})
        if not isinstance(retrieval, dict) or retrieval.get("source") != "nvd_cve_api_2.0":
            stats["records_without_online_cve_retrieval"] += 1
            continue
        api_endpoint = retrieval.get("api_endpoint") or retrieval.get("endpoint") or CVE_ENDPOINT
        if api_endpoint != CVE_ENDPOINT:
            stats["non_nvd_cve_sources"] += 1
            continue
        cve_rows = retrieval.get("cves", [])
        if not isinstance(cve_rows, list):
            stats["malformed_cve_arrays"] += 1
            continue
        for cve_row in cve_rows:
            if not isinstance(cve_row, dict) or not isinstance(cve_row.get("cve"), dict):
                stats["malformed_cve_rows"] += 1
                continue
            cve = cve_row["cve"]
            cve_id = cve.get("id")
            if not isinstance(cve_id, str):
                stats["malformed_cve_rows"] += 1
                continue
            pair = (record_id, cve_id)
            if pair in seen:
                stats["duplicate_record_cve_pairs"] += 1
                continue
            seen.add(pair)
            configs_present = "configurations" in cve
            configurations = copy.deepcopy(cve.get("configurations")) if configs_present else None
            config_hash = canonical_hash({"present": configs_present, "value": configurations})
            relationships = cve_row.get("relationships", [])
            relationship_ids = sorted({str(link.get("identity_id")) for link in relationships if isinstance(link, dict) and link.get("identity_id") is not None}) if isinstance(relationships, list) else []
            strata = _feature_strata(configurations, identities)
            cve_snapshot = {
                "cve_id": cve_id,
                "published": cve.get("published") if isinstance(cve.get("published"), str) else None,
                "last_modified": cve.get("lastModified") if isinstance(cve.get("lastModified"), str) else None,
                "configurations_hash": config_hash,
                "configurations_present": configs_present,
                "configurations": configurations,
                "nvd_source": CVE_ENDPOINT,
                "descriptions": copy.deepcopy(cve.get("descriptions", [])) if isinstance(cve.get("descriptions", []), list) else [],
                "metrics": copy.deepcopy(cve.get("metrics", {})) if isinstance(cve.get("metrics", {}), dict) else {},
            }
            case_id = stable_case_id(record_id, current_hash, cve_id, config_hash)
            row = {"schema_version": MANIFEST_SCHEMA, "case_id": case_id,
                   "source_record_id": record_id, "source_hash": current_hash,
                   "asset_snapshot": {"inventory_completeness": "passive_incomplete", "identities": identities,
                                      "evidence_paths": sorted(evidence_paths), "identity_references": relationship_ids},
                   "cve_snapshot": cve_snapshot, "sample_strata": strata}
            validation = validate_manifest_row(row)
            if validation:
                stats["invalid_case_rows"] += 1
                continue
            stats["candidate_cases"] += 1
            yield row


def _quotas(counts: dict[tuple[str, ...], int], size: int) -> dict[tuple[str, ...], int]:
    keys = sorted(counts)
    if not keys or size <= 0:
        return {}
    base, remainder = divmod(size, len(keys))
    quotas = {key: min(counts[key], base + int(index < remainder)) for index, key in enumerate(keys)}
    unused = size - sum(quotas.values())
    while unused:
        available = [key for key in keys if quotas[key] < counts[key]]
        if not available:
            break
        for key in available:
            if not unused:
                break
            quotas[key] += 1
            unused -= 1
    return quotas


def create_applicability_manifest(source_path: str | Path, assessments_path: str | Path,
                                  output_path: str | Path, size: int = 100,
                                  seed: int = 20261109) -> dict[str, Any]:
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 10000:
        raise ValueError("sample size must be between 1 and 10000")
    destination = Path(output_path)
    if destination.exists():
        raise FileExistsError(destination)
    source_hashes, stats = _source_index(source_path)
    counts: Counter[tuple[str, ...]] = Counter()
    first_stats = Counter(stats)
    for row in _assessment_cases(assessments_path, source_hashes, first_stats):
        counts[tuple(row["sample_strata"])] += 1
    quotas = _quotas(counts, size)
    rng = random.Random(seed)
    reservoirs: dict[tuple[str, ...], list[dict[str, Any]]] = {key: [] for key in counts}
    visited: Counter[tuple[str, ...]] = Counter()
    second_stats = Counter(stats)
    for row in _assessment_cases(assessments_path, source_hashes, second_stats):
        key = tuple(row["sample_strata"])
        cap = quotas.get(key, 0)
        if not cap:
            continue
        visited[key] += 1
        bucket = reservoirs[key]
        if len(bucket) < cap:
            bucket.append(row)
        else:
            position = rng.randrange(visited[key])
            if position < cap:
                bucket[position] = row
    selected: list[dict[str, Any]] = []
    ordered_keys = sorted(reservoirs)
    for bucket in reservoirs.values():
        rng.shuffle(bucket)
    selected_per_stratum = {key: len(bucket) for key, bucket in reservoirs.items()}
    while len(selected) < size and any(reservoirs.values()):
        for key in ordered_keys:
            if reservoirs[key] and len(selected) < size:
                selected.append(reservoirs[key].pop())
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as output:
        for row in selected:
            output.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return {
        "manifest": str(destination), "selected_cases": len(selected),
        "candidate_cases": first_stats["candidate_cases"], "source_records": stats["source_records"],
        "malformed_source_rows": stats["malformed_source_rows"],
        "stale_or_unlinked_assessment_rows": first_stats["stale_or_unlinked_assessment_rows"],
        "malformed_assessment_rows": first_stats["malformed_assessment_rows"],
        "duplicate_record_cve_pairs": first_stats["duplicate_record_cve_pairs"],
        "invalid_case_rows": first_stats["invalid_case_rows"], "seed": seed,
        "sample_method": "uniform reservoir within structural strata; deterministic round-robin allocation",
        "strata_population": {"|".join(key): counts[key] for key in sorted(counts)},
        "strata_selected": {"|".join(key): selected_per_stratum[key] for key in sorted(counts)},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Original local scan JSONL")
    parser.add_argument("--assessments", required=True, help="Online assessment JSONL produced by ASA")
    parser.add_argument("--output", required=True, help="New local manifest JSONL; existing files are never overwritten")
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20261109)
    args = parser.parse_args(argv)
    try:
        result = create_applicability_manifest(args.source, args.assessments, args.output, args.size, args.seed)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
