"""Local JSONL sampling and gold-label contract validation."""
from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any
from benchmarks.cpe.src.identity import compare_cpe_identity, gold_identity

PROTOCOLS = ("ssh", "http", "ftp", "mongodb")
GOLD_REQUIRED = {"record_id", "expected_product", "expected_vendor", "expected_version", "expected_update", "expected_part", "expected_cpe23", "acceptable_cpes", "abstain_expected", "evidence_paths", "adjudication_notes", "scoring_status"}


def iter_jsonl(path: str | Path):
    with Path(path).open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if line.strip():
                try:
                    yield line_no, json.loads(line)
                except json.JSONDecodeError:
                    # Preserve source files as-is; callers can skip malformed
                    # physical lines and report the count in preparation metadata.
                    continue


def stable_id(doc: dict[str, Any], line: int) -> str:
    src = doc.get("_source", {}) if isinstance(doc, dict) else {}
    if not isinstance(src, dict):
        src = {}
    # Keep a record's opaque benchmark ID stable when its content changes so
    # source_hash can detect stale annotations. Prefer Elasticsearch identity;
    # fall back to physical line position when the source has no stable key.
    source_key = next((value for value in (src.get("id"), doc.get("_id"))
                       if isinstance(value, (str, int)) and not isinstance(value, bool)), None)
    identity = f"source:{source_key}" if source_key is not None else f"line:{line}"
    return "rec-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def protocol_of(doc: dict[str, Any]) -> str:
    src = doc.get("_source", {})
    if not isinstance(src, dict):
        src = {}
    declared = str(src.get("proto", "")).lower()
    present = [p for p in PROTOCOLS if any(isinstance(src.get(k), dict) and p in src[k] for k in src if len(k) > 1 and k[0] in "tu" and k[1:].isdigit())]
    return declared if declared in present else present[0] if present else declared if declared in PROTOCOLS else "other"


def evidence_bucket(doc: dict[str, Any]) -> str:
    raw = json.dumps(doc, ensure_ascii=False).lower()
    if any(x in raw for x in ("server_id", "build_info", "openssh_", "vsftpd ", "nginx/", "apache/")):
        return "strong"
    if any(x in raw for x in ("banner", "server", "version")):
        return "moderate"
    return "weak"


def extraction_strata(doc: dict[str, Any], line: int) -> tuple[str, str, str]:
    """Use M2 labels only to form sample strata, never as evaluation gold."""
    outcome, strength, version_presence, _candidate_count = _extraction_details(doc, line)
    return outcome, strength, version_presence


def _extraction_details(doc: dict[str, Any], line: int) -> tuple[str, str, str, int | None]:
    try:
        from app.extractors import EXTRACTORS, extract_candidates
        from app.ingestion.normalizer import normalize
        from app.outcomes import classify
        record = normalize(doc, line_number=line, byte_offset=0)
        candidates = extract_candidates(record, EXTRACTORS)
        supported = any(b["protocol"] in EXTRACTORS for b in record["port_blocks"])
        outcome = classify(record["record_id"], candidates, supported_block_present=supported)["outcome"]
        strengths = [c["evidence_strength"] for c in candidates]
        strength = "strong" if "strong" in strengths else "moderate" if "moderate" in strengths else "weak"
        version_presence = "with_version" if any(isinstance(c.get("version"), str) and c["version"].strip() for c in candidates) else "without_version"
        return outcome, strength, version_presence, len(candidates)
    except Exception:
        return "processing_error", "unavailable", "unavailable", None


def sample(input_path: str | Path, output_path: str | Path, size: int = 40, seed: int = 20261107) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for line, doc in iter_jsonl(input_path):
        if not isinstance(doc, dict):
            continue
        outcome, strength, version_presence = extraction_strata(doc, line)
        key = (protocol_of(doc), outcome, strength, version_presence)
        buckets.setdefault(key, []).append({"record_id": stable_id(doc, line), "raw": doc, "protocol": key[0], "m2_outcome_stratum": key[1], "evidence_strength": key[2], "version_presence": key[3]})
    rng = random.Random(seed)
    for rows in buckets.values():
        rng.shuffle(rows)
    # Round-robin strata gives protocol/evidence/version diversity within the cap.
    selected = []
    keys = sorted(buckets)
    while len(selected) < size and any(buckets.values()):
        for key in keys:
            if buckets[key] and len(selected) < size:
                selected.append(buckets[key].pop())
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with Path(output_path).open("w", encoding="utf-8") as f:
        for row in selected:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return selected


def prepare_pilot_sample(input_path: str | Path, output_path: str | Path, size: int = 100, seed: int = 20261108) -> dict[str, Any]:
    """Write up to 100 raw source records stratified for human annotation.

    M2 is used only to create sampling strata. Its outputs are recorded as
    diagnostics, never as Gold labels. The destination must not already exist.
    """
    from benchmarks.cpe.src.gold import canonical_source_hash

    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 100:
        raise ValueError("pilot sample size must be from 1 through 100")
    buckets: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    malformed = non_object = valid = duplicates = 0
    seen_ids: set[str] = set()
    with Path(input_path).open("rb") as stream:
        for line_number, raw_line in enumerate(stream, 1):
            if not raw_line.strip():
                continue
            try:
                document = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                malformed += 1
                continue
            if not isinstance(document, dict):
                non_object += 1
                continue
            valid += 1
            record_id = stable_id(document, line_number)
            if record_id in seen_ids:
                duplicates += 1
                continue
            seen_ids.add(record_id)
            protocol = protocol_of(document)
            outcome, evidence, _version_presence, candidate_count = _extraction_details(document, line_number)
            if evidence == "unavailable":
                strength = "unavailable"
            else:
                strength = evidence
            candidate_band = (
                "unavailable" if candidate_count is None else
                "zero" if candidate_count == 0 else
                "single" if candidate_count == 1 else "multiple"
            )
            key = (protocol, outcome, strength, candidate_band)
            buckets.setdefault(key, []).append({
                "record_id": record_id,
                "source_hash": canonical_source_hash(document),
                "raw": document,
                "protocol": protocol,
                "m2_outcome_stratum": outcome,
                "evidence_strength": strength,
                "candidate_count": candidate_count,
                "candidate_count_stratum": candidate_band,
            })
    rng = random.Random(seed)
    for values in buckets.values():
        rng.shuffle(values)
    selected: list[dict[str, Any]] = []
    keys = sorted(buckets)
    while len(selected) < size and any(buckets.values()):
        for key in keys:
            if buckets[key] and len(selected) < size:
                selected.append(buckets[key].pop())
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as output:
        for row in selected:
            output.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return {
        "sample": str(destination), "sample_records": len(selected),
        "valid_source_records": valid, "malformed_json_rows": malformed,
        "non_object_rows": non_object, "duplicate_record_ids": duplicates,
        "seed": seed,
        "protocol_distribution": dict(Counter(row["protocol"] for row in selected)),
        "m2_outcome_distribution": dict(Counter(row["m2_outcome_stratum"] for row in selected)),
        "evidence_strength_distribution": dict(Counter(row["evidence_strength"] for row in selected)),
        "candidate_count_distribution": dict(Counter(row["candidate_count_stratum"] for row in selected)),
    }


def create_annotation_manifest(input_path: str | Path, output_path: str | Path, size: int = 100, seed: int = 20261108) -> dict[str, Any]:
    """Write a reproducible annotation manifest without copying source records."""
    from benchmarks.cpe.src.gold import canonical_source_hash

    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    malformed = non_object = valid = 0
    with Path(input_path).open("rb") as stream:
        for line_no, raw_line in enumerate(stream, 1):
            if not raw_line.strip():
                continue
            try:
                line = raw_line.decode("utf-8")
                document = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                malformed += 1
                continue
            if not isinstance(document, dict):
                non_object += 1
                continue
            valid += 1
            protocol = protocol_of(document)
            outcome = "processing_error"
            candidate_count = 0
            try:
                from app.extractors import EXTRACTORS, extract_candidates
                from app.ingestion.normalizer import normalize
                from app.outcomes import classify
                normalized = normalize(document, line_number=line_no, byte_offset=0)
                candidates = extract_candidates(normalized, EXTRACTORS)
                supported = any(block["protocol"] in EXTRACTORS for block in normalized["port_blocks"])
                outcome = classify(normalized["record_id"], candidates, supported_block_present=supported)["outcome"]
                candidate_count = len(candidates)
            except Exception:
                pass
            count_stratum = "zero" if candidate_count == 0 else "single" if candidate_count == 1 else "multiple"
            key = (protocol, outcome, count_stratum)
            buckets.setdefault(key, []).append({
                "schema_version": "2.0",
                "record_id": stable_id(document, line_no),
                "source_hash": canonical_source_hash(document),
                "protocol": protocol,
                "m2_outcome": outcome,
                "candidate_count": candidate_count,
                "candidate_count_stratum": count_stratum,
            })
    rng = random.Random(seed)
    for values in buckets.values():
        rng.shuffle(values)
    selected: list[dict[str, Any]] = []
    keys = sorted(buckets)
    while len(selected) < max(0, size) and any(buckets.values()):
        for key in keys:
            if buckets[key] and len(selected) < size:
                selected.append(buckets[key].pop())
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as output:
        for row in selected:
            output.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return {"manifest": str(destination), "records": len(selected), "valid_source_records": valid, "malformed_json_rows": malformed, "non_object_rows": non_object, "seed": seed}


def validate_gold(gold: dict[str, Any], dictionary=None) -> list[str]:
    errors = []
    missing = GOLD_REQUIRED - gold.keys()
    if missing:
        errors.append("missing fields: " + ", ".join(sorted(missing)))
    if gold.get("scoring_status") not in {"reviewed", "ambiguous", "excluded", "unreviewed"}:
        errors.append("invalid scoring_status")
    if gold.get("abstain_expected") not in {True, False, None}:
        errors.append("abstain_expected must be boolean or null")
    if not isinstance(gold.get("acceptable_cpes", []), list):
        errors.append("acceptable_cpes must be a list")
    for key in ("expected_product", "expected_vendor", "expected_version", "expected_update", "expected_part", "expected_cpe23"):
        if key in gold and gold[key] is not None and not isinstance(gold[key], str): errors.append(f"{key} must be a string or null")
    if not isinstance(gold.get("evidence_paths", []), list) or any(not isinstance(x, str) for x in gold.get("evidence_paths", [])):
        errors.append("evidence_paths must be an array of strings")
    if not isinstance(gold.get("record_id"), str) or not gold.get("record_id"):
        errors.append("record_id must be a non-empty string")
    cpe_names = [name for name in [gold.get("expected_cpe23"), *(gold.get("acceptable_cpes") or [])] if name]
    if cpe_names and (gold.get("expected_product") is None or not str(gold.get("expected_product")).strip() or gold.get("expected_product") == "*"):
        errors.append("expected_product is required when a CPE identity is supplied")
    for name in cpe_names:
        if name:
            try:
                from app.cpe.parser import parse_cpe23
                parse_cpe23(name)
            except (ValueError, TypeError) as exc:
                errors.append(f"invalid CPE 2.3: {exc}")
                continue
            if dictionary is not None and not dictionary.contains_cpe(name):
                errors.append("CPE is absent from the local dictionary")
            comparison = compare_cpe_identity(name, gold_identity(gold))
            for field, matched in comparison["fields"].items():
                if matched is False:
                    label = "product" if field == "product_name" else field
                    errors.append(f"CPE {label} does not match expected identity")
    return errors


def load_reviewed_gold(path: str | Path, dictionary=None, source_documents=None) -> tuple[dict[str, dict], list[dict]]:
    """Compatibility loader for v1 and v2; v2 mapping status is human Gold, not dictionary membership."""
    from benchmarks.cpe.src.gold import load_gold_annotations
    accepted, rejected = load_gold_annotations(path, source_documents)
    if dictionary is not None:
        for record_id, row in list(accepted.items()):
            if row.get("_source_format") == "v1":
                errors = validate_gold(row, dictionary)
                if errors:
                    rejected.append({"record_id": record_id, "errors": errors})
                    accepted.pop(record_id)
    return accepted, rejected
