"""Local JSONL sampling and gold-label contract validation."""
from __future__ import annotations

import hashlib
import json
import random
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
    # Hash content rather than IP/path to provide a stable, non-reversible identifier.
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "rec-" + hashlib.sha256(canonical.encode()).hexdigest()[:16]


def protocol_of(doc: dict[str, Any]) -> str:
    src = doc.get("_source", {})
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
        return outcome, strength, version_presence
    except Exception:
        return "processing_error", "weak", "without_version"


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


def load_reviewed_gold(path: str | Path, dictionary=None) -> tuple[dict[str, dict], list[dict]]:
    accepted: dict[str, dict] = {}
    rejected: list[dict] = []
    for line_number, row in iter_jsonl(path):
        if not isinstance(row, dict):
            rejected.append({"line": line_number, "errors": ["gold row is not an object"]}); continue
        if row.get("scoring_status") not in {"reviewed", "ambiguous"}:
            continue
        errors = validate_gold(row, dictionary)
        if errors:
            rejected.append({"line": line_number, "record_id": row.get("record_id"), "errors": errors})
        else:
            accepted[row["record_id"]] = row
    return accepted, rejected
