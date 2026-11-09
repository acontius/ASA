"""Prepare a private, prediction-blind extraction Gold review pilot."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Iterator

from benchmarks.cpe.src.dataset import create_annotation_manifest, iter_jsonl, protocol_of, stable_id
from benchmarks.cpe.src.gold import _path_exists, canonical_source_hash, load_gold_annotations

BASE = Path(__file__).resolve().parents[1]
LOCAL_ROOT = BASE / "data" / "local"
SCHEMA_VERSION = "extraction-gold-v1-review-manifest"
EVIDENCE_KEYS = {
    "software", "product", "product_name", "version", "version_string",
    "server", "server_id", "banner", "build_info", "product_version",
}


class SourceFormatError(ValueError):
    """The input is not a stream of complete JSON objects."""


def iter_json_documents(path: str | Path, chunk_size: int = 65536) -> Iterator[dict]:
    """Decode concatenated JSON objects, including pretty-printed documents.

    PartOfMe.json is a whitespace-separated stream of JSON objects, not strict
    JSONL. This reader accepts that format and fails closed on malformed input.
    It buffers at most one document plus one read chunk at a time.
    """
    decoder = json.JSONDecoder()
    buffer = ""
    eof = False
    document_number = 0
    with Path(path).open("r", encoding="utf-8") as stream:
        while True:
            buffer = buffer.lstrip()
            if not buffer and not eof:
                buffer = stream.read(chunk_size)
                if not buffer:
                    eof = True
                    continue
            if not buffer and eof:
                return
            try:
                value, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError as exc:
                if not eof:
                    more = stream.read(chunk_size)
                    if more:
                        buffer += more
                        continue
                    eof = True
                    continue
                raise SourceFormatError(
                    f"invalid concatenated JSON near document {document_number + 1}"
                ) from exc
            if not isinstance(value, dict):
                raise SourceFormatError(
                    f"document {document_number + 1} is {type(value).__name__}, expected object"
                )
            document_number += 1
            yield value
            buffer = buffer[end:]


def _evidence_refs(document: dict) -> list[dict[str, str]]:
    refs: set[tuple[str, str]] = set()

    def walk(value, path: str, depth: int = 0) -> None:
        if depth > 24:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                if str(key).lower() in EVIDENCE_KEYS and not isinstance(child, (dict, list)):
                    if child is not None and str(child).strip():
                        refs.add((str(key).lower(), child_path))
                elif str(key).lower() in EVIDENCE_KEYS and isinstance(child, list):
                    for index, item in enumerate(child):
                        if not isinstance(item, (dict, list)) and item is not None and str(item).strip():
                            refs.add((str(key).lower(), f"{child_path}[{index}]"))
                walk(child, child_path, depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]", depth + 1)

    walk(document, "")
    return [
        {"field": field, "path": path, "source_observation": "directly_supported_by_source",
         "identity_interpretation": "requires_human_review"}
        for field, path in sorted(refs)
    ]


def _field_review_hints(refs: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    fields = {row["field"] for row in refs}
    product_evidence = bool(fields & {"software", "product", "product_name", "server", "server_id", "banner", "build_info", "product_version"})
    version_evidence = bool(fields & {"version", "version_string", "software", "server", "banner", "product_version"})
    hints = {}
    for field, present in (("product", product_evidence), ("vendor", "vendor" in fields),
                           ("version", version_evidence), ("update", "update" in fields),
                           ("part", "part" in fields)):
        hints[field] = {
            "source_observation": "directly_supported_by_source" if present else "absent_from_source_evidence",
            "identity_interpretation": "requires_human_review" if present else "unknown_insufficient_evidence",
        }
    return hints


def _gold_shell(record_id: str, source_hash: str) -> dict:
    """Create an unreviewed v2 shell; it contains no generated labels."""
    return {
        "schema_version": "2.0",
        "record_id": record_id,
        "source_hash": source_hash,
        "annotation_status": "unreviewed",
        "expected_identities": [],
        "annotation": {
            "annotator_id": "",
            "reviewed_at": None,
            "adjudication_status": "pending",
            "reviewer_id": None,
            "notes": "Awaiting independent human identity review; no Gold labels generated.",
        },
    }


def _write_jsonl(path: Path, rows) -> None:
    with path.open("x", encoding="utf-8") as output:
        for row in rows:
            output.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def prepare(input_path: str | Path, output_dir: str | Path, size: int = 100, seed: int = 20261124) -> dict:
    if not 1 <= size <= 10000:
        raise ValueError("size must be between 1 and 10000")
    source = Path(input_path).resolve(strict=True)
    destination = Path(output_dir).resolve()
    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=".partofme-gold-", dir=destination.parent))
    committed = False
    try:
        canonical = temp_dir / "canonical-source.jsonl"
        doc_count = 0
        source_id_counts: Counter[str] = Counter()
        protocols: Counter[str] = Counter()
        endpoint_counts: Counter[tuple[str, str, str]] = Counter()
        exact_hashes: Counter[str] = Counter()
        with canonical.open("x", encoding="utf-8") as output:
            for document in iter_json_documents(source):
                doc_count += 1
                source_obj = document.get("_source") if isinstance(document.get("_source"), dict) else {}
                source_key = source_obj.get("id", document.get("_id"))
                if source_key is not None:
                    source_id_counts[str(source_key)] += 1
                protocol = str(source_obj.get("proto", "other")).strip().lower() or "other"
                protocols[protocol] += 1
                # Hash the host token before using it as a private aggregation key.
                host_hash = hashlib.sha256(str(source_obj.get("ip", "")).encode()).hexdigest()
                endpoint_counts[(host_hash, protocol, str(source_obj.get("port", "")))] += 1
                exact_hashes[canonical_source_hash(document)] += 1
                output.write(json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        duplicate_source_ids = sum(count - 1 for count in source_id_counts.values() if count > 1)
        if duplicate_source_ids:
            raise SourceFormatError(f"source identity collision count: {duplicate_source_ids}; refusing ambiguous sampling")

        selected_manifest_path = temp_dir / "selected-manifest.jsonl"
        sample_info = create_annotation_manifest(canonical, selected_manifest_path, size=size, seed=seed)
        selected = [json.loads(line) for line in selected_manifest_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        selected_ids = {row["record_id"] for row in selected}
        if len(selected_ids) != len(selected):
            raise SourceFormatError("sampler produced duplicate record IDs")

        sample_source = temp_dir / "source.jsonl"
        manifest_path = temp_dir / "manifest.jsonl"
        gold_path = temp_dir / "gold.jsonl"
        metadata_path = temp_dir / "dataset.json"
        sample_source_rows = []
        manifest_rows = []
        gold_rows = []
        found_ids: set[str] = set()
        for line_no, document in iter_jsonl(canonical):
            record_id = stable_id(document, line_no)
            if record_id not in selected_ids:
                continue
            if record_id in found_ids:
                raise SourceFormatError("duplicate stable record ID in source")
            found_ids.add(record_id)
            source_hash = canonical_source_hash(document)
            selected_meta = next(row for row in selected if row["record_id"] == record_id)
            evidence_refs = _evidence_refs(document)
            sample_source_rows.append(document)
            manifest_rows.append({
                "schema_version": SCHEMA_VERSION,
                "record_id": record_id,
                "source_hash": source_hash,
                "protocol": selected_meta["protocol"],
                "sampling_seed": seed,
                "sampling_stratum": {
                    "m2_outcome": selected_meta["m2_outcome"],
                    "candidate_count": selected_meta["candidate_count"],
                    "candidate_count_stratum": selected_meta["candidate_count_stratum"],
                },
                "source_evidence_refs": evidence_refs,
                "field_review_hints": _field_review_hints(evidence_refs),
                "annotation_status": "unreviewed",
                "gold_label_generated": False,
            })
            gold_rows.append(_gold_shell(record_id, source_hash))
        if found_ids != selected_ids:
            raise SourceFormatError("sampler manifest references source records that could not be recovered")

        _write_jsonl(sample_source, sample_source_rows)
        _write_jsonl(manifest_path, manifest_rows)
        _write_jsonl(gold_path, gold_rows)
        metadata = {
            "dataset_release": "PartOfMe-extraction-gold-v1-pilot",
            "gold_contract": "ASA Gold v2.0; all generated rows are unreviewed shells",
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "source_format": "whitespace-separated JSON object stream, canonicalized to JSONL for existing tooling",
            "source_records": doc_count,
            "malformed_source_documents": 0,
            "duplicate_source_ids": duplicate_source_ids,
            "duplicate_exact_records": sum(n - 1 for n in exact_hashes.values() if n > 1),
            "duplicate_host_protocol_port_keys": sum(n - 1 for n in endpoint_counts.values() if n > 1),
            "protocol_counts": dict(sorted(protocols.items())),
            "sample_records": len(sample_source_rows),
            "sample_seed": seed,
            "sampling": "existing Gold manifest sampler; M2 is used only for structural strata, never as a Gold label",
            "sampling_malformed_rows": sample_info["malformed_json_rows"],
            "sampling_non_object_rows": sample_info["non_object_rows"],
            "sample_m2_candidate_identities": sum(row["sampling_stratum"]["candidate_count"] for row in manifest_rows),
            "sample_m2_outcome_counts": dict(sorted(Counter(row["sampling_stratum"]["m2_outcome"] for row in manifest_rows).items())),
            "sample_candidate_count_strata": dict(sorted(Counter(row["sampling_stratum"]["candidate_count_stratum"] for row in manifest_rows).items())),
            "sample_source_evidence_records": sum(bool(row["source_evidence_refs"]) for row in manifest_rows),
            "sample_source_evidence_reference_count": sum(len(row["source_evidence_refs"]) for row in manifest_rows),
            "sample_field_review_hint_counts": {
                field: dict(sorted(Counter(
                    row["field_review_hints"][field]["identity_interpretation"] for row in manifest_rows
                ).items()))
                for field in ("product", "vendor", "version", "update", "part")
            },
            "reviewed_records": 0,
            "scorable_records": 0,
            "cpe_gold_identities": 0,
            "evaluation_metrics": None,
        }
        metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        canonical.unlink()
        selected_manifest_path.unlink()
        if destination.exists():
            raise FileExistsError(destination)
        os.rename(temp_dir, destination)
        committed = True
        return {**metadata, "output_dir": str(destination)}
    finally:
        if not committed:
            shutil.rmtree(temp_dir, ignore_errors=True)


def validate(output_dir: str | Path) -> dict:
    directory = Path(output_dir).resolve(strict=True)
    source_path = directory / "source.jsonl"
    manifest_path = directory / "manifest.jsonl"
    gold_path = directory / "gold.jsonl"
    source_by_id = {}
    for line_no, document in iter_jsonl(source_path):
        record_id = stable_id(document, line_no)
        if record_id in source_by_id:
            raise ValueError("duplicate source record ID")
        source_by_id[record_id] = document
    manifest = [json.loads(line) for line in manifest_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if any(not isinstance(row, dict) for row in manifest):
        raise ValueError("manifest rows must be JSON objects")
    manifest_by_id = {row.get("record_id"): row for row in manifest}
    if len(manifest_by_id) != len(manifest):
        raise ValueError("duplicate manifest record ID")
    manifest_fields = {
        "schema_version", "record_id", "source_hash", "protocol", "sampling_seed",
        "sampling_stratum", "source_evidence_refs", "field_review_hints",
        "annotation_status", "gold_label_generated",
    }
    for line_no, row in enumerate(manifest, 1):
        if not isinstance(row, dict) or set(row) != manifest_fields:
            raise ValueError(f"manifest row {line_no} has missing or unexpected fields")
        if row.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"manifest row {line_no} has unsupported schema version")
        record_id = row.get("record_id")
        if record_id not in source_by_id:
            raise ValueError(f"manifest row {line_no} references an unknown record")
        if (not isinstance(record_id, str) or not record_id
                or not isinstance(row.get("source_hash"), str) or len(row["source_hash"]) != 64
                or any(char not in "0123456789abcdef" for char in row["source_hash"])
                or not isinstance(row.get("protocol"), str) or not row["protocol"].strip()
                or not isinstance(row.get("sampling_seed"), int) or isinstance(row.get("sampling_seed"), bool)):
            raise ValueError(f"manifest row {line_no} has malformed identifiers or metadata")
        document = source_by_id[record_id]
        if row.get("schema_version") != SCHEMA_VERSION or row.get("source_hash") != canonical_source_hash(document):
            raise ValueError(f"manifest row {line_no} has unsupported schema or stale source hash")
        if row.get("annotation_status") != "unreviewed" or row.get("gold_label_generated") is not False:
            raise ValueError(f"manifest row {line_no} must remain a prediction-blind unreviewed case")
        stratum = row.get("sampling_stratum")
        if (not isinstance(stratum, dict) or set(stratum) != {"m2_outcome", "candidate_count", "candidate_count_stratum"}
                or not isinstance(stratum.get("candidate_count"), int) or isinstance(stratum.get("candidate_count"), bool)
                or stratum.get("candidate_count_stratum") not in {"zero", "single", "multiple"}):
            raise ValueError(f"manifest row {line_no} has invalid M2 sampling stratum")
        count = stratum["candidate_count"]
        expected_band = "zero" if count == 0 else "single" if count == 1 else "multiple"
        if stratum["candidate_count_stratum"] != expected_band:
            raise ValueError(f"manifest row {line_no} candidate-count band is inconsistent")
        hints = row.get("field_review_hints")
        if not isinstance(hints, dict) or set(hints) != {"product", "vendor", "version", "update", "part"}:
            raise ValueError(f"manifest row {line_no} has invalid field review hints")
        for field_hint in hints.values():
            if (not isinstance(field_hint, dict) or set(field_hint) != {"source_observation", "identity_interpretation"}
                    or field_hint.get("source_observation") not in {"directly_supported_by_source", "absent_from_source_evidence"}
                    or field_hint.get("identity_interpretation") not in {"requires_human_review", "unknown_insufficient_evidence"}):
                raise ValueError(f"manifest row {line_no} has malformed field review hint")
            expected_claim = (
                "requires_human_review" if field_hint["source_observation"] == "directly_supported_by_source"
                else "unknown_insufficient_evidence"
            )
            if field_hint["identity_interpretation"] != expected_claim:
                raise ValueError(f"manifest row {line_no} overstates an unsupported identity field")
        refs = row.get("source_evidence_refs")
        if not isinstance(refs, list):
            raise ValueError(f"manifest row {line_no} has malformed evidence references")
        for ref in refs:
            if (not isinstance(ref, dict) or set(ref) != {"field", "path", "source_observation", "identity_interpretation"}
                    or ref.get("source_observation") != "directly_supported_by_source"
                    or ref.get("identity_interpretation") != "requires_human_review"
                    or not isinstance(ref.get("path"), str) or not _path_exists(document, ref["path"])):
                raise ValueError(f"manifest row {line_no} has invalid or stale evidence path")
    gold_by_id, rejected = load_gold_annotations(gold_path, source_by_id)
    if rejected:
        raise ValueError(f"Gold validation rejected {len(rejected)} rows")
    if set(source_by_id) != set(manifest_by_id) or set(source_by_id) != set(gold_by_id):
        raise ValueError("source, manifest, and Gold record IDs differ")
    stale = 0
    status_counts = Counter(row.get("annotation_status") for row in gold_by_id.values())
    scorable = sum(
        row.get("annotation_status") in {"reviewed", "no_software_identity"}
        and row.get("annotation", {}).get("adjudication_status") in {"reviewed", "adjudicated"}
        for row in gold_by_id.values()
    )
    identities = [identity for row in gold_by_id.values() for identity in row.get("expected_identities", [])]
    return {
        "source_records": len(source_by_id), "manifest_records": len(manifest),
        "gold_records": len(gold_by_id), "valid_rows": len(gold_by_id),
        "invalid_rows": 0, "stale_source_hashes": stale,
        "annotation_status_counts": dict(sorted(status_counts.items())),
        "scorable_records": scorable, "identity_count": len(identities),
        "cpe_mapping_status_counts": dict(sorted(Counter(i.get("cpe_mapping_status") for i in identities).items())),
    }


def evaluate_pilot(output_dir: str | Path, output_path: str | Path | None = None) -> dict:
    """Run existing M2 predictions through existing metrics against reviewed Gold only."""
    from app.extractors import EXTRACTORS, extract_candidates
    from app.ingestion.normalizer import normalize
    from benchmarks.cpe.src.metrics import evaluate as evaluate_gold

    directory = Path(output_dir).resolve(strict=True)
    source_path, gold_path = directory / "source.jsonl", directory / "gold.jsonl"
    source_docs = {}
    prediction_rows = []
    protocol_counts: Counter[str] = Counter()
    candidate_counts: Counter[str] = Counter()
    extraction_errors: Counter[str] = Counter()
    for line_no, document in iter_jsonl(source_path):
        record_id = stable_id(document, line_no)
        source_docs[record_id] = document
        protocol = protocol_of(document)
        protocol_counts[protocol] += 1
        try:
            normalized = normalize(document, line_number=line_no, byte_offset=0)
            predictions = extract_candidates(normalized, EXTRACTORS)
        except Exception as exc:
            predictions = []
            extraction_errors[type(exc).__name__] += 1
        candidate_counts[protocol] += len(predictions)
        prediction_rows.append({
            "record_id": record_id,
            "protocol": protocol,
            "extraction_predictions": predictions,
            "final_cpe_resolutions": [],
        })
    gold, rejected = load_gold_annotations(gold_path, source_docs)
    if rejected:
        raise ValueError(f"Gold validation rejected {len(rejected)} rows")
    metrics = evaluate_gold(prediction_rows, gold)
    result = {
        "evaluation": "M2 extraction predictions against independently reviewed Gold v2 only",
        "gold_labels_generated": False,
        "source_records": len(prediction_rows),
        "m2_candidate_identities": sum(candidate_counts.values()),
        "m2_candidate_records_by_protocol": dict(sorted(protocol_counts.items())),
        "m2_candidate_identities_by_protocol": dict(sorted(candidate_counts.items())),
        "m2_record_errors": sum(extraction_errors.values()),
        "m2_record_error_types": dict(sorted(extraction_errors.items())),
        "scorable_gold_records": metrics["scored_records"],
        "unreviewed_gold_records": metrics["gold_status_counts"].get("unreviewed", 0),
        "extraction_metrics": metrics["evaluation_tracks"]["extraction_only"],
        "cpe_metrics": metrics["evaluation_tracks"]["end_to_end_cpe"],
        "accuracy_available": metrics["scored_records"] > 0,
        "note": "No independent extraction or CPE accuracy is available until human review is complete.",
    }
    if output_path is not None:
        target = Path(output_path)
        with target.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--input", required=True)
    prepare_parser.add_argument("--output-dir", required=True, help="must be a new directory under benchmarks/cpe/data/local")
    prepare_parser.add_argument("--size", type=int, default=100)
    prepare_parser.add_argument("--seed", type=int, default=20261124)
    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--output-dir", required=True)
    evaluate_parser = sub.add_parser("evaluate")
    evaluate_parser.add_argument("--output-dir", required=True)
    evaluate_parser.add_argument("--output")
    args = parser.parse_args()
    output_dir = Path(args.output_dir).resolve()
    if not output_dir.is_relative_to(LOCAL_ROOT.resolve()):
        parser.error("private pilot outputs must stay under benchmarks/cpe/data/local")
    try:
        if args.command == "prepare":
            result = prepare(args.input, output_dir, args.size, args.seed)
        elif args.command == "validate":
            result = validate(output_dir)
        else:
            target = Path(args.output).resolve() if args.output else output_dir / "evaluation.json"
            if not target.is_relative_to(output_dir):
                parser.error("evaluation output must stay inside the local pilot directory")
            result = evaluate_pilot(output_dir, target)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
