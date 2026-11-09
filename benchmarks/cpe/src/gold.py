"""Gold Dataset v2 validation, loading, source integrity, and explicit v1 migration."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from app.cpe.parser import parse_cpe23
from benchmarks.cpe.src.dataset import stable_id, validate_gold as validate_gold_v1
from benchmarks.cpe.src.identity import compare_cpe_identity

ANNOTATION_STATES = {"reviewed", "no_software_identity", "ambiguous", "insufficient_evidence", "out_of_scope", "unreviewed"}
MAPPING_STATES = {"mapped", "not_in_dictionary", "ambiguous", "version_unresolved", "unreviewed"}
ADJUDICATION_STATES = {"pending", "reviewed", "disputed", "adjudicated"}
V2_FIELDS = {"schema_version", "record_id", "source_hash", "annotation_status", "expected_identities", "annotation"}
IDENTITY_FIELDS = {"identity_id", "expected_product", "expected_vendor", "expected_version", "expected_update", "expected_part", "cpe_mapping_status", "expected_cpe23", "acceptable_cpes", "evidence_paths", "adjudication_notes"}


def canonical_source_hash(document: Any) -> str:
    content = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def _path_exists(document: Any, path: str) -> bool:
    value = document
    path = path.strip()
    if path.startswith("$"):
        path = path[1:].lstrip(".")
    # The benchmark's existing evidence convention is dotted keys, with optional
    # numeric array indexes (e.g. $.t22.ssh.result.banner or items[0].name).
    pieces: list[str] = []
    token = ""
    i = 0
    while i < len(path):
        char = path[i]
        if char == ".":
            if token:
                pieces.append(token); token = ""
            i += 1
        elif char == "[":
            if token:
                pieces.append(token); token = ""
            end = path.find("]", i + 1)
            if end < 0:
                return False
            raw_index = path[i + 1:end].strip("'\"")
            pieces.append(raw_index); i = end + 1
        else:
            token += char; i += 1
    if token:
        pieces.append(token)
    if not pieces:
        return False
    try:
        for piece in pieces:
            if isinstance(value, dict):
                value = value[piece]
            elif isinstance(value, list) and piece.isdigit():
                value = value[int(piece)]
            else:
                return False
    except (KeyError, IndexError, TypeError):
        return False
    return True


def validate_gold_v2(record: dict, source_document: Any | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["Gold record must be an object"]
    missing = V2_FIELDS - record.keys()
    extra = record.keys() - V2_FIELDS
    if missing:
        errors.append("missing fields: " + ", ".join(sorted(missing)))
    if extra:
        errors.append("unexpected fields: " + ", ".join(sorted(extra)))
    if record.get("schema_version") != "2.0":
        errors.append("schema_version must be '2.0'")
    if not isinstance(record.get("record_id"), str) or not record.get("record_id", "").strip():
        errors.append("record_id must be a non-empty string")
    source_hash = record.get("source_hash")
    if not isinstance(source_hash, str) or len(source_hash) != 64 or any(c not in "0123456789abcdef" for c in source_hash):
        errors.append("source_hash must be a lowercase SHA-256 hex digest")
    elif source_document is not None and canonical_source_hash(source_document) != source_hash:
        errors.append("source_hash does not match the current source record")
    status = record.get("annotation_status")
    if status not in ANNOTATION_STATES:
        errors.append("invalid annotation_status")
    identities = record.get("expected_identities")
    if not isinstance(identities, list):
        errors.append("expected_identities must be an array")
        identities = []
    if status == "reviewed" and not identities:
        errors.append("reviewed records require at least one expected identity; use no_software_identity for confirmed negatives")
    if status == "no_software_identity" and identities:
        errors.append("no_software_identity records must have an empty expected_identities array")
    if status in {"insufficient_evidence", "out_of_scope"} and identities:
        errors.append(f"{status} records must have an empty expected_identities array")
    seen_ids: set[str] = set()
    for index, identity in enumerate(identities):
        prefix = f"expected_identities[{index}]"
        if not isinstance(identity, dict):
            errors.append(prefix + " must be an object")
            continue
        identity_missing = IDENTITY_FIELDS - identity.keys()
        identity_extra = identity.keys() - IDENTITY_FIELDS
        if identity_missing:
            errors.append(prefix + " missing fields: " + ", ".join(sorted(identity_missing)))
        if identity_extra:
            errors.append(prefix + " unexpected fields: " + ", ".join(sorted(identity_extra)))
        identity_id = identity.get("identity_id")
        if not isinstance(identity_id, str) or not identity_id.strip():
            errors.append(prefix + " identity_id must be a non-empty string")
        elif identity_id in seen_ids:
            errors.append(prefix + " identity_id must be unique within the record")
        else:
            seen_ids.add(identity_id)
        product = identity.get("expected_product")
        if not isinstance(product, str) or not product.strip() or product.strip() in {"*", "-"}:
            errors.append(prefix + " expected_product must be a concrete non-empty product")
        for key in ("expected_vendor", "expected_version", "expected_update", "expected_part", "expected_cpe23"):
            if identity.get(key) is not None and not isinstance(identity.get(key), str):
                errors.append(prefix + f" {key} must be a string or null")
            elif identity.get(key) is not None and not identity[key].strip():
                errors.append(prefix + f" {key} must be null when unknown, not an empty string")
        part = identity.get("expected_part")
        if isinstance(part, str) and part.strip().casefold() not in {"a", "o", "h", "*", "-"}:
            errors.append(prefix + " expected_part must be a, o, h, *, -, or null")
        mapping = identity.get("cpe_mapping_status")
        if mapping not in MAPPING_STATES:
            errors.append(prefix + " invalid cpe_mapping_status")
        acceptable = identity.get("acceptable_cpes")
        if not isinstance(acceptable, list) or any(not isinstance(name, str) for name in acceptable):
            errors.append(prefix + " acceptable_cpes must be an array of strings")
            acceptable = []
        evidence = identity.get("evidence_paths")
        if not isinstance(evidence, list) or not evidence or any(not isinstance(path, str) or not path.strip() for path in evidence):
            errors.append(prefix + " evidence_paths must contain at least one non-empty path")
            evidence = []
        elif source_document is not None:
            for path in evidence:
                if not _path_exists(source_document, path):
                    errors.append(prefix + f" evidence path does not exist in source: {path}")
        if not isinstance(identity.get("adjudication_notes"), str):
            errors.append(prefix + " adjudication_notes must be a string")
        primary = identity.get("expected_cpe23")
        names = ([primary] if primary else []) + acceptable
        for name in names:
            try:
                parse_cpe23(name)
            except (ValueError, TypeError) as exc:
                errors.append(prefix + f" invalid CPE 2.3: {exc}")
                continue
            identity_comparison = compare_cpe_identity(name, {
                "product_name": product,
                "vendor": identity.get("expected_vendor"),
                "version": identity.get("expected_version"),
                "update": identity.get("expected_update"),
                "part": identity.get("expected_part"),
            })
            for field, matched in identity_comparison["fields"].items():
                if matched is False:
                    errors.append(prefix + f" CPE {field} does not match expected identity")
        if mapping == "mapped" and not primary:
            errors.append(prefix + " mapped status requires expected_cpe23")
        if mapping in {"not_in_dictionary", "version_unresolved", "unreviewed"} and names:
            errors.append(prefix + f" {mapping} status cannot carry expected or acceptable CPE values")
        if mapping == "ambiguous" and primary:
            errors.append(prefix + " ambiguous mapping cannot have one primary expected_cpe23")
    annotation = record.get("annotation")
    if not isinstance(annotation, dict):
        errors.append("annotation must be an object")
    else:
        required = {"annotator_id", "reviewed_at", "adjudication_status", "reviewer_id", "notes"}
        if required - annotation.keys():
            errors.append("annotation missing fields: " + ", ".join(sorted(required - annotation.keys())))
        if annotation.keys() - required:
            errors.append("annotation has unexpected fields: " + ", ".join(sorted(annotation.keys() - required)))
        if not isinstance(annotation.get("annotator_id"), str):
            errors.append("annotation.annotator_id must be a string")
        elif record.get("annotation_status") in {"reviewed", "no_software_identity"} and not annotation["annotator_id"].strip():
            errors.append("annotation.annotator_id is required for reviewed records")
        if annotation.get("reviewed_at") is not None and not isinstance(annotation.get("reviewed_at"), str):
            errors.append("annotation.reviewed_at must be a string or null")
        if annotation.get("adjudication_status") not in ADJUDICATION_STATES:
            errors.append("invalid annotation.adjudication_status")
        elif record.get("annotation_status") == "no_software_identity" and annotation["adjudication_status"] not in {"reviewed", "adjudicated"}:
            errors.append("no_software_identity requires a deliberate reviewed or adjudicated decision")
        if annotation.get("reviewer_id") is not None and not isinstance(annotation.get("reviewer_id"), str):
            errors.append("annotation.reviewer_id must be a string or null")
        if not isinstance(annotation.get("notes"), str):
            errors.append("annotation.notes must be a string")
    return errors


def migrate_v1_record(old: dict, source_document: dict, record_id: str | None = None) -> dict:
    """Explicitly carry v1 fields forward as unreviewed; never infer a negative."""
    identity = None
    if isinstance(old.get("expected_product"), str) and old["expected_product"].strip():
        primary = old.get("expected_cpe23")
        acceptable = list(old.get("acceptable_cpes", []))
        identity = {
            "identity_id": f"{record_id or old['record_id']}-1",
            "expected_product": old["expected_product"],
            "expected_vendor": old.get("expected_vendor"),
            "expected_version": old.get("expected_version"),
            "expected_update": old.get("expected_update"),
            "expected_part": old.get("expected_part"),
            "cpe_mapping_status": "mapped" if primary else "ambiguous" if acceptable else "unreviewed",
            "expected_cpe23": primary,
            "acceptable_cpes": acceptable,
            "evidence_paths": list(old.get("evidence_paths", [])),
            "adjudication_notes": old.get("adjudication_notes", ""),
        }
    return {
        "schema_version": "2.0",
        "record_id": record_id or old["record_id"],
        "source_hash": canonical_source_hash(source_document),
        "annotation_status": "unreviewed",
        "expected_identities": [identity] if identity else [],
        "annotation": {
            "annotator_id": "",
            "reviewed_at": None,
            "adjudication_status": "pending",
            "reviewer_id": None,
            "notes": "Migrated from Gold v1; review the status and identity before scoring.",
        },
    }


def load_gold_annotations(path: str | Path, source_documents: dict[str, Any] | None = None) -> tuple[dict[str, dict], list[dict]]:
    """Load v2 and explicitly tagged v1 rows; report malformed, stale, or invalid rows."""
    accepted: dict[str, dict] = {}
    rejected: list[dict] = []
    source_documents = source_documents or {}
    try:
        stream = Path(path).open(encoding="utf-8")
    except FileNotFoundError:
        return accepted, rejected
    with stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                rejected.append({"line": line_number, "errors": [f"invalid JSON: {exc.msg}"]}); continue
            if not isinstance(row, dict):
                rejected.append({"line": line_number, "errors": ["Gold row must be an object"]}); continue
            record_id = row.get("record_id")
            if not isinstance(record_id, str) or not record_id:
                rejected.append({"line": line_number, "errors": ["record_id must be a non-empty string"]}); continue
            if record_id in accepted:
                rejected.append({"line": line_number, "record_id": record_id, "errors": ["duplicate record_id"]}); continue
            if row.get("schema_version") == "2.0":
                errors = validate_gold_v2(row, source_documents.get(record_id))
                if errors:
                    rejected.append({"line": line_number, "record_id": record_id, "errors": errors})
                else:
                    accepted[record_id] = row
            elif "schema_version" not in row:
                errors = validate_gold_v1(row)
                if errors:
                    rejected.append({"line": line_number, "record_id": record_id, "errors": errors})
                else:
                    # Kept visibly tagged. Metrics apply legacy v1 semantics only
                    # to explicit identity/CPE labels; v1 abstentions are not negatives.
                    accepted[record_id] = {**row, "_source_format": "v1"}
            else:
                rejected.append({"line": line_number, "record_id": record_id, "errors": [f"unsupported schema_version: {row.get('schema_version')}"]})
    return accepted, rejected


def migrate_v1_file(source_gold: str | Path, destination: str | Path, source_input: str | Path) -> int:
    """Migrate v1 Gold to a new file, leaving source untouched; migrated rows require review."""
    source_gold, destination, source_input = Path(source_gold), Path(destination), Path(source_input)
    if source_gold.resolve() == destination.resolve():
        raise ValueError("migration destination must differ from source Gold file")
    if destination.exists():
        raise FileExistsError(destination)
    source_index: dict[str, tuple[dict, str]] = {}
    with source_input.open(encoding="utf-8") as source_stream:
        for line_number, line in enumerate(source_stream, 1):
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(document, dict):
                continue
            current_id = stable_id(document, line_number)
            source_index[current_id] = (document, current_id)
            legacy_hash_id = "rec-" + hashlib.sha256(
                json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest()[:16]
            source_index[legacy_hash_id] = (document, current_id)
            inner = document.get("_source", document)
            for candidate in (document.get("_id"), inner.get("id")):
                if candidate is not None:
                    source_index[str(candidate)] = (document, current_id)
    migrated: list[dict] = []
    with source_gold.open(encoding="utf-8") as gold_stream:
        for line_number, line in enumerate(gold_stream, 1):
            if not line.strip():
                continue
            try:
                old = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid v1 JSON at line {line_number}: {exc.msg}") from exc
            if not isinstance(old, dict) or "schema_version" in old:
                raise ValueError(f"line {line_number} is not an unversioned Gold v1 record")
            errors = validate_gold_v1(old)
            if errors:
                raise ValueError(f"invalid v1 row at line {line_number}: {'; '.join(errors)}")
            source_entry = source_index.get(old["record_id"])
            if source_entry is None:
                raise ValueError(f"source record not found for {old['record_id']}")
            document, current_id = source_entry
            migrated.append(migrate_v1_record(old, document, current_id))
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".gold-v2-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            for row in migrated:
                out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            out.flush(); os.fsync(out.fileno())
        os.link(temp_name, destination)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
    return len(migrated)
