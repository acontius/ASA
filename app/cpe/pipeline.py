"""Stream M2 outcome JSONL into CPE resolution JSONL."""

from __future__ import annotations

import json
from pathlib import Path

from app.cpe.resolver import resolve_candidate
from app.cpe.store import metadata, require_ready


class ResolveError(RuntimeError):
    """Fatal resolver configuration error."""


def resolve_outcomes(input_path: str, output_path: str, db_path: str) -> dict[str, int]:
    source = Path(input_path).resolve()
    target = Path(output_path).resolve()
    if not source.is_file():
        raise ResolveError(f"input not found: {input_path}")
    if source == target:
        raise ResolveError("refusing to overwrite the M2 outcomes file")
    db = require_ready(db_path)
    info = metadata(db)
    public_meta = {
        "schema_version": info.get("schema_version"),
        "source_timestamp": info.get("source_timestamp"),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    stats = {"records": 0, "errors": 0, "candidates": 0}
    try:
        with source.open("r", encoding="utf-8") as incoming, target.open("w", encoding="utf-8") as outgoing:
            for line_number, line in enumerate(incoming, start=1):
                if not line.strip():
                    continue
                record = _one_record(line, line_number, db, public_meta)
                outgoing.write(json.dumps(record, ensure_ascii=False))
                outgoing.write("\n")
                outgoing.flush()
                stats["records"] += 1
                stats["candidates"] += len(record["candidate_resolutions"])
                if record.get("error"):
                    stats["errors"] += 1
    finally:
        db.close()
    return stats


def _one_record(line: str, line_number: int, db, public_meta: dict) -> dict:
    try:
        document = json.loads(line)
    except json.JSONDecodeError as exc:
        return {
            "record_id": None,
            "source_outcome": None,
            "candidate_resolutions": [],
            "dictionary_metadata": public_meta,
            "error": f"invalid JSON: {exc.msg}",
            "line_number": line_number,
        }
    if not isinstance(document, dict):
        return {
            "record_id": None,
            "source_outcome": None,
            "candidate_resolutions": [],
            "dictionary_metadata": public_meta,
            "error": "outcome line is not an object",
            "line_number": line_number,
        }
    candidates = document.get("candidates")
    if not isinstance(candidates, list):
        candidates = []
    return {
        "record_id": document.get("record_id") if isinstance(document.get("record_id"), str) else None,
        "source_outcome": document.get("outcome") if isinstance(document.get("outcome"), str) else None,
        "candidate_resolutions": [resolve_candidate(db, item) for item in candidates],
        "dictionary_metadata": public_meta,
    }
