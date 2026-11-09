"""Streaming pipeline: read → normalize → extract → classify → append outcome."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, TextIO

from schemas.models import SUPPORTED_PROTOCOLS, ProcessingOutcome

from app.extractors import EXTRACTORS, extract_candidates
from app.ingestion.checkpoint import Checkpoint, load_checkpoint, save_checkpoint
from app.ingestion.normalizer import NormalizationError, normalize
from app.ingestion.reader import JsonlItem, iter_jsonl_records
from app.outcomes import classify


class PipelineError(RuntimeError):
    """Fatal configuration or invocation error."""


def run_pipeline(
    input_path: str,
    output_path: str,
    checkpoint_path: str | None = None,
    *,
    resume: bool = False,
) -> dict[str, int]:
    """Process JSONL incrementally.

    Outcomes are appended one JSON object per line. When ``resume`` is set and
    a checkpoint exists, reading starts at ``next_offset``. The output file is
    opened for append so previously written lines are kept.
    """
    in_path = Path(input_path).resolve()
    out_path = Path(output_path).resolve()
    if not in_path.is_file():
        raise PipelineError(f"input not found: {input_path}")
    if in_path == out_path:
        raise PipelineError("refusing to overwrite the input dataset with output")
    if checkpoint_path and Path(checkpoint_path).resolve() == in_path:
        raise PipelineError("checkpoint path must not be the input dataset")

    start_offset = 0
    completed = 0
    if resume:
        if not checkpoint_path:
            raise PipelineError("--resume requires a checkpoint path")
        ckpt = load_checkpoint(checkpoint_path, input_size=in_path.stat().st_size)
        start_offset = ckpt.next_offset
        completed = ckpt.records_completed

    out_path.parent.mkdir(parents=True, exist_ok=True)
    stats = {"processed": 0, "errors": 0, "skipped_blank": 0}
    mode = "a" if resume and out_path.exists() else "w"
    with out_path.open(mode, encoding="utf-8") as handle:
        for item in iter_jsonl_records(str(in_path), start_offset=start_offset):
            if item.document is None and item.error is None:
                stats["skipped_blank"] += 1
                _checkpoint(checkpoint_path, item.next_offset, completed)
                continue
            outcome = process_m2_item(item)
            handle.write(json.dumps(outcome, ensure_ascii=False))
            handle.write("\n")
            handle.flush()
            completed += 1
            stats["processed"] += 1
            if outcome["outcome"] == "processing_error":
                stats["errors"] += 1
            _checkpoint(checkpoint_path, item.next_offset, completed)
    return stats


def _checkpoint(path: str | None, next_offset: int, completed: int) -> None:
    if not path:
        return
    save_checkpoint(path, Checkpoint(next_offset=next_offset, records_completed=completed))


def process_m2_item(item: JsonlItem) -> ProcessingOutcome:
    """Run the authoritative M1 normalization and M2 extraction for one item.

    The online NVD pipeline reuses this exact boundary so it cannot diverge
    from the legacy streaming M2 behavior.
    """
    if item.error or item.document is None:
        return classify(
            f"line-{item.line_number}",
            [],
            supported_block_present=False,
            error=item.error or "empty document",
        )
    try:
        record = normalize(item.document, line_number=item.line_number, byte_offset=item.byte_offset)
    except NormalizationError as exc:
        return classify(
            f"line-{item.line_number}",
            [],
            supported_block_present=False,
            error=str(exc),
        )
    supported = any(block["protocol"] in SUPPORTED_PROTOCOLS for block in record["port_blocks"])
    if not supported and record["declared_proto"] in SUPPORTED_PROTOCOLS:
        # Declared protocol is in scope but no parseable block was found.
        supported = True
    candidates = extract_candidates(record, EXTRACTORS) if supported else []
    outcome = classify(
        record["record_id"],
        candidates,
        supported_block_present=supported,
    )
    outcome["notes"] = _with_provenance(outcome.get("notes"), record)
    return outcome


def _with_provenance(notes: str | None, record: dict[str, Any]) -> str:
    marker = f"source_path={record['source_path']};scan_time={record['scan_time']}"
    if notes:
        return f"{notes};{marker}"
    return marker


def outcome_to_json(outcome: ProcessingOutcome, handle: TextIO) -> None:
    handle.write(json.dumps(outcome))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
