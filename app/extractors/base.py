"""Shared extractor helpers and protocol dispatch."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, Iterable

from schemas.models import ExtractionCandidate, NormalizedRecord, PortBlock

Extractor = Callable[[NormalizedRecord, PortBlock], list[ExtractionCandidate]]

_VERSION_TAIL = re.compile(
    r"^(?P<name>[A-Za-z][A-Za-z0-9._+-]*?)[_/\s-](?P<ver>\d+(?:\.\d+)*(?:p\d+)?)\b"
)


def stable_id(*parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:12]
    return digest


def candidate(
    record: NormalizedRecord,
    *,
    product_name: str,
    raw_value: str,
    source_path: str,
    signal_type: str,
    extractor_id: str,
    evidence_strength: str,
    version: str | None = None,
    evidence_refs: Iterable[str] | None = None,
) -> ExtractionCandidate:
    refs = list(evidence_refs or [])
    return {
        "candidate_id": stable_id(record["record_id"], source_path, raw_value, product_name),
        "product_name": product_name,
        "vendor": None,
        "version": version,
        "update": None,
        "part": None,
        "source_path": source_path,
        "raw_value": raw_value,
        "signal_type": signal_type,  # type: ignore[typeddict-item]
        "extractor_id": extractor_id,
        "evidence_strength": evidence_strength,  # type: ignore[typeddict-item]
        "evidence_refs": refs,
        "normalized_record_id": record["record_id"],
    }


def split_product_version(text: str) -> tuple[str, str] | None:
    """Split 'OpenSSH_9.6p1' or 'nginx/1.24.0' into (product, version)."""
    match = _VERSION_TAIL.match(text.strip())
    if not match:
        return None
    return match.group("name"), match.group("ver")


def result_of(block: PortBlock) -> dict[str, Any]:
    raw = block.get("raw_block") or {}
    if not isinstance(raw, dict):
        return {}
    result = raw.get("result")
    return result if isinstance(result, dict) else {}


def block_path(block: PortBlock, *tail: str) -> str:
    parts = [block["port_key"], block["protocol"], *tail]
    return ".".join(parts)


def extract_candidates(record: NormalizedRecord, registry: dict[str, Extractor]) -> list[ExtractionCandidate]:
    found: list[ExtractionCandidate] = []
    seen: set[str] = set()
    for block in record["port_blocks"]:
        extractor = registry.get(block["protocol"])
        if extractor is None:
            continue
        for item in extractor(record, block):
            if item["candidate_id"] in seen:
                continue
            seen.add(item["candidate_id"])
            found.append(item)
    return found
