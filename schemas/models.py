"""M1 contract models — lightweight TypedDicts for validation and type hints.

No external dependencies. Suitable for both runtime checks and static analysis.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

try:
    from typing import NotRequired  # Python 3.11+
except ImportError:  # pragma: no cover - Python 3.10
    class NotRequired:  # type: ignore[no-redef]
        """Stand-in so annotations import on 3.10. Runtime checks do not rely on it."""

        def __class_getitem__(cls, item):  # noqa: N805
            return item


class PortBlock(TypedDict):
    port_key: str
    protocol: str
    raw_block: dict[str, Any]
    status: NotRequired[str]


class Provenance(TypedDict):
    original_line: NotRequired[int | None]
    jid: NotRequired[str | None]
    host: NotRequired[str | None]


class NormalizedRecord(TypedDict):
    record_id: str
    source_path: str
    ip: str
    scan_time: str
    merge_time: NotRequired[str | None]
    app_id: str
    declared_proto: str
    declared_port: str
    port_blocks: list[PortBlock]
    provenance: Provenance


EvidenceStrength = Literal["strong", "moderate", "weak"]
SignalType = Literal["banner", "header", "build_info", "certificate", "comment", "other"]
Part = Literal["a", "o", "h"]

OutcomeKind = Literal[
    "matched",
    "ambiguous",
    "no_match",
    "insufficient_evidence",
    "processing_error",
    "unsupported_protocol",
]


class ExtractionCandidate(TypedDict):
    candidate_id: str
    product_name: str
    vendor: NotRequired[str | None]
    version: NotRequired[str | None]
    update: NotRequired[str | None]
    part: NotRequired[Part | None]
    source_path: str
    raw_value: str
    signal_type: SignalType
    extractor_id: str
    evidence_strength: EvidenceStrength
    evidence_refs: list[str]
    normalized_record_id: str


class ProcessingOutcome(TypedDict):
    outcome: OutcomeKind
    record_id: str
    candidates: list[ExtractionCandidate]
    notes: NotRequired[str | None]
    error: NotRequired[str | None]


# Minimal required keys for an input _source object
REQUIRED_SOURCE_KEYS = frozenset({"ip", "scanTime", "proto", "port", "appId", "path"})

SUPPORTED_PROTOCOLS = frozenset({"ssh", "http", "ftp", "mongodb"})


def is_port_key(key: str) -> bool:
    """Return True if key looks like a tNN / uNN port block."""
    if not isinstance(key, str) or len(key) < 2:
        return False
    if key[0] not in ("t", "u"):
        return False
    return key[1:].isdigit()
