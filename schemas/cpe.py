"""M3 CPE resolution contracts. Does not change the M1 outcome model."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

try:
    from typing import NotRequired
except ImportError:  # pragma: no cover
    class NotRequired:  # type: ignore[no-redef]
        def __class_getitem__(cls, item):  # noqa: N805
            return item


ResolutionStatus = Literal[
    "exact_match",
    "review_required",
    "ambiguous",
    "product_only",
    "no_match",
    "deprecated_only",
    "skipped_weak",
    "invalid_candidate",
]


class CpeComponents(TypedDict):
    cpe_name: str
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str


class CandidateResolution(TypedDict):
    candidate_id: str | None
    resolution_status: ResolutionStatus
    cpe_name: NotRequired[str | None]
    cpe_name_id: NotRequired[str | None]
    part: NotRequired[str | None]
    vendor: NotRequired[str | None]
    product: NotRequired[str | None]
    version: NotRequired[str | None]
    title: NotRequired[str | None]
    deprecated: NotRequired[bool | None]
    resolution_basis: NotRequired[str | None]
    notes: NotRequired[str | None]
    source_path: NotRequired[str | None]
    normalized_record_id: NotRequired[str | None]
    evidence_strength: NotRequired[str | None]
    competing: NotRequired[list[dict[str, Any]]]
    match_count: NotRequired[int]


class ResolutionRecord(TypedDict):
    record_id: str | None
    source_outcome: str | None
    candidate_resolutions: list[CandidateResolution]
    dictionary_metadata: dict[str, Any]
    error: NotRequired[str | None]
    line_number: NotRequired[int]
