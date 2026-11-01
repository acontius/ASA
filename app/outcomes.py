"""Deterministic outcome classification.

Rules
-----
* processing_error: the record could not be parsed or normalized.
* unsupported_protocol: no supported-protocol port block is present.
* ambiguous: two or more strong/moderate candidates name different products
  or the same product with different versions.
* matched: at least one strong or moderate candidate, and they agree.
* insufficient_evidence: only weak candidates.
* no_match: a supported protocol was present but no candidate was produced.

Weak candidates do not override a consistent strong/moderate identification,
but they are still retained on the outcome.
"""

from __future__ import annotations

from schemas.models import ExtractionCandidate, OutcomeKind, ProcessingOutcome

_IDENTIFYING = {"strong", "moderate"}


def classify(
    record_id: str,
    candidates: list[ExtractionCandidate],
    *,
    supported_block_present: bool,
    error: str | None = None,
) -> ProcessingOutcome:
    if error:
        return {
            "outcome": "processing_error",
            "record_id": record_id,
            "candidates": [],
            "notes": None,
            "error": error,
        }
    if not supported_block_present:
        return {
            "outcome": "unsupported_protocol",
            "record_id": record_id,
            "candidates": candidates,
            "notes": "no supported protocol block",
            "error": None,
        }
    identifying = [item for item in candidates if item["evidence_strength"] in _IDENTIFYING]
    if not candidates:
        return {
            "outcome": "no_match",
            "record_id": record_id,
            "candidates": [],
            "notes": None,
            "error": None,
        }
    if not identifying:
        return {
            "outcome": "insufficient_evidence",
            "record_id": record_id,
            "candidates": candidates,
            "notes": "only weak evidence",
            "error": None,
        }
    signatures = {(item["product_name"].lower(), item.get("version")) for item in identifying}
    outcome: OutcomeKind = "ambiguous" if len(signatures) > 1 else "matched"
    return {
        "outcome": outcome,
        "record_id": record_id,
        "candidates": candidates,
        "notes": None,
        "error": None,
    }
