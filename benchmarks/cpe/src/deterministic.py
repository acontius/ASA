"""Adapter over the existing M2 normalizer/extractors and M3 resolver."""
from __future__ import annotations

import time
from app.extractors import EXTRACTORS, extract_candidates
from app.ingestion.normalizer import normalize
from app.outcomes import classify
from app.cpe.store import require_ready
from app.cpe.resolver import resolve_candidate


def process(raw: dict, record_id: str, line_number: int, db=None) -> dict:
    start = time.perf_counter()
    record = normalize(raw, line_number=line_number, byte_offset=0)
    candidates = extract_candidates(record, EXTRACTORS)
    supported = any(b["protocol"] in EXTRACTORS for b in record["port_blocks"])
    outcome = classify(record_id, candidates, supported_block_present=supported)
    resolutions = [resolve_candidate(db, c) for c in candidates] if db else []
    return {"record_id": record_id, "outcome": outcome, "candidate_resolutions": resolutions, "latency_seconds": time.perf_counter()-start}
