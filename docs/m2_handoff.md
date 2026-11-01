# M2 Handoff — Streaming Ingestion & Deterministic Extraction

> Status: the pipeline described below has been implemented. See
> [m2_implementation.md](m2_implementation.md) for the behavior that actually
> shipped. This file remains the original recommendation and is not a second
> source of truth where the two differ.

## Goal of M2
Implement a streaming, resumable ingestion pipeline that:
1. Reads JSONL records without loading the full dataset into RAM.
2. Produces Normalized Records according to the M1 contract.
3. Runs deterministic, protocol-specific extractors for SSH, HTTP/HTTPS, FTP, MongoDB.
4. Emits Extraction Candidates + Processing Outcomes.
5. Preserves provenance (source path / line offset / original scanTime).

## Recommended minimal layout
```
app/
  ingestion/
    reader.py          # JSONL streaming reader + checkpointing
    normalizer.py      # → NormalizedRecord
  extractors/
    base.py            # Extractor protocol / registry
    ssh.py
    http.py
    ftp.py
    mongodb.py
  schemas/
    models.py          # TypedDicts / dataclasses from M1 contracts
  evaluation/          # deferred
tests/
  fixtures/            # already populated
  test_ingestion.py
  test_extractors_ssh.py
  …
```

## Required for M2
- Streaming reader that yields (line_offset, raw_dict).
- Checkpoint / resume by byte or line offset.
- One extractor per supported protocol that returns zero-or-more Candidates.
- Outcome classification logic.
- Unit tests against the fixtures created in M1.

## Explicitly deferred
- Agent orchestrator / LLM tools.
- CPE dictionary download or resolution.
- Multi-agent or RAG components.
- Full 4 GB production run (design for it, test on sample).
- Active scanning.

## Open decisions (non-blocking)
- Exact checkpoint storage format (JSON sidecar vs SQLite).
- Whether to keep full raw blocks or only evidence paths + hashes.
- Qualitative vs provisional numeric confidence (prefer qualitative until calibration data exists).

## Dependencies
- Python ≥ 3.10 standard library only for core path (json, dataclasses, typing, pathlib).
- Optional: `ijson` or similar only if memory pressure appears on the full dataset; not required for the sample.

## Success metric for M2
- All M1 fixtures produce the expected outcome class and at least the documented primary candidates.
- Streaming reader processes the sample file with peak RSS well under file size.
- Provenance fields round-trip correctly.
