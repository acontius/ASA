# M2 Implementation — Streaming Ingestion and Deterministic Extraction

This document describes the code that landed in M2. The earlier design note
[m2_handoff.md](m2_handoff.md) is kept as the original recommendation.

## 1. Architecture and data flow

```
JSONL file
  -> app.ingestion.reader.iter_jsonl_records   (one line, byte offset)
  -> app.ingestion.normalizer.normalize        (NormalizedRecord)
  -> app.extractors (ssh / http / ftp / mongodb)
  -> app.outcomes.classify                     (ProcessingOutcome)
  -> append one JSON line to the output file
  -> atomic JSON checkpoint (next byte offset)
```

Nothing in this path calls the network, an LLM, or the NVD.

## 2. Module responsibilities

| Module | Role |
|--------|------|
| `app/ingestion/reader.py` | Binary `readline` loop. Yields line number, start offset, next offset, document or error. |
| `app/ingestion/checkpoint.py` | Versioned JSON sidecar. Atomic replace. Validated before resume. |
| `app/ingestion/normalizer.py` | `_source` envelope → `NormalizedRecord`. Every `tNN` / `uNN` key becomes a port block. |
| `app/extractors/` | Deterministic evidence only. `vendor` and `part` stay null. |
| `app/outcomes.py` | Maps candidates to the six M1 outcome labels. |
| `app/pipeline.py` | Streams records, writes outcomes, updates the checkpoint after each flush. |
| `app/cli.py` | `python -m app.cli`. |
| `schemas/models.py` | M1 TypedDicts. `NotRequired` imports on 3.11 and has a 3.10 fallback so the module still imports. |

`raw_block` keeps the single protocol object for the record currently being processed. Candidates store only `raw_value` and `source_path`, not a second copy of the banner payload.

## 3. How to run

Python 3.11 is the tested interpreter (3.10 can import the models; run tests on 3.11).

```bash
python3.11 -m app.cli \
  --input Data/PartOfMe.json \
  --output out/outcomes.jsonl \
  --checkpoint out/scan.ckpt.json
```

Resume:

```bash
python3.11 -m app.cli \
  --input Data/PartOfMe.json \
  --output out/outcomes.jsonl \
  --checkpoint out/scan.ckpt.json \
  --resume
```

Fatal configuration errors (missing input, output path equal to the input, bad checkpoint) exit with status 2. A malformed record does not abort the file.

## 4. Sanitized input / output example

Input shape (SSH fixture, IP already redacted):

```json
{"_source": {"ip": "203.0.113.1", "scanTime": "1762417273", "proto": "ssh", "port": "t22", "appId": "pub-zgrab2", "path": "/data/ip/pub-zgrab2_0_t22_ssh_local_3_1762417273.json", "t22": {"ssh": {"result": {"server_id": {"software": "OpenSSH_9.6p1", "version": "2.0"}}}}}}
```

Outcome (fields abbreviated):

```json
{"outcome": "matched", "record_id": "3104055211", "candidates": [{"product_name": "OpenSSH", "version": "9.6p1", "vendor": null, "part": null, "raw_value": "OpenSSH_9.6p1", "evidence_strength": "strong", "extractor_id": "ssh.server_id.v1"}]}
```

`server_id.version` (`2.0`) is the SSH protocol version and is not copied into `version`.

## 5. Outcome rules

| Outcome | Rule |
|---------|------|
| `processing_error` | JSON parse failure, non-object, or normalization error (missing required fields / wrong types). |
| `unsupported_protocol` | No port block whose protocol is ssh, http, ftp, or mongodb, and the declared protocol is also outside that set. |
| `no_match` | A supported protocol block exists but no candidate was produced. |
| `insufficient_evidence` | Only `weak` candidates (generic `WAF` / bare `nginx`, unparsed FTP banner, SSH comment alone). |
| `matched` | One or more `strong`/`moderate` candidates that agree on product and version. |
| `ambiguous` | Two or more identifying candidates disagree on product or version. |

A weak candidate does not cancel a consistent identifying candidate. Secondary port blocks are extracted; they are not dropped because `proto` names a different primary protocol. That means a Winbox record that also contains an HTTP block is classified from the HTTP evidence, not as `unsupported_protocol`.

## 6. Checkpoint and resume

- Offsets are **byte offsets** at line boundaries (`next_offset` is the position immediately after the line, including its newline when present).
- The sidecar is written only after that record's outcome line has been flushed.
- Resume opens the output in append mode and seeks the input to `next_offset`.
- A crash after the write and before the checkpoint can repeat one record (at-least-once). Exactly-once is not claimed.
- Invalid version, non-integer offset, or an offset past the input size is rejected.

An incomplete final line is parsed if it is valid JSON. If it is not, it is a `processing_error` for that line.

## 7. Error handling

- Malformed lines yield `processing_error` and the scan continues.
- Blank lines are skipped and the checkpoint still advances.
- The pipeline refuses to use the input path as the output path.

## 8. Tests and results

Command (from the repository root):

```bash
python3.11 -m unittest discover -s tests -v
```

Result observed on 2026-11-01: **41 tests, OK** (11 existing M1 tests plus M2 reader, checkpoint, normalizer, extractor, outcome, and pipeline tests).

The pipeline test also runs `Data/PartOfMe.json` (1 618 records). Observed outcome counts on that sample:

| Outcome | Count |
|---------|------:|
| matched | 753 |
| no_match | 502 |
| insufficient_evidence | 342 |
| ambiguous | 21 |
| processing_error | 0 |
| unsupported_protocol | 0 |

`unsupported_protocol` is 0 on this sample because the non-MVP protocols in the file also carry an HTTP block. The dedicated Winbox fixture covers the explicit unsupported outcome.

## 9. Memory

`resource.getrusage(RUSAGE_SELF).ru_maxrss` after processing the 14.8 MB sample was about **18.9 MB** (Linux reports this value in kilobytes). The reader uses `readline`, not a full-file `read()`. Outcomes are appended per record. The 4 GB dataset was **not** executed.

## 10. Deferred to later milestones

- CPE dictionary, CPE validation, CVE matching, scoring.
- Agent / LLM orchestrator. Local LLM selection.
- Active scanning.
- Production checkpoint store beyond the JSON sidecar.
- Numeric confidence calibration.
