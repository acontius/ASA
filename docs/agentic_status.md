# Agentic Development Status

**Repository:** `acontius/ASA`  
**Status snapshot:** 2026-11-04  
**Current main baseline before Task 2:** `e52b0c70353430625946d2977b2c10bc4af41d34`  
**Working branch:** `feat/local-agent-mvp`

## 1. Current project state

ASA is a Python 3.11, standard-library-oriented CLI for passive vulnerability assessment. Its deterministic stages process local scan records, identify product/version evidence, resolve evidence against a local CPE dictionary, and assess applicability against locally imported CVE/CPE Match intelligence.

M1 through M4 are implemented and remain authoritative for extraction, CPE resolution, CVE records, evidence, findings, and assessment statuses. The agent foundation is isolated under `app/agent/`; it does not modify the deterministic pipeline or existing schemas.

All processing and future inference must remain local/offline. The planned model runtime is llama.cpp / llama-server bound to loopback only.

## 2. Completed milestones

### M1 — Dataset analysis and contracts: COMPLETE

- Profiled the JSONL input envelope and protocol-specific structures.
- Defined input, normalized-record, extraction-candidate, and processing-outcome contracts.
- Established sanitized fixtures for supported protocols, multi-port records, and unsupported protocols.
- Acceptance document records all 15 criteria as PASS.

### M2 — Streaming ingestion and deterministic extraction: COMPLETE

- Implemented line-by-line JSONL ingestion, normalization, protocol extractors, outcome classification, JSONL output, and byte-offset checkpoint/resume.
- Extractors cover only FTP, HTTP/HTTPS, SSH, and MongoDB.
- Historical documented run: 41 tests passed; 1,618-record sample processed with approximately 18.9 MB peak RSS.
- Resume is at-least-once, not exactly-once. The 4 GB production dataset has not been run.

### M3 — Offline CPE resolution: COMPLETE

- Implemented local NVD CPE Dictionary 2.0 import into SQLite and conservative candidate resolution.
- Exact matches require strong evidence and a unique active product/version row; vendor and part are copied from that dictionary row.
- Historical documented run: 61 tests passed.
- The official full dictionary has not been imported; version-range and alias/fuzzy matching are not implemented.

### M4 — Offline CVE intelligence and applicability: COMPLETE

- Implemented local NVD CVE 2.0 and CPE Match 2.0 importers, SQLite storage, and conservative configuration-tree evaluation.
- Applicability uses three-valued logic; missing information remains unknown.
- The strongest emitted finding status is `potentially_affected`; there is no confirmed-vulnerable status.
- Historical documented run: 105 tests passed.
- Official full CVE and CPE Match feeds have not been imported. GitHub Actions and release workflow outcomes recorded in the M4 acceptance document were not verified there.

## 3. Existing deterministic pipeline

```text
Local scan JSONL
  -> streaming reader / checkpoint
  -> normalization
  -> deterministic FTP, HTTP/HTTPS, SSH, MongoDB extractors
  -> processing outcomes
  -> local CPE Dictionary import / exact resolution
  -> local CVE + CPE Match imports
  -> conservative applicability assessment
  -> JSONL results
```

M1–M4 behavior, schemas, CLI commands, and output formats must remain unchanged.

## 4. Task 2 — Agent contracts, configuration, and run state: IMPLEMENTED

Added an isolated standard-library-only foundation:

- `app/agent/contracts.py`: frozen request, decision, and tool-call dataclasses; decision types are `tool_call`, `final_answer`, and `clarification`.
- `app/agent/state.py`: immutable explicit state machine with terminal states and enforced step budget.
- `app/agent/config.py`: frozen configuration with conservative timeout/token/step limits and literal-loopback-only HTTP URL validation.
- `app/agent/__init__.py`: public exports.
- `tests/test_agent_contracts.py`: focused unittest coverage.
- `docs/agent_contract.md`: trust boundary, contracts, state transitions, config rules, and deferred work.

The only permitted future tool names are `inspect_input`, `check_readiness`, `list_prior_runs`, and `summarize_results`. They are identifiers only; no tools are implemented or executed.

The existing authoritative schemas in `schemas/models.py`, `schemas/cpe.py`, and `schemas/vulnerability.py` are not duplicated or modified. No model inference, HTTP client, tool execution, agent loop, CLI integration, persistence, or dependencies were added.

## 5. Non-negotiable constraints

- Python 3.11 CLI; standard library preferred.
- Only FTP, HTTP/HTTPS, SSH, and MongoDB remain supported.
- All processing and inference remain local/offline; no cloud APIs, telemetry, automatic feed downloads, or external inference.
- Future llama.cpp / llama-server must bind to loopback.
- No active scanning, exploitation, credential testing, target probing, arbitrary shell/Python execution, or generated-code execution.
- Agent output is advisory and untrusted. It must never create or modify CVE IDs, CPE identities, evidence, findings, or assessment statuses.
- `potentially_affected` must never be promoted to a confirmed vulnerability.
- No LangGraph, multi-agent architecture, Pydantic, or unnecessary dependencies.
- Changes remain incremental and tested. Never merge a branch or PR without explicit user approval.

## 6. Known limitations

- The 4 GB production scan dataset has not been tested.
- M2 checkpoint resume can repeat a record after a crash between output flush and checkpoint update.
- M3 has not been validated against the official full CPE dictionary and does not implement CPE version-range semantics.
- M4 has not been validated against the official full CVE and CPE Match feeds.
- Task 2 contracts validate in-process typed objects only; raw model JSON parsing/validation is deferred.
- No llama.cpp process, HTTP communication, tool registry, tool execution, agent loop, CLI integration, or run persistence exists.

## 7. Next step

Task 3 must be separately specified and approved. The likely next boundary is strict validation of untrusted model response text and a local llama.cpp integration design, without adding tool execution or changing M1–M4. Do not proceed automatically.

---

*Historical M1–M4 test counts above are taken from milestone documentation. Task 2 test results must be recorded only after an actual run; this document update does not claim tests have passed.*
