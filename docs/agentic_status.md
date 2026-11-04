# Agentic Development Status

**Repository:** `acontius/ASA`  
**Status snapshot:** 2026-11-04  
**Baseline:** `main` at `ecd9f76a897ba3969e3043b5053a3abdd1de5f2f`  
**Working branch:** `feat/local-agent-mvp`

## 1. Current project state

ASA is a Python 3.11, standard-library-oriented CLI for passive vulnerability assessment. Its deterministic stages process local scan records, identify product/version evidence, resolve evidence against a local CPE dictionary, and assess applicability against locally imported CVE/CPE Match intelligence.

The current repository documents M1 through M4 as implemented. The existing pipeline is the source of truth for extracted evidence, CPE resolutions, CVE records, and assessment statuses. The planned local agent has **not** been implemented in the inspected baseline: there is no agent module or llama.cpp integration in the current application tree.

The CLI is not a web service. Runtime processing and intelligence imports consume local paths. No cloud inference or external service is part of the current architecture.

## 2. Completed milestones

### M1 — Dataset analysis and contracts: COMPLETE

- Profiled the JSONL input envelope and observed protocol-specific structures.
- Defined input, normalized-record, extraction-candidate, and processing-outcome contracts.
- Established sanitized fixtures for supported protocols, multi-port records, and unsupported protocols.
- Documented evidence strength and the distinction between missing evidence and processing errors.
- Acceptance document records all 15 criteria as PASS.

### M2 — Streaming ingestion and deterministic extraction: COMPLETE

- Implemented line-by-line JSONL ingestion, normalization, protocol extractors, outcome classification, and JSONL output.
- Implemented byte-offset checkpoints and resume.
- Extractors cover only FTP, HTTP/HTTPS, SSH, and MongoDB.
- The documented test run on 2026-11-01 reported 41 tests passing.
- The 1,618-record sample was processed; the documented peak RSS was approximately 18.9 MB.
- Resume is **at-least-once**, not exactly-once. The 4 GB production dataset was not run.

### M3 — Offline CPE resolution: COMPLETE

- Implemented local NVD CPE Dictionary 2.0 import into SQLite and conservative candidate resolution.
- Exact matches require strong evidence and a unique active product/version row. Vendor and part are copied only from that unique dictionary row; they are not guessed.
- M2 outputs and behavior remain unchanged.
- The documented test run on 2026-11-01 reported 61 tests passing.
- The official NVD CPE dictionary was not imported; tests use a small synthetic fixture. Version-range matching and alias/fuzzy matching are not implemented.

### M4 — Offline CVE intelligence and applicability: COMPLETE

- Implemented local NVD CVE 2.0 and CPE Match 2.0 importers, SQLite storage, and conservative configuration-tree evaluation.
- Assessment uses verified M3 exact-match inventory and preserves source evidence and CVSS data.
- Applicability evaluation uses three-valued logic; missing information remains unknown rather than being treated as false.
- The strongest emitted finding status is `potentially_affected`; the system does not claim `confirmed_vulnerable`.
- The documented local test run on 2026-11-03 reported 105 tests passing.
- The official full CVE and CPE Match feeds were not imported. The memory measurement used a 2,000-record synthetic CVE feed, not the official large feeds.
- GitHub Actions and release workflow results for the M4 PR/main are marked not verified in the acceptance record.

## 3. Existing deterministic pipeline

The current high-level flow is:

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

M1–M4 are established behavior and must be preserved. Agent work must be additive and must not silently change extraction, resolution, assessment, output contracts, or existing CLI behavior.

## 4. Planned local-agent MVP (not implemented)

The intended design is one bounded local agent using **llama.cpp** and a small explicit Python state machine. It is not a multi-agent system and should not introduce a general agent framework without a demonstrated need.

Before implementation, the agent boundary must be specified against the actual M1–M4 contracts. Its permitted inputs, outputs, and decisions must be explicit, deterministic where possible, bounded, and independently testable.

Non-negotiable safeguards:

- The agent must never create, rewrite, infer, or modify CVE IDs, CPE identities, security findings, evidence, or assessment statuses.
- The agent must not upgrade `potentially_affected` to a confirmed vulnerability or reinterpret missing/unknown evidence as a negative result.
- Any model output must be treated as untrusted advisory output and validated against a strict schema and allow-listed actions before use.
- The agent must not execute arbitrary shell commands, Python code, tools, or generated code.
- No active scanning, exploitation, credential testing, or target probing.
- No cloud APIs, remote inference, telemetry, automatic feed downloads, or external fallbacks. Model inference and all processing remain local/offline.
- Protocol scope remains strictly FTP, HTTP/HTTPS, SSH, and MongoDB. Do not add protocols.
- No unnecessary frameworks, orchestration layers, or multi-agent abstractions.

## 5. Project constraints and working rules

- Runtime target: Python 3.11 CLI.
- Preserve M1–M4 and the deterministic pipeline; changes must be incremental and regression-tested.
- Keep all data processing and inference local/offline.
- Do not add network clients, feed auto-downloaders, telemetry, or external inference fallbacks.
- Do not add active or intrusive security-testing capabilities.
- Keep scan data, local intelligence feeds, SQLite databases, and generated output out of Git.
- Document decisions and limitations. Make small, focused commits.
- Never merge a branch or PR without explicit user approval.

## 6. Known limitations in the current baseline

- The 4 GB production scan dataset has not been tested.
- M2 checkpoint resume can repeat a record after a crash between output flush and checkpoint update.
- M3 has not been validated against the official full CPE dictionary and currently uses exact product/version matching rather than CPE version-range semantics.
- M4 has not been validated against the official full CVE and CPE Match feeds.
- M4 GitHub Actions and release workflow outcomes are not confirmed in the acceptance document.
- The agent, llama.cpp runtime integration, agent state machine, and agent-specific tests do not yet exist in the inspected baseline.

## 7. Next step

**Do not start agent implementation yet.** First define and review a minimal agent integration contract using the existing M1–M4 schemas and CLI outputs:

1. Identify the single, bounded task the agent is allowed to perform and the exact existing records it may read.
2. Specify a strict input/output schema and an allow-list of permitted state transitions.
3. Make all authoritative security fields immutable and reject any model response that attempts to add or alter them.
4. Define deterministic validation, timeout/token bounds, local model configuration, and fail-closed behavior when llama.cpp or the model is unavailable.
5. Add contract and safety tests before wiring the agent into any existing command or pipeline.

The first implementation step should be isolated behind a new opt-in CLI entry point or similarly separate boundary. Existing M1–M4 commands and outputs must remain unchanged. The precise task and CLI shape require review before implementation.

---

*This document records the repository state inspected at the baseline SHA above. Historical test counts are taken from the milestone acceptance/implementation documents; they were not rerun as part of this documentation-only change.*
