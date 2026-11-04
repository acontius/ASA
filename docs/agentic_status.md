# Agentic Development Status

**Repository:** \`acontius/ASA\`  
**Status snapshot:** 2026-11-04  
**Main baseline for Task 3:** \`859a2f3f3957f1728f83e3cfbd5caf57bfa07639\`  
**Working branch:** \`feat/local-agent-mvp\`

## 1. Current project state

ASA is a Python 3.11, standard-library-oriented CLI for passive vulnerability assessment. Its deterministic stages process local scan records, extract product/version evidence, resolve it against a local CPE dictionary, and assess applicability against locally imported CVE/CPE Match intelligence.

M1–M4 remain authoritative for extraction, CPE resolution, CVE records, evidence, findings, and assessment statuses. Agent code is isolated under \`app/agent/\`; it does not alter M1–M4 schemas, pipeline behavior, CLI commands, or output formats.

All processing and future inference remain local/offline. The planned model runtime is llama.cpp / llama-server bound to loopback only.

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
- The strongest emitted finding status is \`potentially_affected\`; there is no confirmed-vulnerable status.
- Historical documented run: 105 tests passed.
- Official full CVE and CPE Match feeds have not been imported.

## 3. Existing deterministic pipeline

\`\`\`text
Local scan JSONL
  -> streaming reader / checkpoint
  -> normalization
  -> deterministic FTP, HTTP/HTTPS, SSH, MongoDB extractors
  -> processing outcomes
  -> local CPE Dictionary import / exact resolution
  -> local CVE + CPE Match imports
  -> conservative applicability assessment
  -> JSONL results
\`\`\`

M1–M4 behavior, schemas, CLI commands, and output formats must remain unchanged.

## 4. Task 2 — Agent contracts, configuration, and run state: COMPLETE

- \`app/agent/contracts.py\`: frozen request, decision, and tool-call dataclasses.
- \`app/agent/state.py\`: immutable state machine; \`max_steps\` is now consistently constrained to 1–10, matching \`AgentConfig\`.
- \`app/agent/config.py\`: frozen configuration and literal-loopback-only HTTP URL validation.
- \`tests/test_agent_contracts.py\`: contract, state, and configuration tests.
- \`docs/agent_contract.md\`: trust boundary and agent contracts.

The preliminary Task 3 state-limit correction was isolated from the registry work:
- State validation: \`3e8890989c26e94285002a53c9d2811b7adb2642\`
- Focused regression test: \`fd058171ba09405a363c19ef4e54c674834da2bd\`

Task 2 CI previously passed on CPython 3.11.17: 133 tests in the runner environment and 133 tests inside Docker; Docker sample smoke test processed 1,618 records with zero errors.

## 5. Task 3 — Safe read-only tool registry: IMPLEMENTED; CI VALIDATION PENDING

Implemented in the current feature branch:

- \`app/agent/tool_registry.py\`: explicit allow-list registry for \`inspect_input\`, \`check_readiness\`, \`list_prior_runs\`, and \`summarize_results\`.
- \`app/agent/__init__.py\`: public exports for registry, result, limits, and dispatch error.
- \`tests/test_agent_tools.py\`: temporary-directory tests for dispatch, exact arguments, path safety, symlinks, regular files, read-only behavior, bounded JSONL processing, truncation, SQLite read-only readiness, and M2/M3/M4 summaries.
- \`docs/agent_contract.md\`: argument contracts, workspace trust boundary, hard limits, schema-derived status counts, and task sequencing.

Security/behavior decisions:
- The caller, not model output, supplies the absolute workspace root and configurable allowed data roots. Defaults are \`Data/\`, \`out/\`, and \`local-data/\`.
- Paths must be relative and beneath an allowed root. Absolute paths, traversal, URLs, home markers, hidden paths, symlink traversal, and non-regular files are rejected. File access uses directory-relative opens with no-follow flags.
- JSONL reads are streaming with default ceilings of 64 MiB, 100,000 lines/records, and 1 MiB per line. Limit hits are explicit; partial statistics are never reported as complete.
- SQLite readiness uses read-only, immutable connections and returns only bounded schema metadata.
- Summary counters use the authoritative schema Literal values and actual fields: M2 \`outcome\`, M3 \`candidate_resolutions[].resolution_status\`, and M4 \`dataset_status\` / \`cve_assessments[].assessment_status\`.
- Tool results contain bounded JSON-compatible summaries only. No raw records, banners, credentials, environment values, or secrets are returned.
- \`list_prior_runs\` always returns \`available: false\` and an empty list; it does not scan output folders.
- No pipeline invocation, writes, external calls, dynamic imports, shell/Python execution, provider, inference, loop, CLI, or persistence was added.

Task 3 implementation commits currently on the branch:
- Registry: \`d300d1907b69e09f6e16f300aa01948cb5be01a2\`
- Unknown-tool rejection: \`5ca87a840d5b49298b0937524cbbad304c675497\`
- Test suite: \`3890fa150ff847eceae951bb7e6cbf1fd8f29331\`
- Public exports: \`a4bf455d97bcec4fba4052c5e8dd134711ab6524\`
- Malformed status-value handling: \`62ad03948c9f41b018e06b93a5a0c7dc9f24171d\`
- Derive summary status sets from schemas: \`7e74c296a19c72cf9b0567e78d13134e776fefad\`
- Tool registry documentation: \`23a94812550f8f0c3e9863d85f57765e64421658\`

The focused Task 3 tests and full suite have not yet been reported as passing. Record exact Python 3.11 runtime and test counts only after CI has completed.

## 6. Non-negotiable constraints

- Python 3.11 CLI; standard library preferred.
- Supported protocols remain FTP, HTTP/HTTPS, SSH, and MongoDB only.
- All processing and inference remain local/offline; no cloud APIs, telemetry, automatic feed downloads, or external inference.
- Future llama.cpp / llama-server must bind to loopback.
- No active scanning, exploitation, credential testing, target probing, arbitrary shell/Python execution, or generated-code execution.
- Agent output is advisory and untrusted. It must never create or modify CVE IDs, CPE identities, evidence, findings, or assessment statuses.
- \`potentially_affected\` must never be promoted to a confirmed vulnerability.
- No LangGraph, multi-agent architecture, Pydantic, or unnecessary dependencies.
- Never merge a branch or PR without explicit user approval.

## 7. Known limitations

- The 4 GB production scan dataset has not been tested.
- M2 checkpoint resume can repeat a record after a crash between output flush and checkpoint update.
- M3 has not been validated against the official full CPE dictionary and does not implement CPE version-range semantics.
- M4 has not been validated against the official full CVE and CPE Match feeds.
- Task 3 readiness reports SQLite table names and user_version metadata; it does not certify application-level compatibility with a particular production database version.
- The registry is not yet connected to a model provider or agent loop.

## 8. Agreed next-step order

1. **Task 3 — Safe read-only tool registry:** current implementation; finish CI validation and review.
2. **Task 4 — Local llama.cpp provider:** local-only provider integration; no agent loop.
3. **Task 5 — Bounded agent loop and strict model-response validation.**
4. Later: opt-in CLI integration and minimal UI.

Do not skip the registry stage. Do not begin Task 4 until Task 3 is reviewed and explicitly complete.

---

*This status distinguishes implemented code from verified test results. CI results will be added only after the corresponding workflow has completed.*
