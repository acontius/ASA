# Local Agent Contracts and Run State

**Status:** Task 2 foundation  
**Scope:** Contracts, bounded state, and validated configuration only

## 1. Role and trust boundary

The future ASA agent is a single, bounded, local assistant for interpreting user requests and presenting explanations about information already available in the local ASA workspace. It is not a scanner, vulnerability assessor, or source of security truth.

M1–M4 remain authoritative:

- `schemas/models.py`: `ProcessingOutcome`, `ExtractionCandidate`
- `schemas/cpe.py`: `ResolutionRecord`, `CandidateResolution`
- `schemas/vulnerability.py`: `AssessmentRecord`, `CveAssessment`

The agent package does not redefine or mutate these records. In particular, the agent cannot create or change CVE IDs, CPE identities, evidence, findings, or assessment statuses. It cannot promote `potentially_affected` to a confirmed vulnerability.

Model output is untrusted advisory content. A future integration must validate raw output against a strict response schema and keep all authoritative M1–M4 fields outside model write access.

## 2. Interaction contracts

The standard-library dataclasses in `app/agent/contracts.py` define:

- `AgentRequest(request_id, message)`: non-empty request identifier and user message.
- `ToolCall(name, arguments)`: one named request for a future allow-listed read-only tool. Arguments are immutable string key/value pairs.
- `AgentDecision(kind, message, tool_call)`: one of the decision types below, with a non-empty message.

Allowed decision types:

| Type | Tool call | Meaning |
|---|---|---|
| `tool_call` | Exactly one required | Request one future allow-listed read-only operation |
| `final_answer` | Forbidden | Return an advisory response to the user |
| `clarification` | Forbidden | Ask the user for missing information |

Currently permitted tool names (names only; no implementations or execution in this task):

- `inspect_input`
- `check_readiness`
- `list_prior_runs`
- `summarize_results`

Unknown decision and tool names, empty required strings, duplicate argument keys, and invalid decision/tool combinations are rejected. The dataclasses validate already-constructed Python objects; they do not parse raw JSON or make raw model output trusted.

## 3. Run-state machine

`AgentRunState` is an immutable snapshot. Transitions and step accounting return new snapshots; they do not mutate existing state.

| Current state | Allowed next states |
|---|---|
| `created` | `running`, `failed`, `cancelled` |
| `running` | `waiting_for_user`, `completed`, `failed`, `cancelled` |
| `waiting_for_user` | `running`, `failed`, `cancelled` |
| `completed` | None (terminal) |
| `failed` | None (terminal) |
| `cancelled` | None (terminal) |

A step can be recorded only while running. `max_steps` must be between 1 and 10; the step count cannot exceed that limit. A run that has exhausted its budget cannot resume into `running`. Invalid transitions raise `InvalidTransitionError`; exhausted budgets raise `StepLimitExceeded`.

No persistence, scheduling, retries, or orchestration is included.

## 4. Local runtime configuration

`AgentConfig` is a frozen dataclass with these defaults:

| Setting | Default | Accepted range / rule |
|---|---:|---|
| `server_url` | `http://127.0.0.1:8080` | HTTP URL with a literal loopback IP only; no credentials, path, query, or fragment |
| `request_timeout_seconds` | `15.0` | Greater than 0 and at most 120 |
| `max_steps` | `5` | Integer from 1 to 10 |
| `max_output_tokens` | `512` | Integer from 1 to 2048 |

IPv4 loopback addresses and IPv6 `::1` are accepted. Hostnames (including `localhost`), LAN/public addresses, HTTPS, URL credentials, paths, queries, fragments, malformed ports, booleans masquerading as integers, and non-finite timeouts are rejected.

The configuration object performs validation only. It does not load environment variables, open sockets, contact llama.cpp, discover models, or download model files. The eventual llama.cpp / llama-server process must bind to loopback; this URL validation is a configuration guard, not a substitute for runtime/network isolation.


## 5. Read-only tool registry (Task 3)

`ToolRegistry` in `app/agent/tool_registry.py` dispatches only an `AgentDecision` whose kind is `tool_call`. Its handler map must match the four identifiers in `ALLOWED_TOOL_NAMES`; there is no dynamic import, shell, Python execution, pipeline invocation, or network access.

| Tool | Exact arguments | Behavior |
|---|---|---|
| `inspect_input` | `input_path` | Bounded streaming inspection of an input JSONL file |
| `check_readiness` | At least one of `input_path`, `cpe_db_path`, `vulnerability_db_path` | Read-only checks of explicitly supplied prerequisites |
| `list_prior_runs` | None | Reports `available: false`; persistence does not exist |
| `summarize_results` | `results_path` | Counts recognized M2, M3, or M4 fields without returning records |

The trusted caller supplies an absolute workspace root, allowed relative data roots (default: `Data/`, `out/`, `local-data/`), and hard limits. The model supplies only a relative file path. Absolute paths, traversal, URLs, home markers, hidden paths, symlinks, non-regular files, and paths outside those roots are rejected. Files are opened read-only using directory-relative opens with no-follow flags. The workspace root and allowed roots are never model-controlled.

Default ceilings are 64 MiB per file, 100,000 inspected lines/records, and 1 MiB per line. Limit hits are explicit in the result; partial counts are never labelled complete. Result envelopes are JSON-compatible and capped at 16 KiB. SQLite prerequisites are opened with `mode=ro` and `immutable=1`; only bounded schema metadata is returned.

M2 summaries count the schema-defined `outcome` field. M3 summaries count `candidate_resolutions[].resolution_status`. M4 summaries count `dataset_status` and `cve_assessments[].assessment_status`. The status allow-lists are derived from the existing schema `Literal` types. No IDs, CPEs, CVEs, evidence, findings, or assessment statuses are generated or modified. In particular, `potentially_affected` remains exactly as stored.

`list_prior_runs` does not inspect output directories and never treats pipeline artifacts as agent history. No persistence is implemented.

## 6. Explicitly deferred

Task 4 is the local llama.cpp provider only. Task 5 is the bounded agent loop and strict model-response validation. CLI integration and UI remain later work. The registry is deliberately implemented before provider or loop integration.

## 7. Explicitly deferred

This task does **not** implement:

- llama.cpp provider code, model loading, inference, or prompt construction;
- HTTP requests or server health checks;
- raw JSON parsing or strict validation of model-generated response text;
- a tool registry, tool implementations, or tool execution;
- an agent loop, CLI integration, persistence, or run recovery;
- any changes to M1–M4 schemas, pipeline, CLI, output formats, or supported protocols.

Those require separate, reviewed tasks. No cloud APIs, telemetry, remote inference, feed downloads, active scanning, exploitation, credential testing, target probing, arbitrary shell execution, or generated Python execution are permitted.
