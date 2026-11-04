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

## 5. Explicitly deferred

This task does **not** implement:

- llama.cpp provider code, model loading, inference, or prompt construction;
- HTTP requests or server health checks;
- raw JSON parsing or strict validation of model-generated response text;
- a tool registry, tool implementations, or tool execution;
- an agent loop, CLI integration, persistence, or run recovery;
- any changes to M1–M4 schemas, pipeline, CLI, output formats, or supported protocols.

Those require separate, reviewed tasks. No cloud APIs, telemetry, remote inference, feed downloads, active scanning, exploitation, credential testing, target probing, arbitrary shell execution, or generated Python execution are permitted.
