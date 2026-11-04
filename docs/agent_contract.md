# Local Agent Contracts and Run State

**Status:** Task 2 foundation + Task 3 read-only registry + Task 4 local provider  
**Scope:** Contracts, bounded state, validated configuration, four read-only tools, and synchronous local inference

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

The four implemented read-only tool identifiers are:

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
| `max_output_tokens` | `512` | Integer from 1 to 2048 |\n| `model_alias` | `asa-local` | 1–64 ASCII letters, digits, dots, underscores, or hyphens; starts with a letter or digit |

IPv4 loopback addresses and IPv6 `::1` are accepted. Hostnames (including `localhost`), LAN/public addresses, HTTPS, URL credentials, paths, queries, fragments, malformed ports, booleans masquerading as integers, and non-finite timeouts are rejected.

The configuration object performs validation only. It does not load environment variables, open sockets, contact llama.cpp, discover models, or download model files. The model alias is trusted configuration; the llama-server must be started with the matching `--alias asa-local` (or the configured alias). The URL validation is a configuration guard, not a substitute for runtime/network isolation.


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

## 6. Local llama.cpp provider (Task 4)

`LocalLlamaCppProvider` in `app/agent/provider.py` is a synchronous standard-library HTTP client. It accepts only a trusted immutable `AgentConfig` and exposes:

- `health_check() -> bool`: `GET /health`; exactly `{"status":"ok"}` at HTTP 200 is ready, and HTTP 503 is a normal not-ready result (`False`). Other HTTP, transport, timeout, or malformed-response conditions raise sanitized provider exceptions.
- `complete(messages) -> str`: `POST /v1/chat/completions`; returns the first assistant message's raw text content. It does not parse model-generated JSON or create an `AgentDecision`.

`ProviderMessage` is an immutable role/content pair. Only `system`, `user`, and `assistant` roles are accepted. A request is limited to 16 messages and 256 KiB of encoded JSON. Response reads are capped at 1 MiB (one extra byte is read only to detect overflow). The payload contains only the configured model alias, validated messages, configured `max_tokens`, `temperature: 0`, and `stream: false`; no tools, tool choice, MCP, or function definitions are sent.

Transport safeguards:
- The destination is derived only from the validated literal-loopback `AgentConfig.server_url` and fixed endpoint paths. Messages and model output cannot choose a URL, host, port, model alias, or timeout.
- An explicit empty `ProxyHandler` prevents proxy environment variables from being used. Redirects are rejected, not followed.
- The request uses the configured bounded timeout; there are no automatic retries or remote fallbacks.
- Response reads have a hard byte ceiling. Exceptions expose controlled status/error labels only, never prompt text, raw response bodies, credentials, or server diagnostics.
- The provider does not start or manage llama-server and has no connection to `ToolRegistry`. It does not execute native tool calls.

### Manual local server setup

Start llama-server manually after obtaining a model file through your own approved offline process. This example assumes the file already exists:

```bash
llama-server \
  --model "/absolute/path/to/model.gguf" \
  --host 127.0.0.1 \
  --port 8080 \
  --alias asa-local
```

Do not bind to `0.0.0.0`; do not use `-hf` or `--model-url`; do not enable `--tools all`; and do not configure `--mcp-servers-config` or `--mcp-servers-json`. No model is downloaded automatically and Python does not launch the server.

Qwen3 8B GGUF Q4_K_M is only an optional manual candidate; its local availability and suitability on the target 16 GB RAM / 8 GB VRAM machine have not been verified. Check the installed `llama-server --help` for supported GPU offload flags and determine the number of layers empirically; do not assume all layers fit in VRAM.

## 7. Explicitly deferred

This task does **not** implement:

- raw JSON parsing or strict validation of model-generated response text into `AgentDecision`;
- an agent loop, prompt policy, tool dispatch, or registry integration;
- CLI integration, UI, persistence, or run recovery;
- model loading, downloading, or automatic model management;
- any changes to M1–M4 schemas, pipeline, CLI, output formats, or supported protocols.

Those require separate, reviewed tasks. No cloud APIs, telemetry, remote inference, feed downloads, active scanning, exploitation, credential testing, target probing, arbitrary shell execution, or generated Python execution are permitted.
