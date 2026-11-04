# Local Agent Contracts, Run State, and Bounded Loop

**Status:** Tasks 2–6. Contracts, bounded state, configuration, read-only tools, local provider, strict decision parser, synchronous agent loop, and an opt-in host CLI  
**Scope:** One local request at a time. The CLI does not persist the conversation

## 1. Role and trust boundary

The future ASA agent is a single, bounded, local assistant for interpreting user requests and presenting explanations about information already available in the local ASA workspace. It is not a scanner, vulnerability assessor, or source of security truth.

M1–M4 remain authoritative:

- `schemas/models.py`: `ProcessingOutcome`, `ExtractionCandidate`
- `schemas/cpe.py`: `ResolutionRecord`, `CandidateResolution`
- `schemas/vulnerability.py`: `AssessmentRecord`, `CveAssessment`

The agent package does not redefine or mutate these records. In particular, the agent cannot create or change CVE IDs, CPE identities, evidence, findings, or assessment statuses. It cannot promote `potentially_affected` to a confirmed vulnerability.

Model output is untrusted advisory content. The bounded loop validates raw provider text with `parse_agent_decision` before it acts on a decision. Authoritative M1–M4 fields stay outside model write access. The model cannot choose the server URL, model alias, workspace root, or tool registry.

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

The state object does not schedule work, retry, persist, or call a model. `run_agent` is the orchestrator, and it records steps only through `record_step` and `transition`.

## 4. Local runtime configuration

`AgentConfig` is a frozen dataclass with these defaults:

| Setting | Default | Accepted range / rule |
|---|---:|---|
| `server_url` | `http://127.0.0.1:8080` | HTTP URL with a literal loopback IP only; no credentials, path, query, or fragment |
| `request_timeout_seconds` | `15.0` | Greater than 0 and at most 120 |
| `max_steps` | `5` | Integer from 1 to 10 |
| `max_output_tokens` | `512` | Integer from 1 to 2048 |
| `model_alias` | `asa-local` | 1–64 ASCII letters, digits, dots, underscores, or hyphens; starts with a letter or digit |

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

## 7. Strict model-response parsing (Task 5A)

`parse_agent_decision` in `app/agent/decision_parser.py` converts untrusted raw model text into an `AgentDecision` only after strict JSON and contract validation. The parser:

- rejects input larger than 64 KiB before parsing, and converts `RecursionError` from deeply nested JSON into `DecisionParseError`;
- accepts a single JSON object with exactly `kind`, `message`, and `tool_call`;
- rejects duplicate JSON object keys, non-standard constants, malformed JSON, non-object top-level values, and missing or extra fields;
- requires a tool-call object to contain exactly `name` and `arguments`, with string-to-string arguments, and delegates allow-list and decision-combination validation to the existing contracts;
- requires `tool_call: null` for `final_answer` and `clarification`;
- raises `DecisionParseError` for invalid output and does not dispatch tools, execute code, or change M1–M4 data.

Parse errors do not include the raw model text. Parsing does not select a provider, a workspace, or a tool implementation. `run_agent` is what calls the parser.

## 8. Bounded agent loop (Task 5B)

`run_agent(request, *, config, provider, registry)` in `app/agent/runner.py` is a single-request, synchronous state machine. Dependencies are injected. Tests use fake providers and registries; the function does not start llama-server, open a network connection itself, or load a model.

`provider` must expose `health_check()` and `complete(messages)`. `registry` must be a `ToolRegistry`. `config` is the trusted step budget and the config used to estimate request size. Model text cannot replace any of these objects.

### Lifecycle

1. Validate the request and the injected dependencies.
2. Create `AgentRunState(max_steps=config.max_steps)` and transition it to `running`.
3. Call `health_check`. Only an exact `True` continues. `False` or a connection failure ends the run as `failed`. This preflight does not consume a step.
4. Build a conversation: one fixed system prompt, then the user message prefixed as untrusted data.
5. While budget and context remain, call `provider.complete` with a snapshot of that conversation.
6. Parse the returned text with `parse_agent_decision`.
7. On `final_answer`, transition to `completed` and return the decision message.
8. On `clarification`, transition to `waiting_for_user`, return the clarification, and stop. No tool is dispatched and `input()` is not called. The function does not store the conversation or resume it later.
9. On `tool_call`, dispatch only when the step rule below allows it. Dispatch goes through `ToolRegistry.dispatch` and nowhere else. A compact JSON summary of the `ToolResult` is appended as untrusted user-role data, and the loop continues.
10. Return `AgentRunResult`.

### Step accounting

| Event | Consumes a step | Effect |
|---|---|---|
| `health_check` | No | Preflight only |
| `complete()` returns text | Yes | Counted even if the parser then rejects the text |
| `complete()` raises | No | The run fails. There is no retry and no remote fallback |
| Tool dispatch | Yes | `record_step()` runs before `dispatch` |
| `final_answer` or `clarification` | No additional step | Accepted on the model step that produced it, including the last allowed step |

A tool is dispatched only when, after its model step has been counted, `max_steps - steps_completed >= 2`. Those two remaining steps are the dispatch and the model completion that must interpret the tool result. If fewer than two steps remain, the tool is not dispatched, the provider is not called again, and the run fails with `step_budget_exhausted`.

Consequences:

- A direct final answer or clarification needs 1 step.
- One tool followed by another model decision needs 3 steps.
- `k` tools followed by a concluding model decision need `2k + 1` steps.
- With `max_steps == 2`, a tool decision is refused: one step would remain after the model completion, which is not enough to both dispatch and ask the model again.
- The counter is never reset and never allowed to exceed `max_steps`.

### Conversation limits

The loop keeps the provider limits: at most 16 messages and 256 KiB of serialized chat-completion JSON. Tool results are already capped at 16 KiB by `ToolResult`. The runner additionally refuses model text above the parser's 64 KiB limit.

History stored for the next completion is not the raw provider body. An assistant turn is the canonical JSON of the validated decision. A tool turn is a compact JSON object with `"untrusted": true`, the tool name, success flag, bounded data, and sanitized error. User text and tool data stay in `user` messages. They are never copied into the system prompt and are never parsed as a new decision.

If the next request would exceed the message count or byte limit, the loop stops with `context_limit_exceeded` and does not call `complete` again. The same code is used when the provider itself reports `request_too_large` or `invalid_message_count`.

### Result

`AgentRunResult` is frozen. It exposes:

| Field | Meaning |
|---|---|
| `status` | `completed`, `waiting_for_user`, `failed`, or `cancelled` |
| `steps_completed` | Steps actually recorded |
| `message` | User-facing answer, clarification, or sanitized failure text |
| `error_code` | Set only when `status` is `failed` |
| `needs_user_input` | True only for `waiting_for_user` |

It does not expose the transcript, raw model output, or tool payloads. Failure codes are `provider_unavailable`, `provider_timeout`, `provider_http_error`, `provider_response_error`, `invalid_model_decision`, `step_budget_exhausted`, `context_limit_exceeded`, `tool_dispatch_failed`, and `internal_error`. Failure text comes from a fixed map. Provider bodies, prompts, paths, environment values, and exception text are not copied into it.

A `ToolResult` with `success` false is not a failed run. Its sanitized envelope is given back to the model, which may then answer or clarify. A `ToolDispatchError`, invalid decision, or unexpected exception ends the run.

### Explicitly unchanged

The loop does not add tools, widen tool permissions, call the pipeline, write M1–M4 records, or promote `potentially_affected`. Supported protocols remain FTP, HTTP/HTTPS, SSH, and MongoDB. Inference stays on the injected loopback provider.

## 9. Explicitly deferred

The host CLI in the next section is only an interface to `run_agent`. This project does **not** implement:

- a UI;
- persistent run history, conversation storage, or recovery;
- resuming a `waiting_for_user` result automatically;
- model download, model discovery, or llama-server process management;
- remote or cloud inference, telemetry, or fallback;
- another agent framework or multi-agent orchestration;
- new tools, active scanning, exploitation, credential testing, or target probing;
- changes to M1–M4 schemas, pipeline behavior, CLI behavior, or output formats.

No cloud APIs, automatic feed downloads, arbitrary shell execution, or generated Python execution are permitted.

## 10. Opt-in host CLI (Task 6)

`python -m app.agent.cli` builds `AgentConfig`, `ToolRegistry`, `LocalLlamaCppProvider`, and `AgentRequest`, then calls `run_agent`. It does not add tools, orchestration, scanning, or storage.

```bash
python -m app.agent.cli \
  --workspace-root /absolute/path/to/asa \
  --message "What local results are ready?"
```

Stdin is used only when `--message` is omitted. The two sources cannot be combined when stdin contains actual bytes: terminal stdin and EOF (including `/dev/null` or a closed empty pipe) are allowed with `--message`. The check is bounded; if stdin contains data, the CLI rejects the combination before running the agent. Unsupported streams are treated conservatively as conflicting. The request is limited to 32768 bytes, must be valid UTF-8, and must not be empty. The read asks for at most 32769 bytes so an oversized request is detected without reading the rest. Nothing from the request or the run is written to disk.

| Argument | Default | Rule |
|---|---|---|
| `--workspace-root` | required | Absolute directory chosen by the caller |
| `--allowed-data-root` | `Data`, `out`, `local-data` | Repeatable relative root; same validation as the registry |
| `--server-url` | `http://127.0.0.1:8080` | Existing literal-loopback `AgentConfig` rule |
| `--model-alias` | `asa-local` | Existing identifier rule |
| `--timeout` | `15` | Seconds, greater than 0 and at most 120 |
| `--max-steps` | `5` | Integer from 1 through 10 |
| `--max-output-tokens` | `512` | Integer from 1 through 2048 |
| `--message` | stdin | One request; not stored |

The workspace root and allowed roots come only from these arguments. Environment variables are not configuration. The model still cannot choose them.

Start llama-server yourself with the command in section 6 before using this CLI. If it is not reachable, the command reports the existing sanitized unavailable result and does not try another server.

Stdout is the result. Stderr is used for argument errors and for an interrupt. Exit codes:

| Result | Code |
|---|---|
| `completed` | 0 |
| `waiting_for_user` | 0 |
| invalid arguments or configuration | 2 |
| `failed` | 1 |
| `cancelled` or keyboard interrupt | 130 |

A waiting result prints the clarification and says the request was not saved. The process exits. It does not ask again or resume.

The printed result is `status`, `steps`, and for a failure the stable `error_code`, plus the result message. Raw provider JSON, tool payloads, exception traces, and credentials are not printed.

### Docker

The Docker entrypoint is unchanged: `scan`, `cpe`, and `vulnerability` only. An `agent` container command is intentionally absent.

`LocalLlamaCppProvider` accepts only a literal loopback URL. Inside the default Compose bridge network, `127.0.0.1` is the container, not the host where llama-server is running. Making the URL accept the host gateway, switching Compose to host networking, or publishing the server port would weaken that boundary, so none of those changes were made. Run the agent CLI on the host. The container remains the deterministic M2–M4 pipeline.

