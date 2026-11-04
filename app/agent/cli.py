"""Opt-in command line for the existing local agent.

This module only validates caller-supplied settings, builds the existing
agent objects, and prints the run result. It does not scan, persist a
conversation, start llama-server, or change M1–M4 behavior.

Example::

    python -m app.agent.cli --workspace-root /absolute/asa --message "What is ready?"
"""

from __future__ import annotations

import argparse
import io
import select
import sys
import uuid
from typing import BinaryIO, Callable

from app.agent.config import AgentConfig
from app.agent.contracts import AgentRequest
from app.agent.provider import LocalLlamaCppProvider, ProviderConnectionError
from app.agent.runner import AgentRunResult, run_agent
from app.agent.state import RunStatus
from app.agent.tool_registry import ToolRegistry

MAX_REQUEST_BYTES = 32 * 1024

_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.agent.cli",
        description=(
            "Ask the existing local agent one question. "
            "A loopback llama-server must already be running. "
            "This command does not start the server, store the conversation, "
            "or run inside the default Docker bridge network."
        ),
    )
    parser.add_argument(
        "--workspace-root",
        required=True,
        help="Absolute trusted workspace root. The model cannot choose this path.",
    )
    parser.add_argument(
        "--allowed-data-root",
        action="append",
        default=None,
        dest="allowed_data_roots",
        help=(
            "Relative data root the tools may read. Repeat to set more than one. "
            "Default: Data, out, local-data."
        ),
    )
    parser.add_argument(
        "--server-url",
        help="Loopback llama-server URL. Default: http://127.0.0.1:8080",
    )
    parser.add_argument(
        "--model-alias",
        help="Trusted llama-server model alias. Default: asa-local",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="Provider timeout in seconds, from just above 0 through 120. Default: 15",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        help="Step budget from 1 through 10. Default: 5",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        help="Generation limit from 1 through 2048. Default: 512",
    )
    parser.add_argument(
        "--message",
        help="One UTF-8 request. If omitted, one request is read from stdin.",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    stdin: BinaryIO | None = None,
    provider_factory: Callable[[AgentConfig], object] | None = None,
    agent_runner: Callable[..., AgentRunResult] | None = None,
) -> int:
    """Return a process status. Exceptions are not printed as tracebacks."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 2

    try:
        message = _read_message(args.message, sys.stdin.buffer if stdin is None else stdin)
        config = _config_from_args(args)
        if args.allowed_data_roots is None:
            registry = ToolRegistry(args.workspace_root)
        else:
            registry = ToolRegistry(
                args.workspace_root,
                allowed_data_roots=tuple(args.allowed_data_roots),
            )
        factory = provider_factory or LocalLlamaCppProvider
        runner = agent_runner or run_agent
        provider = factory(config)
        request = AgentRequest(request_id=uuid.uuid4().hex, message=message)
        result = runner(request, config=config, provider=provider, registry=registry)
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return _INTERRUPTED
    except ProviderConnectionError:
        _print_result(
            AgentRunResult(
                status=RunStatus.FAILED,
                steps_completed=0,
                message="The local model is unavailable.",
                error_code="provider_unavailable",
            )
        )
        return 1
    except (ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("error: the agent could not run", file=sys.stderr)
        return 1

    _print_result(result)
    if result.status in (RunStatus.COMPLETED, RunStatus.WAITING_FOR_USER):
        return 0
    if result.status is RunStatus.CANCELLED:
        return _INTERRUPTED
    return 1


def _config_from_args(args: argparse.Namespace) -> AgentConfig:
    values: dict[str, object] = {}
    if args.server_url is not None:
        values["server_url"] = args.server_url
    if args.model_alias is not None:
        values["model_alias"] = args.model_alias
    if args.timeout is not None:
        values["request_timeout_seconds"] = args.timeout
    if args.max_steps is not None:
        values["max_steps"] = args.max_steps
    if args.max_output_tokens is not None:
        values["max_output_tokens"] = args.max_output_tokens
    return AgentConfig(**values)


def _read_message(message: str | None, stdin: BinaryIO) -> str:
    if message is not None:
        if _stdin_has_bytes(stdin):
            raise ValueError("provide either --message or stdin, not both")
        text = message
    else:
        text = _read_stdin(stdin)
    if not isinstance(text, str) or not text.strip():
        raise ValueError("request must not be empty")
    return text


def _read_stdin(stdin: BinaryIO) -> str:
    data = stdin.read(MAX_REQUEST_BYTES + 1)
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("request must be UTF-8 bytes")
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError(f"request exceeds {MAX_REQUEST_BYTES} bytes")
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("request must be valid UTF-8") from exc


def _stdin_has_bytes(stdin: BinaryIO) -> bool:
    if hasattr(stdin, "isatty"):
        try:
            if stdin.isatty():
                return False
        except (AttributeError, ValueError, OSError):
            pass
    if isinstance(stdin, io.BytesIO):
        return bool(stdin.getvalue()[stdin.tell() :])
    try:
        fileno = stdin.fileno()
    except (AttributeError, io.UnsupportedOperation, OSError, ValueError):
        return False
    readable, _, _ = select.select([fileno], [], [], 0)
    return bool(readable)


def _print_result(result: AgentRunResult) -> None:
    lines = [f"status: {result.status.value}", f"steps: {result.steps_completed}"]
    if result.status is RunStatus.WAITING_FOR_USER:
        lines.append("needs_input: yes")
        lines.append(
            "The previous request was not saved. "
            "This clarification does not continue automatically."
        )
    if result.error_code is not None:
        lines.append(f"error_code: {result.error_code}")
    if result.message:
        lines.append("")
        lines.append(result.message)
    print("\n".join(lines))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        raise SystemExit(_INTERRUPTED) from None
