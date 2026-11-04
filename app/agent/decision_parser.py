"""Strict parser for untrusted model decision JSON."""

from __future__ import annotations

import json
from typing import Any

from app.agent.contracts import AgentDecision, ToolCall


class DecisionParseError(ValueError):
    """Raw model output does not satisfy the decision response contract."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DecisionParseError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise DecisionParseError(f"invalid JSON constant: {value}")


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise DecisionParseError(f"{label} has missing or unexpected fields")


def parse_agent_decision(raw_text: str) -> AgentDecision:
    """Parse a JSON response with exact keys and validate it against contracts."""
    if not isinstance(raw_text, str) or not raw_text.strip():
        raise DecisionParseError("model response must be non-empty text")
    try:
        payload = json.loads(
            raw_text, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except DecisionParseError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise DecisionParseError("model response is not valid JSON") from exc

    if not isinstance(payload, dict):
        raise DecisionParseError("model response must be a JSON object")
    _exact_keys(payload, {"kind", "message", "tool_call"}, "decision")
    kind, message, raw_call = payload["kind"], payload["message"], payload["tool_call"]
    if not isinstance(kind, str) or not isinstance(message, str):
        raise DecisionParseError("kind and message must be strings")

    call = None
    if kind == "tool_call":
        if not isinstance(raw_call, dict):
            raise DecisionParseError("tool_call decision requires an object")
        _exact_keys(raw_call, {"name", "arguments"}, "tool_call")
        name, arguments = raw_call["name"], raw_call["arguments"]
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise DecisionParseError("tool name must be a string and arguments an object")
        if any(not isinstance(k, str) or not isinstance(v, str)
               for k, v in arguments.items()):
            raise DecisionParseError("tool arguments must map strings to strings")
        try:
            call = ToolCall(name=name, arguments=tuple(arguments.items()))
        except (TypeError, ValueError) as exc:
            raise DecisionParseError("tool call violates the tool contract") from exc
    elif raw_call is not None:
        raise DecisionParseError("non-tool decisions require tool_call=null")

    try:
        return AgentDecision(kind=kind, message=message, tool_call=call)
    except (TypeError, ValueError) as exc:
        raise DecisionParseError("decision violates the agent contract") from exc
