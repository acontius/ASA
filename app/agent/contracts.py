"""Typed interaction contracts for the bounded local agent.

These are conversation/control contracts only. They are not security findings
and deliberately do not mirror or replace the M1-M4 data schemas.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ToolName = Literal[
    "inspect_input",
    "check_readiness",
    "list_prior_runs",
    "summarize_results",
    "extract_identities",
    "resolve_cpe_local",
]
DecisionType = Literal["tool_call", "final_answer", "clarification"]

ALLOWED_TOOL_NAMES = frozenset(
    {
        "inspect_input",
        "check_readiness",
        "list_prior_runs",
        "summarize_results",
        "extract_identities",
        "resolve_cpe_local",
    }
)
ALLOWED_DECISION_TYPES = frozenset(
    {"tool_call", "final_answer", "clarification"}
)


def _require_non_empty_string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


@dataclass(frozen=True, slots=True)
class AgentRequest:
    """A user request passed to the agent boundary."""

    request_id: str
    message: str

    def __post_init__(self) -> None:
        _require_non_empty_string(self.request_id, "request_id")
        _require_non_empty_string(self.message, "message")


@dataclass(frozen=True, slots=True)
class ToolCall:
    """One allow-listed tool invocation description.

    Arguments are represented as immutable string pairs. This object describes
    a request only; it does not execute the tool or authorize arbitrary actions.
    """

    name: ToolName
    arguments: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or self.name not in ALLOWED_TOOL_NAMES:
            raise ValueError(f"unknown tool name: {self.name!r}")
        if not isinstance(self.arguments, tuple):
            raise ValueError("arguments must be an immutable tuple of string pairs")

        seen: set[str] = set()
        for item in self.arguments:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not item[0].strip()
                or not isinstance(item[1], str)
            ):
                raise ValueError("each argument must be a (non-empty string, string) pair")
            if item[0] in seen:
                raise ValueError(f"duplicate tool argument: {item[0]!r}")
            seen.add(item[0])


@dataclass(frozen=True, slots=True)
class AgentDecision:
    """A single bounded decision returned by the agent.

    Exactly one ToolCall object is permitted for tool_call. The other decision
    types cannot carry a tool call. This validates an in-process typed object;
    it does not parse or trust raw model output.
    """

    kind: DecisionType
    message: str
    tool_call: ToolCall | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in ALLOWED_DECISION_TYPES:
            raise ValueError(f"unknown decision type: {self.kind!r}")
        _require_non_empty_string(self.message, "message")

        if self.kind == "tool_call":
            if not isinstance(self.tool_call, ToolCall):
                raise ValueError("tool_call decisions require exactly one ToolCall")
        elif self.tool_call is not None:
            raise ValueError(f"{self.kind} decisions must not contain a tool call")
