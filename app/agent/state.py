"""Small immutable state machine for bounded agent runs."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum


class RunStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    WAITING_FOR_USER = "waiting_for_user"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATES = frozenset(
    {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}
)

ALLOWED_TRANSITIONS = {
    RunStatus.CREATED: frozenset({RunStatus.RUNNING, RunStatus.FAILED, RunStatus.CANCELLED}),
    RunStatus.RUNNING: frozenset(
        {
            RunStatus.WAITING_FOR_USER,
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.WAITING_FOR_USER: frozenset(
        {RunStatus.RUNNING, RunStatus.FAILED, RunStatus.CANCELLED}
    ),
    RunStatus.COMPLETED: frozenset(),
    RunStatus.FAILED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
}


class InvalidTransitionError(ValueError):
    """Raised when a run attempts a transition outside the state graph."""


class StepLimitExceeded(ValueError):
    """Raised when a run attempts to exceed its configured step budget."""


@dataclass(frozen=True, slots=True)
class AgentRunState:
    """Immutable run snapshot; methods return a new validated snapshot."""

    status: RunStatus = RunStatus.CREATED
    steps_completed: int = 0
    max_steps: int = 5

    def __post_init__(self) -> None:
        if not isinstance(self.status, RunStatus):
            raise ValueError("status must be a RunStatus")
        if isinstance(self.steps_completed, bool) or not isinstance(self.steps_completed, int):
            raise ValueError("steps_completed must be an integer")
        if isinstance(self.max_steps, bool) or not isinstance(self.max_steps, int):
            raise ValueError("max_steps must be an integer")
        if self.max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        if self.steps_completed < 0 or self.steps_completed > self.max_steps:
            raise ValueError("steps_completed must be between 0 and max_steps")

    def transition(self, target: RunStatus) -> "AgentRunState":
        """Return a new state after validating the requested transition."""
        if not isinstance(target, RunStatus):
            raise InvalidTransitionError("target must be a RunStatus")
        if target not in ALLOWED_TRANSITIONS[self.status]:
            raise InvalidTransitionError(
                f"transition {self.status.value!r} -> {target.value!r} is not allowed"
            )
        if target is RunStatus.RUNNING and self.steps_completed >= self.max_steps:
            raise StepLimitExceeded("run has exhausted its step budget")
        return replace(self, status=target)

    def record_step(self) -> "AgentRunState":
        """Count one completed bounded step while the run is active."""
        if self.status is not RunStatus.RUNNING:
            raise InvalidTransitionError("steps can only be recorded while running")
        if self.steps_completed >= self.max_steps:
            raise StepLimitExceeded("run has exhausted its step budget")
        return replace(self, steps_completed=self.steps_completed + 1)
