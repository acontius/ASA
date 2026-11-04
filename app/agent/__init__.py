"""Bounded, local agent contracts and run-state primitives.

This package intentionally contains no model runtime, network client, or tool executor.
"""

from app.agent.config import AgentConfig
from app.agent.contracts import (
    AgentDecision,
    AgentRequest,
    DecisionType,
    ToolCall,
    ToolName,
)
from app.agent.tool_registry import ToolDispatchError, ToolLimits, ToolRegistry, ToolResult
from app.agent.state import (
    AgentRunState,
    InvalidTransitionError,
    RunStatus,
    StepLimitExceeded,
)

__all__ = [
    "AgentConfig",
    "AgentDecision",
    "AgentRequest",
    "AgentRunState",
    "DecisionType",
    "InvalidTransitionError",
    "RunStatus",
    "StepLimitExceeded",
    "ToolCall",
    "ToolDispatchError",
    "ToolLimits",
    "ToolName",
    "ToolRegistry",
    "ToolResult",
]
