"""Bounded local-agent contracts, provider, read-only tools, parser, and loop."""

from app.agent.config import AgentConfig
from app.agent.provider import (
    LocalLlamaCppProvider,
    ProviderConnectionError,
    ProviderError,
    ProviderHTTPError,
    ProviderMessage,
    ProviderResponseError,
    ProviderTimeoutError,
)
from app.agent.contracts import (
    AgentDecision,
    AgentRequest,
    DecisionType,
    ToolCall,
    ToolName,
)
from app.agent.runner import AgentRunResult, run_agent
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
    "AgentRunResult",
    "AgentRunState",
    "DecisionType",
    "InvalidTransitionError",
    "LocalLlamaCppProvider",
    "ProviderConnectionError",
    "ProviderError",
    "ProviderHTTPError",
    "ProviderMessage",
    "ProviderResponseError",
    "ProviderTimeoutError",
    "RunStatus",
    "StepLimitExceeded",
    "ToolCall",
    "ToolDispatchError",
    "ToolLimits",
    "ToolName",
    "ToolRegistry",
    "ToolResult",
    "run_agent",
]
