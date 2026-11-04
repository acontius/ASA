"""Minimal immutable configuration for a future loopback-only local agent."""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


def _validate_loopback_url(value: object) -> None:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError("server_url must be a non-empty URL without surrounding whitespace")
    if any(char.isspace() for char in value):
        raise ValueError("server_url must not contain whitespace")
    if "?" in value or "#" in value:
        raise ValueError("server_url must not contain a query or fragment")

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid server_url: {exc}") from exc

    if parsed.scheme != "http":
        raise ValueError("server_url must use http")
    if not parsed.netloc or hostname is None:
        raise ValueError("server_url must include a literal loopback IP address")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("server_url must not contain credentials")
    if parsed.path:
        raise ValueError("server_url must not contain a path")
    if "%" in hostname:
        raise ValueError("scoped or percent-encoded IP addresses are not allowed")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError as exc:
        raise ValueError("server_url host must be a literal loopback IP address") from exc

    if not address.is_loopback:
        raise ValueError("server_url host must be a loopback IP address")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("server_url port must be between 1 and 65535")


@dataclass(frozen=True, slots=True)
class AgentConfig:
    """Conservative limits for local inference; no environment or I/O behavior."""

    server_url: str = "http://127.0.0.1:8080"
    request_timeout_seconds: float = 15.0
    max_steps: int = 5
    max_output_tokens: int = 512
    model_alias: str = "asa-local"

    def __post_init__(self) -> None:
        _validate_loopback_url(self.server_url)

        if (
            not isinstance(self.model_alias, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", self.model_alias) is None
        ):
            raise ValueError("model_alias must be a 1-64 character identifier")

        timeout = self.request_timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("request_timeout_seconds must be a number")
        if not math.isfinite(timeout) or not 0 < timeout <= 120:
            raise ValueError("request_timeout_seconds must be greater than 0 and at most 120")

        if isinstance(self.max_steps, bool) or not isinstance(self.max_steps, int):
            raise ValueError("max_steps must be an integer")
        if not 1 <= self.max_steps <= 10:
            raise ValueError("max_steps must be between 1 and 10")

        if isinstance(self.max_output_tokens, bool) or not isinstance(self.max_output_tokens, int):
            raise ValueError("max_output_tokens must be an integer")
        if not 1 <= self.max_output_tokens <= 2048:
            raise ValueError("max_output_tokens must be between 1 and 2048")
