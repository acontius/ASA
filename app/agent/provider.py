"""Synchronous, bounded HTTP provider for a loopback llama-server."""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from http.client import HTTPException
from typing import Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from app.agent.config import AgentConfig

MAX_MESSAGES = 16
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024


class ProviderError(RuntimeError):
    """Base class for sanitized local-provider failures."""


class ProviderConnectionError(ProviderError):
    """The configured local server could not be reached."""


class ProviderTimeoutError(ProviderError):
    """The configured local server exceeded the request timeout."""


class ProviderHTTPError(ProviderError):
    """The local server returned an unexpected HTTP status."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"local_model_http_error:{status}")


class ProviderResponseError(ProviderError):
    """The local server returned an invalid or oversized response."""


@dataclass(frozen=True, slots=True)
class ProviderMessage:
    """One ordinary text message; no tool or function schema is representable."""

    role: str
    content: str

    def __post_init__(self) -> None:
        if self.role not in {"system", "user", "assistant"}:
            raise ValueError("role must be system, user, or assistant")
        if not isinstance(self.content, str) or not self.content.strip():
            raise ValueError("content must be non-empty text")


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LocalLlamaCppProvider:
    """Call only the trusted loopback endpoint in an immutable AgentConfig."""

    def __init__(self, config: AgentConfig) -> None:
        if not isinstance(config, AgentConfig):
            raise TypeError("config must be an AgentConfig")
        self._config = config
        # An explicit empty proxy map prevents HTTP_PROXY/ALL_PROXY discovery.
        # Redirects are deliberately not followed, even to another loopback port.
        self._opener = build_opener(ProxyHandler({}), _RejectRedirects())

    def health_check(self) -> bool:
        """Return False only for the server's explicit HTTP 503 not-ready state."""
        response = self._request("GET", "/health", None, allow_not_ready=True)
        if response is None:
            return False
        try:
            payload = json.loads(response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderResponseError("malformed_health_response") from exc
        if not isinstance(payload, dict) or payload != {"status": "ok"}:
            raise ProviderResponseError("invalid_health_response")
        return True

    def complete(self, messages: Sequence[ProviderMessage]) -> str:
        """Send a bounded non-streaming completion and return raw assistant text."""
        normalized = self._validate_messages(messages)
        payload = {
            "model": self._config.model_alias,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in normalized
            ],
            "max_tokens": self._config.max_output_tokens,
            "temperature": 0,
            "stream": False,
        }
        try:
            body = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ProviderResponseError("request_serialization_failed") from exc
        if len(body) > MAX_REQUEST_BYTES:
            raise ProviderResponseError("request_too_large")

        response = self._request("POST", "/v1/chat/completions", body)
        if response is None:  # Only health checks can accept a 503 response.
            raise ProviderHTTPError(503)
        try:
            envelope = json.loads(response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderResponseError("malformed_completion_response") from exc
        return self._extract_content(envelope)

    @staticmethod
    def _validate_messages(
        messages: Sequence[ProviderMessage],
    ) -> tuple[ProviderMessage, ...]:
        if isinstance(messages, (str, bytes, bytearray)) or not isinstance(
            messages, Sequence
        ):
            raise ProviderResponseError("messages_must_be_a_sequence")
        if not 1 <= len(messages) <= MAX_MESSAGES:
            raise ProviderResponseError("invalid_message_count")
        result: list[ProviderMessage] = []
        for message in messages:
            if not isinstance(message, ProviderMessage):
                raise ProviderResponseError("invalid_message")
            result.append(message)
        return tuple(result)

    @staticmethod
    def _extract_content(envelope: object) -> str:
        if not isinstance(envelope, dict):
            raise ProviderResponseError("invalid_completion_envelope")
        choices = envelope.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderResponseError("missing_completion_choice")
        first = choices[0]
        if not isinstance(first, dict):
            raise ProviderResponseError("invalid_completion_choice")
        message = first.get("message")
        if not isinstance(message, dict):
            raise ProviderResponseError("missing_assistant_message")
        if "tool_calls" in message or first.get("finish_reason") == "tool_calls":
            raise ProviderResponseError("native_tool_calls_not_supported")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ProviderResponseError("empty_or_invalid_assistant_content")
        return content

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None,
        *,
        allow_not_ready: bool = False,
    ) -> bytes | None:
        base = self._config.server_url
        # AgentConfig validates the base URL as a literal loopback IP. The
        # destination is derived only from that trusted config, never a message.
        parsed = urlsplit(base)
        url = f"{parsed.scheme}://{parsed.netloc}{path}"
        request = Request(
            url,
            data=body,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method=method,
        )
        try:
            response = self._opener.open(
                request, timeout=self._config.request_timeout_seconds
            )
        except HTTPError as exc:
            if allow_not_ready and exc.code == 503:
                return None
            raise ProviderHTTPError(exc.code) from None
        except (socket.timeout, TimeoutError) as exc:
            raise ProviderTimeoutError("local_model_timeout") from None
        except URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise ProviderTimeoutError("local_model_timeout") from None
            raise ProviderConnectionError("local_model_unavailable") from None
        except (OSError, HTTPException, ValueError) as exc:
            if isinstance(exc, (socket.timeout, TimeoutError)):
                raise ProviderTimeoutError("local_model_timeout") from None
            raise ProviderConnectionError("local_model_unavailable") from None

        try:
            with response:
                status = getattr(response, "status", None)
                if status != 200:
                    raise ProviderHTTPError(
                        status if isinstance(status, int) else 0
                    )
                data = response.read(MAX_RESPONSE_BYTES + 1)
        except ProviderError:
            raise
        except (socket.timeout, TimeoutError):
            raise ProviderTimeoutError("local_model_timeout") from None
        except (OSError, HTTPException):
            raise ProviderConnectionError("local_model_unavailable") from None
        if len(data) > MAX_RESPONSE_BYTES:
            raise ProviderResponseError("response_too_large")
        return data
