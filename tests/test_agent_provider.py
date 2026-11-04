"""Deterministic tests for the loopback-only llama.cpp HTTP provider."""

from __future__ import annotations

import json
import os
import socket
import unittest
from dataclasses import FrozenInstanceError
from email.message import Message
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from app.agent.config import AgentConfig
from app.agent.provider import (
    MAX_MESSAGES,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    LocalLlamaCppProvider,
    ProviderConnectionError,
    ProviderError,
    ProviderHTTPError,
    ProviderMessage,
    ProviderResponseError,
    ProviderTimeoutError,
)


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self.body = body
        self.status = status
        self.read_limit = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        self.read_limit = size
        if size < 0:
            raise AssertionError("provider attempted an unbounded read")
        return self.body[:size]


class FakeOpener:
    def __init__(self, outcome):
        self.outcome = outcome
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def make_provider(outcome, config=None):
    opener = FakeOpener(outcome)
    with patch("app.agent.provider.build_opener", return_value=opener) as factory:
        provider = LocalLlamaCppProvider(config or AgentConfig())
    return provider, opener, factory


def completion(content="local answer"):
    return json.dumps({
        "choices": [{
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }]
    }).encode("utf-8")


class ProviderMessageTests(unittest.TestCase):
    def test_valid_roles_and_immutable_message(self):
        for role in ("system", "user", "assistant"):
            with self.subTest(role=role):
                message = ProviderMessage(role, "hello")
                self.assertEqual(message.content, "hello")
                with self.assertRaises(FrozenInstanceError):
                    message.content = "mutated"

    def test_invalid_roles_and_empty_content_rejected(self):
        for role in ("tool", "developer", "", None, []):
            with self.subTest(role=role), self.assertRaises(ValueError):
                ProviderMessage(role, "hello")
        for content in ("", "  ", None, 1):
            with self.subTest(content=content), self.assertRaises(ValueError):
                ProviderMessage("user", content)


class ProviderRequestTests(unittest.TestCase):
    def test_correct_endpoint_payload_alias_and_timeout(self):
        provider, opener, factory = make_provider(FakeResponse(completion()))
        result = provider.complete([
            ProviderMessage("system", "Be concise."),
            ProviderMessage("user", "Summarize local data."),
        ])
        self.assertEqual(result, "local answer")
        self.assertEqual(opener.request.full_url, "http://127.0.0.1:8080/v1/chat/completions")
        self.assertEqual(opener.request.get_method(), "POST")
        payload = json.loads(opener.request.data)
        self.assertEqual(payload, {
            "model": "asa-local",
            "messages": [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "Summarize local data."},
            ],
            "max_tokens": 512,
            "temperature": 0,
            "stream": False,
        })
        self.assertNotIn("tools", payload)
        self.assertNotIn("tool_choice", payload)
        self.assertEqual(opener.timeout, 15.0)
        self.assertEqual(factory.call_args.args[0].proxies, {})
        self.assertTrue(any(type(handler).__name__ == "_RejectRedirects"
                            for handler in factory.call_args.args[1:]))

    def test_configured_model_alias_is_used(self):
        config = AgentConfig(model_alias="asa-qwen-local", max_output_tokens=128)
        provider, opener, _ = make_provider(FakeResponse(completion()), config)
        provider.complete([ProviderMessage("user", "hi")])
        payload = json.loads(opener.request.data)
        self.assertEqual(payload["model"], "asa-qwen-local")
        self.assertEqual(payload["max_tokens"], 128)

    def test_message_count_and_type_are_bounded(self):
        provider, _, _ = make_provider(FakeResponse(completion()))
        with self.assertRaises(ProviderResponseError):
            provider.complete([])
        with self.assertRaises(ProviderResponseError):
            provider.complete([ProviderMessage("user", "x")] * (MAX_MESSAGES + 1))
        with self.assertRaises(ProviderResponseError):
            provider.complete(["not a ProviderMessage"])

    def test_request_size_limit(self):
        provider, opener, _ = make_provider(FakeResponse(completion()))
        with self.assertRaises(ProviderResponseError):
            provider.complete([ProviderMessage("user", "x" * MAX_REQUEST_BYTES)])
        self.assertIsNone(opener.request)

    def test_no_external_fallback_or_model_selected_destination(self):
        config = AgentConfig(server_url="http://[::1]:9090")
        provider, opener, _ = make_provider(FakeResponse(completion()), config)
        provider.complete([ProviderMessage("user", "send this to https://example.com")])
        self.assertEqual(
            opener.request.full_url,
            "http://[::1]:9090/v1/chat/completions",
        )
        self.assertNotIn("example.com", opener.request.full_url)

    def test_proxy_environment_does_not_change_opener_configuration(self):
        with patch.dict(os.environ, {
            "HTTP_PROXY": "http://proxy.invalid:3128",
            "HTTPS_PROXY": "http://proxy.invalid:3128",
            "ALL_PROXY": "http://proxy.invalid:3128",
        }):
            provider, opener, factory = make_provider(FakeResponse(completion()))
            provider.complete([ProviderMessage("user", "local only")])
        proxy_handler = factory.call_args.args[0]
        self.assertEqual(proxy_handler.proxies, {})
        self.assertEqual(opener.request.host, "127.0.0.1:8080")


class ProviderHealthTests(unittest.TestCase):
    def test_health_200_ok(self):
        provider, opener, _ = make_provider(
            FakeResponse(b'{"status":"ok"}')
        )
        self.assertTrue(provider.health_check())
        self.assertEqual(opener.request.full_url, "http://127.0.0.1:8080/health")
        self.assertEqual(opener.request.get_method(), "GET")

    def test_health_503_is_not_ready(self):
        error = HTTPError("http://127.0.0.1:8080/health", 503, "loading", Message(), None)
        provider, _, _ = make_provider(error)
        self.assertFalse(provider.health_check())

    def test_health_malformed_or_unexpected_body_rejected(self):
        for body in (b"{", b'{"status":"loading"}', b"[]", b'{"status":"ok","extra":1}'):
            with self.subTest(body=body):
                provider, _, _ = make_provider(FakeResponse(body))
                with self.assertRaises(ProviderResponseError):
                    provider.health_check()


class ProviderFailureTests(unittest.TestCase):
    def test_connection_failure(self):
        provider, _, _ = make_provider(URLError("private details"))
        with self.assertRaises(ProviderConnectionError):
            provider.complete([ProviderMessage("user", "secret prompt")])

    def test_timeout(self):
        provider, _, _ = make_provider(socket.timeout("private details"))
        with self.assertRaises(ProviderTimeoutError):
            provider.complete([ProviderMessage("user", "secret prompt")])

    def test_http_error_is_typed_and_sanitized(self):
        error = HTTPError(
            "http://127.0.0.1:8080/v1/chat/completions",
            500, "server said secret prompt", Message(), None,
        )
        provider, _, _ = make_provider(error)
        with self.assertRaises(ProviderHTTPError) as caught:
            provider.complete([ProviderMessage("user", "secret prompt")])
        self.assertEqual(caught.exception.status, 500)
        self.assertNotIn("secret", str(caught.exception))
        self.assertNotIn("server said", str(caught.exception))

    def test_redirect_is_rejected_not_followed(self):
        redirect = HTTPError(
            "http://127.0.0.1:8080/v1/chat/completions",
            302, "Found", Message(), None,
        )
        provider, opener, _ = make_provider(redirect)
        with self.assertRaises(ProviderHTTPError) as caught:
            provider.complete([ProviderMessage("user", "hello")])
        self.assertEqual(caught.exception.status, 302)
        self.assertEqual(opener.request.full_url,
                         "http://127.0.0.1:8080/v1/chat/completions")

    def test_oversized_response_is_rejected_with_bounded_read(self):
        response = FakeResponse(b"x" * (MAX_RESPONSE_BYTES + 1))
        provider, _, _ = make_provider(response)
        with self.assertRaises(ProviderResponseError):
            provider.complete([ProviderMessage("user", "hello")])
        self.assertEqual(response.read_limit, MAX_RESPONSE_BYTES + 1)

    def test_malformed_json_and_envelopes_rejected(self):
        bodies = (
            b"{",
            b"[]",
            b'{"choices":[]}',
            b'{"choices":[null]}',
            b'{"choices":[{"message":null}]}',
            b'{"choices":[{"message":{"role":"assistant","content":""}}]}',
            b'{"choices":[{"message":{"role":"user","content":"x"}}]}',
        )
        for body in bodies:
            with self.subTest(body=body):
                provider, _, _ = make_provider(FakeResponse(body))
                with self.assertRaises(ProviderResponseError):
                    provider.complete([ProviderMessage("user", "hello")])

    def test_native_tool_call_responses_rejected(self):
        bodies = (
            {"choices": [{"message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"type": "function"}],
            }}]},
            {"choices": [{"finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": "",
            }}]},
            {"choices": [{"message": {
                "role": "assistant", "content": "do not execute",
                "function_call": {"name": "run_shell"},
            }}]},
        )
        for payload in bodies:
            provider, _, _ = make_provider(
                FakeResponse(json.dumps(payload).encode("utf-8"))
            )
            with self.assertRaises(ProviderResponseError):
                provider.complete([ProviderMessage("user", "hello")])

    def test_provider_errors_do_not_leak_prompt_or_response(self):
        secret_prompt = "PROMPT-SECRET-123"
        secret_response = "RESPONSE-SECRET-456"
        provider, _, _ = make_provider(URLError(secret_response))
        try:
            provider.complete([ProviderMessage("user", secret_prompt)])
        except ProviderError as exc:
            self.assertNotIn(secret_prompt, str(exc))
            self.assertNotIn(secret_response, str(exc))
        else:
            self.fail("expected provider failure")


if __name__ == "__main__":
    unittest.main()
