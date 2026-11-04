"""Focused tests for the bounded local-agent foundation."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from app.agent.config import AgentConfig
from app.agent.contracts import AgentDecision, AgentRequest, ToolCall
from app.agent.state import (
    AgentRunState,
    InvalidTransitionError,
    RunStatus,
    StepLimitExceeded,
)


class TestInteractionContracts(unittest.TestCase):
    def test_valid_request(self):
        request = AgentRequest(request_id="req-1", message="Summarize this local scan.")
        self.assertEqual(request.request_id, "req-1")

    def test_empty_request_fields_rejected(self):
        for kwargs in (
            {"request_id": "", "message": "hello"},
            {"request_id": "req-1", "message": "  "},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                AgentRequest(**kwargs)

    def test_valid_tool_call_decision(self):
        call = ToolCall("inspect_input", (("input_path", "scan.jsonl"),))
        decision = AgentDecision("tool_call", "Inspect the selected local input.", call)
        self.assertEqual(decision.tool_call.name, "inspect_input")

    def test_each_allow_listed_tool_is_accepted(self):
        for name in (
            "inspect_input",
            "check_readiness",
            "list_prior_runs",
            "summarize_results",
        ):
            with self.subTest(name=name):
                self.assertEqual(ToolCall(name).name, name)

    def test_unknown_tool_name_rejected(self):
        with self.assertRaises(ValueError):
            ToolCall("run_shell_command")

    def test_tool_arguments_must_be_immutable_string_pairs(self):
        with self.assertRaises(ValueError):
            ToolCall("inspect_input", {"path": "scan.jsonl"})
        with self.assertRaises(ValueError):
            ToolCall("inspect_input", (("path", "a"), ("path", "b")))
        with self.assertRaises(ValueError):
            ToolCall("inspect_input", (("", "value"),))

    def test_final_answer_cannot_contain_tool_call(self):
        with self.assertRaises(ValueError):
            AgentDecision("final_answer", "Done.", ToolCall("inspect_input"))

    def test_clarification_cannot_contain_tool_call(self):
        with self.assertRaises(ValueError):
            AgentDecision("clarification", "Which file?", ToolCall("inspect_input"))

    def test_tool_call_requires_exactly_one_tool_call(self):
        with self.assertRaises(ValueError):
            AgentDecision("tool_call", "Inspect.", None)
        with self.assertRaises(ValueError):
            AgentDecision("tool_call", "Inspect.", [ToolCall("inspect_input")])

    def test_unknown_decision_and_empty_message_rejected(self):
        with self.assertRaises(ValueError):
            AgentDecision("execute_code", "No.")
        with self.assertRaises(ValueError):
            AgentDecision("final_answer", " ")

    def test_contracts_are_immutable(self):
        request = AgentRequest("req-1", "hello")
        with self.assertRaises(FrozenInstanceError):
            request.message = "changed"


class TestRunState(unittest.TestCase):
    def test_allowed_transitions(self):
        state = AgentRunState()
        state = state.transition(RunStatus.RUNNING)
        state = state.record_step()
        state = state.transition(RunStatus.WAITING_FOR_USER)
        state = state.transition(RunStatus.RUNNING)
        state = state.transition(RunStatus.COMPLETED)
        self.assertEqual(state.status, RunStatus.COMPLETED)
        self.assertEqual(state.steps_completed, 1)

    def test_created_can_fail_or_cancel(self):
        self.assertEqual(
            AgentRunState().transition(RunStatus.FAILED).status, RunStatus.FAILED
        )
        self.assertEqual(
            AgentRunState().transition(RunStatus.CANCELLED).status, RunStatus.CANCELLED
        )

    def test_forbidden_transitions(self):
        for start, target in (
            (RunStatus.CREATED, RunStatus.COMPLETED),
            (RunStatus.CREATED, RunStatus.WAITING_FOR_USER),
            (RunStatus.RUNNING, RunStatus.CREATED),
            (RunStatus.WAITING_FOR_USER, RunStatus.COMPLETED),
        ):
            with self.subTest(start=start, target=target):
                with self.assertRaises(InvalidTransitionError):
                    AgentRunState(status=start).transition(target)

    def test_terminal_states_cannot_transition(self):
        for terminal in (
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        ):
            state = AgentRunState(status=RunStatus.RUNNING).transition(terminal)
            for target in RunStatus:
                with self.subTest(terminal=terminal, target=target):
                    with self.assertRaises(InvalidTransitionError):
                        state.transition(target)

    def test_step_count_only_increments_while_running(self):
        with self.assertRaises(InvalidTransitionError):
            AgentRunState().record_step()
        state = AgentRunState().transition(RunStatus.RUNNING).record_step()
        self.assertEqual(state.steps_completed, 1)

    def test_maximum_step_count_is_enforced(self):
        state = AgentRunState(max_steps=2).transition(RunStatus.RUNNING)
        state = state.record_step().record_step()
        self.assertEqual(state.steps_completed, 2)
        with self.assertRaises(StepLimitExceeded):
            state.record_step()
        with self.assertRaises(StepLimitExceeded):
            state.transition(RunStatus.WAITING_FOR_USER).transition(RunStatus.RUNNING)

    def test_invalid_run_limits_rejected(self):
        for kwargs in (
            {"max_steps": 0},
            {"max_steps": True},
            {"steps_completed": -1},
            {"steps_completed": 2, "max_steps": 1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                AgentRunState(**kwargs)


class TestAgentConfig(unittest.TestCase):
    def test_default_config(self):
        config = AgentConfig()
        self.assertEqual(config.server_url, "http://127.0.0.1:8080")
        self.assertEqual(config.request_timeout_seconds, 15.0)
        self.assertEqual(config.max_steps, 5)
        self.assertEqual(config.max_output_tokens, 512)

    def test_loopback_urls_accepted(self):
        for url in (
            "http://127.0.0.1:8080",
            "http://127.1.2.3:9000",
            "http://[::1]:8080",
            "http://127.0.0.1",
        ):
            with self.subTest(url=url):
                self.assertEqual(AgentConfig(server_url=url).server_url, url)

    def test_remote_and_non_literal_hosts_rejected(self):
        for url in (
            "http://example.com:8080",
            "https://127.0.0.1:8080",
            "http://localhost:8080",
            "http://192.168.1.10:8080",
            "http://0.0.0.0:8080",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                AgentConfig(server_url=url)

    def test_credentials_paths_queries_and_fragments_rejected(self):
        for url in (
            "http://user:pass@127.0.0.1:8080",
            "http://127.0.0.1:8080/v1",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8080?mode=local",
            "http://127.0.0.1:8080#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                AgentConfig(server_url=url)

    def test_invalid_ports_and_malformed_urls_rejected(self):
        for url in (
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:abc",
            "http://[::1",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                AgentConfig(server_url=url)

    def test_numeric_limits_rejected(self):
        invalid = (
            {"request_timeout_seconds": 0},
            {"request_timeout_seconds": 121},
            {"request_timeout_seconds": float("inf")},
            {"request_timeout_seconds": True},
            {"max_steps": 0},
            {"max_steps": 11},
            {"max_steps": True},
            {"max_output_tokens": 0},
            {"max_output_tokens": 2049},
            {"max_output_tokens": False},
        )
        for kwargs in invalid:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                AgentConfig(**kwargs)

    def test_config_is_immutable(self):
        config = AgentConfig()
        with self.assertRaises(FrozenInstanceError):
            config.max_steps = 8


if __name__ == "__main__":
    unittest.main()
