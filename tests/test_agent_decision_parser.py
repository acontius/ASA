"""Tests for strict parsing of untrusted agent decision JSON."""
from __future__ import annotations

import unittest

from app.agent.contracts import AgentDecision, ToolCall
from app.agent.decision_parser import (
    MAX_DECISION_BYTES,
    DecisionParseError,
    parse_agent_decision,
)


class TestDecisionParser(unittest.TestCase):
    def test_valid_tool_call(self):
        decision = parse_agent_decision(
            '{"kind":"tool_call","message":"Inspect input",'
            '"tool_call":{"name":"inspect_input","arguments":{"input_path":"Data/a.jsonl"}}}'
        )
        self.assertEqual(decision.kind, "tool_call")
        self.assertEqual(
            decision.tool_call,
            ToolCall("inspect_input", (("input_path", "Data/a.jsonl"),)),
        )

    def test_valid_final_answer_and_clarification(self):
        for kind in ("final_answer", "clarification"):
            with self.subTest(kind=kind):
                decision = parse_agent_decision(
                    '{"kind":"' + kind + '","message":"Answer","tool_call":null}'
                )
                self.assertEqual(decision, AgentDecision(kind, "Answer"))

    def test_empty_or_non_string_input_rejected(self):
        for value in ("", "  ", None, 42):
            with self.subTest(value=value), self.assertRaises(DecisionParseError):
                parse_agent_decision(value)

    def test_invalid_json_and_non_object_rejected(self):
        for value in ("{", "[]", "null", '"string"', "NaN"):
            with self.subTest(value=value), self.assertRaises(DecisionParseError):
                parse_agent_decision(value)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(DecisionParseError):
            parse_agent_decision(
                '{"kind":"final_answer","kind":"tool_call",'
                '"message":"x","tool_call":null}'
            )

    def test_unknown_or_missing_top_level_fields_rejected(self):
        payloads = (
            '{"kind":"final_answer","message":"x","tool_call":null,"extra":1}',
            '{"kind":"final_answer","message":"x"}',
        )
        for value in payloads:
            with self.subTest(value=value), self.assertRaises(DecisionParseError):
                parse_agent_decision(value)

    def test_tool_call_shape_and_arguments_are_strict(self):
        payloads = (
            '{"kind":"tool_call","message":"x","tool_call":null}',
            '{"kind":"tool_call","message":"x","tool_call":{"name":"inspect_input"}}',
            '{"kind":"tool_call","message":"x","tool_call":{"name":"inspect_input",'
            '"arguments":{"input_path":1}}}',
            '{"kind":"tool_call","message":"x","tool_call":{"name":"inspect_input",'
            '"arguments":[]}}',
            '{"kind":"tool_call","message":"x","tool_call":{"name":"inspect_input",'
            '"arguments":{},"extra":true}}',
        )
        for value in payloads:
            with self.subTest(value=value), self.assertRaises(DecisionParseError):
                parse_agent_decision(value)

    def test_unknown_tool_and_decision_rejected(self):
        payloads = (
            '{"kind":"tool_call","message":"x","tool_call":{"name":"run_shell",'
            '"arguments":{}}}',
            '{"kind":"run_shell","message":"x","tool_call":null}',
        )
        for value in payloads:
            with self.subTest(value=value), self.assertRaises(DecisionParseError):
                parse_agent_decision(value)

    def test_non_tool_decision_cannot_carry_tool_call(self):
        with self.assertRaises(DecisionParseError):
            parse_agent_decision(
                '{"kind":"final_answer","message":"x","tool_call":'
                '{"name":"inspect_input","arguments":{}}}'
            )

    def test_non_standard_json_constants_rejected(self):
        with self.assertRaises(DecisionParseError):
            parse_agent_decision(
                '{"kind":"final_answer","message":"x","tool_call":null,"x":Infinity}'
            )

    def test_oversized_text_rejected_without_echoing_it(self):
        raw = "z" * (MAX_DECISION_BYTES + 1)
        with self.assertRaises(DecisionParseError) as caught:
            parse_agent_decision(raw)
        self.assertEqual(str(caught.exception), "model response exceeds size limit")
        self.assertNotIn(raw[:32], str(caught.exception))

    def test_deeply_nested_json_raises_decision_parse_error(self):
        raw = "[" * 2000 + "]" * 2000
        with self.assertRaises(DecisionParseError) as caught:
            parse_agent_decision(raw)
        # Python versions differ on whether this valid but deeply nested JSON
        # reaches the non-object contract check or hits the parser recursion
        # limit first. Both outcomes are safely rejected by the parser.
        self.assertIn(
            str(caught.exception),
            {"model response is not valid JSON", "model response must be a JSON object"},
        )
        self.assertLess(len(str(caught.exception)), 200)


if __name__ == "__main__":
    unittest.main()
