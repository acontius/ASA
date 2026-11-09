import json
import unittest
from unittest.mock import patch

from benchmarks.cpe.src.agent import run_agent


class FakeLookup:
    def __init__(self):
        self.calls = 0

    def lookup(self, product, version=None, vendor=None):
        self.calls += 1
        return [{"cpe_name": "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"}]


def extraction(abstain=False, product="OpenSSH"):
    return {"product_name": None if abstain else product, "vendor": "OpenBSD", "version": "9.6p1",
            "update": None, "part": "a", "cpe_candidates": [],
            "evidence_paths": ["_source.t22.ssh.result.server_id.software"],
            "abstain": abstain, "explanation": "synthetic fixture"}


def response(parsed, latency=.1, tokens=10):
    return {"raw_response": json.dumps(parsed), "latency_seconds": latency, "ttft_seconds": .02,
            "prompt_tokens": tokens, "completion_tokens": tokens, "error": None}


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.raw = {"_source": {"t22": {"ssh": {"result": {"server_id": {"software": "OpenSSH_9.6p1"}}}}}}

    def test_explicit_abstention_skips_m3_lookup(self):
        lookup = FakeLookup()
        with patch("benchmarks.cpe.src.agent.call_local", return_value=response(extraction(abstain=True))):
            result = run_agent(self.raw, "r", "qwen", lookup, "http://127.0.0.1:8080")
        self.assertTrue(result["cpe_abstain"])
        self.assertTrue(result["parsed"]["abstain"])
        self.assertEqual(result["model_calls"], 1)
        self.assertEqual(result["tool_calls"], 0)
        self.assertEqual(lookup.calls, 0)

    def test_one_model_call_budget_uses_one_lookup_then_abstains(self):
        lookup = FakeLookup()
        with patch("benchmarks.cpe.src.agent.call_local", return_value=response(extraction())) as call:
            result = run_agent(self.raw, "r", "qwen", lookup, "http://127.0.0.1:8080", max_model_calls=1)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(result["model_calls"], 1)
        self.assertEqual(result["tool_calls"], 1)
        self.assertTrue(result["cpe_abstain"])
        self.assertFalse(result["parsed"]["abstain"])

    def test_final_cpe_must_be_selected_from_tool_candidates_and_usage_is_aggregated(self):
        chosen = extraction()
        chosen["cpe_candidates"] = ["cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"]
        chosen["abstain"] = False
        lookup = FakeLookup()
        with patch("benchmarks.cpe.src.agent.call_local", side_effect=[response(extraction(), .1, 10), response(chosen, .2, 20)]):
            result = run_agent(self.raw, "r", "qwen", lookup, "http://127.0.0.1:8080")
        self.assertEqual(result["parsed"]["cpe_candidates"], chosen["cpe_candidates"])
        self.assertEqual(result["prompt_tokens"], 30)
        self.assertEqual(result["completion_tokens"], 30)
        self.assertAlmostEqual(result["latency_seconds"], .3)
        self.assertEqual(result["model_calls"], 2)
        self.assertEqual(result["tool_calls"], 1)

    def test_cpe_selection_abstention_does_not_erase_successful_extraction(self):
        selection = extraction(abstain=True)
        lookup = FakeLookup()
        with patch("benchmarks.cpe.src.agent.call_local", side_effect=[response(extraction(), .1, 10), response(selection, .2, 20)]):
            result = run_agent(self.raw, "r", "qwen", lookup, "http://127.0.0.1:8080")
        self.assertFalse(result["extraction_parsed"]["abstain"])
        self.assertTrue(result["cpe_abstain"])
        self.assertEqual(result["extraction_parsed"]["product_name"], "OpenSSH")
        self.assertEqual(result["parsed"]["cpe_candidates"], [])

    def test_invalid_extraction_path_stops_before_lookup(self):
        bad = extraction(); bad["evidence_paths"] = ["_source.missing"]
        lookup = FakeLookup()
        with patch("benchmarks.cpe.src.agent.call_local", return_value=response(bad)):
            result = run_agent(self.raw, "r", "qwen", lookup, "http://127.0.0.1:8080")
        self.assertFalse(result["schema_valid"])
        self.assertEqual(result["invalid_reason"], "evidence_path_not_found")
        self.assertEqual(result["tool_calls"], 0)
        self.assertEqual(lookup.calls, 0)


if __name__ == "__main__":
    unittest.main()
