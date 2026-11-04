"""Security and behavior tests for the read-only agent tool registry."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.agent.contracts import AgentDecision, ToolCall
from app.agent.tool_registry import ToolDispatchError, ToolLimits, ToolRegistry


def decision(name: str, **arguments: str) -> AgentDecision:
    return AgentDecision(
        "tool_call", f"Call {name}",
        ToolCall(name, tuple(arguments.items())),
    )


class ToolRegistryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("Data", "out", "local-data"):
            (self.root / name).mkdir()
        self.registry = ToolRegistry(self.root)

    def write_jsonl(self, relative: str, lines: list[object]) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "".join(
                (line if isinstance(line, str) else json.dumps(line)) + "\n"
                for line in lines
            ),
            encoding="utf-8",
        )
        return path

    def test_successful_dispatch_for_each_tool(self):
        self.write_jsonl("Data/input.jsonl", [
            {"_source": {"proto": "ssh"}},
            {"_source": {"proto": "https"}},
        ])
        self.write_jsonl("out/m2.jsonl", [
            {"outcome": "matched", "record_id": "r1", "candidates": []},
        ])
        calls = (
            decision("inspect_input", input_path="Data/input.jsonl"),
            decision("check_readiness", input_path="Data/input.jsonl"),
            decision("list_prior_runs"),
            decision("summarize_results", results_path="out/m2.jsonl"),
        )
        results = [self.registry.dispatch(item) for item in calls]
        self.assertTrue(all(result.success for result in results))
        self.assertEqual(results[0].data["recognized_protocol_counts"]["ssh"], 1)
        self.assertFalse(results[2].data["available"])
        self.assertEqual(results[3].data["format"], "m2")

    def test_non_tool_decisions_are_rejected(self):
        for kind in ("final_answer", "clarification"):
            with self.subTest(kind=kind), self.assertRaises(ToolDispatchError):
                self.registry.dispatch(AgentDecision(kind, "No tool call."))

    def test_unknown_tool_is_rejected_even_if_contract_is_bypassed(self):
        call = object.__new__(ToolCall)
        object.__setattr__(call, "name", "run_shell")
        object.__setattr__(call, "arguments", ())
        item = AgentDecision("tool_call", "unsafe", call)
        with self.assertRaises(ToolDispatchError):
            self.registry.dispatch(item)

    def test_missing_and_extra_arguments_are_rejected(self):
        missing = self.registry.dispatch(decision("inspect_input"))
        extra = self.registry.dispatch(
            decision("inspect_input", input_path="Data/a.jsonl", command="cat")
        )
        no_prerequisite = self.registry.dispatch(decision("check_readiness"))
        self.assertFalse(missing.success)
        self.assertEqual(missing.error, "missing_required_arguments")
        self.assertEqual(extra.error, "unexpected_arguments")
        self.assertEqual(no_prerequisite.error, "at_least_one_prerequisite_required")

    def test_absolute_traversal_url_home_and_null_paths_are_rejected(self):
        invalid = (
            "/etc/passwd",
            "../outside.jsonl",
            "Data/../../outside.jsonl",
            "~/secret.jsonl",
            "https://example.invalid/file.jsonl",
            "Data/bad\x00name.jsonl",
        )
        for value in invalid:
            with self.subTest(value=value):
                result = self.registry.dispatch(
                    decision("inspect_input", input_path=value)
                )
                self.assertFalse(result.success)

    def test_hidden_paths_are_rejected(self):
        (self.root / "Data" / ".secret.jsonl").write_text("{}\n")
        result = self.registry.dispatch(
            decision("inspect_input", input_path="Data/.secret.jsonl")
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error, "hidden paths are not allowed")

    def test_symlink_file_and_directory_escape_are_rejected(self):
        outside = self.root.parent / (self.root.name + "-outside.jsonl")
        outside.write_text('{"_source":{"proto":"ssh"}}\n')
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        (self.root / "Data" / "link.jsonl").symlink_to(outside)
        (self.root / "Data" / "linked-dir").symlink_to(outside.parent, target_is_directory=True)
        for path in ("Data/link.jsonl", "Data/linked-dir/" + outside.name):
            with self.subTest(path=path):
                result = self.registry.dispatch(decision("inspect_input", input_path=path))
                self.assertFalse(result.success)

    def test_non_regular_files_are_rejected(self):
        result = self.registry.dispatch(
            decision("inspect_input", input_path="Data")
        )
        self.assertFalse(result.success)

    def test_unconfigured_roots_are_rejected(self):
        (self.root / "private").mkdir()
        (self.root / "private" / "scan.jsonl").write_text("{}\n")
        result = self.registry.dispatch(
            decision("inspect_input", input_path="private/scan.jsonl")
        )
        self.assertFalse(result.success)

    def test_inspection_streams_and_counts_malformed_blank_and_protocols(self):
        path = self.write_jsonl("Data/input.jsonl", [
            {"_source": {"proto": "ftp"}},
            "",
            "{broken",
            {"_source": {"proto": "http"}},
            {"_source": {"proto": "https"}},
            {"_source": {"proto": "ssh"}},
            {"_source": {"proto": "mongodb"}},
            {"_source": {"proto": "telnet"}},
        ])
        before = path.read_bytes()
        result = self.registry.dispatch(
            decision("inspect_input", input_path="Data/input.jsonl")
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data["records_inspected"], 6)
        self.assertEqual(result.data["blank_lines"], 1)
        self.assertEqual(result.data["malformed_lines"], 1)
        self.assertEqual(result.data["recognized_protocol_counts"]["ftp"], 1)
        self.assertEqual(result.data["recognized_protocol_counts"]["http"], 1)
        self.assertEqual(result.data["recognized_protocol_counts"]["https"], 1)
        self.assertEqual(result.data["recognized_protocol_counts"]["ssh"], 1)
        self.assertEqual(result.data["recognized_protocol_counts"]["mongodb"], 1)
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue(result.data["statistics_complete"])

    def test_line_size_limit_stops_and_reports_oversized_line(self):
        self.write_jsonl("Data/large.jsonl", [
            {"_source": {"proto": "ssh", "payload": "x" * 100}},
        ])
        limited = ToolRegistry(
            self.root,
            limits=ToolLimits(max_bytes=256, max_records=10, max_line_bytes=64),
        )
        result = limited.dispatch(decision("inspect_input", input_path="Data/large.jsonl"))
        self.assertTrue(result.success)
        self.assertTrue(result.data["stopped_at_limit"])
        self.assertTrue(result.data["oversized_line"])
        self.assertFalse(result.data["statistics_complete"])

    def test_record_limit_stops_and_reports_partial_statistics(self):
        self.write_jsonl("Data/many.jsonl", [
            {"_source": {"proto": "ssh"}},
            {"_source": {"proto": "ftp"}},
            {"_source": {"proto": "http"}},
        ])
        limited = ToolRegistry(
            self.root,
            limits=ToolLimits(max_bytes=4096, max_records=2, max_line_bytes=1024),
        )
        result = limited.dispatch(decision("inspect_input", input_path="Data/many.jsonl"))
        self.assertEqual(result.data["records_inspected"], 2)
        self.assertTrue(result.data["stopped_at_limit"])
        self.assertFalse(result.data["statistics_complete"])

    def test_byte_limit_stops_and_reports_partial_statistics(self):
        self.write_jsonl("Data/bytes.jsonl", [
            {"_source": {"proto": "ssh"}},
            {"_source": {"proto": "ftp"}},
            {"_source": {"proto": "http"}},
        ])
        limited = ToolRegistry(
            self.root,
            limits=ToolLimits(max_bytes=40, max_records=100, max_line_bytes=40),
        )
        result = limited.dispatch(decision("inspect_input", input_path="Data/bytes.jsonl"))
        self.assertTrue(result.data["stopped_at_limit"])
        self.assertFalse(result.data["statistics_complete"])

    def test_readiness_checks_sqlite_in_read_only_mode(self):
        db = self.root / "local-data" / "cpe.sqlite"
        connection = sqlite3.connect(db)
        connection.execute("CREATE TABLE cpe_entries (id INTEGER PRIMARY KEY)")
        connection.commit()
        connection.close()
        before = db.read_bytes()
        result = self.registry.dispatch(
            decision("check_readiness", cpe_db_path="local-data/cpe.sqlite")
        )
        self.assertTrue(result.success)
        check = result.data["checks"]["cpe_db_path"]
        self.assertTrue(check["ready"])
        self.assertTrue(check["sqlite_read_only"])
        self.assertIn("cpe_entries", check["table_names"])
        self.assertEqual(db.read_bytes(), before)
        self.assertFalse(list(db.parent.glob("*.journal")))
        self.assertFalse(list(db.parent.glob("*.wal")))

    def test_readiness_rejects_non_sqlite_file_without_modifying_it(self):
        db = self.root / "local-data" / "not-db.sqlite"
        db.write_text("not sqlite")
        before = db.read_bytes()
        result = self.registry.dispatch(
            decision("check_readiness", vulnerability_db_path="local-data/not-db.sqlite")
        )
        self.assertTrue(result.success)
        self.assertFalse(result.data["checks"]["vulnerability_db_path"]["ready"])
        self.assertEqual(db.read_bytes(), before)

    def test_prior_runs_never_invents_history(self):
        result = self.registry.dispatch(decision("list_prior_runs"))
        self.assertEqual(
            result.data,
            {
                "available": False,
                "runs": [],
                "reason": "persistent_agent_run_history_not_implemented",
            },
        )

    def test_m2_m3_m4_summaries_use_authoritative_fields(self):
        m2 = self.write_jsonl("out/m2.jsonl", [
            {"outcome": "matched", "record_id": "m2-1", "candidates": []},
            {"outcome": "no_match", "record_id": "m2-2", "candidates": []},
            "{invalid",
        ])
        m3 = self.write_jsonl("out/m3.jsonl", [
            {"record_id": "m3-1", "candidate_resolutions": [
                {"resolution_status": "exact_match"},
                {"resolution_status": "review_required"},
            ]},
        ])
        m4 = self.write_jsonl("out/m4.jsonl", [
            {"record_id": "m4-1", "dataset_status": "assessed", "cve_assessments": [
                {"assessment_status": "potentially_affected"},
                {"assessment_status": "rejected"},
            ]},
            {"record_id": "m4-2", "dataset_status": "not_evaluated", "cve_assessments": []},
        ])
        originals = [path.read_bytes() for path in (m2, m3, m4)]
        r2 = self.registry.dispatch(decision("summarize_results", results_path="out/m2.jsonl"))
        r3 = self.registry.dispatch(decision("summarize_results", results_path="out/m3.jsonl"))
        r4 = self.registry.dispatch(decision("summarize_results", results_path="out/m4.jsonl"))
        self.assertEqual(r2.data["counts"], {"matched": 1, "no_match": 1})
        self.assertEqual(r2.data["malformed_records"], 1)
        self.assertEqual(r3.data["counts"], {"exact_match": 1, "review_required": 1})
        self.assertEqual(r4.data["dataset_status_counts"], {"assessed": 1, "not_evaluated": 1})
        self.assertEqual(
            r4.data["assessment_status_counts"],
            {"potentially_affected": 1, "rejected": 1},
        )
        self.assertEqual([path.read_bytes() for path in (m2, m3, m4)], originals)
        self.assertNotIn("confirmed_vulnerable", r4.data["assessment_status_counts"])

    def test_summary_limit_reports_truncation(self):
        self.write_jsonl("out/large-m2.jsonl", [
            {"outcome": "matched", "record_id": f"r{i}", "candidates": []}
            for i in range(4)
        ])
        limited = ToolRegistry(
            self.root,
            limits=ToolLimits(max_bytes=4096, max_records=2, max_line_bytes=1024),
        )
        result = limited.dispatch(
            decision("summarize_results", results_path="out/large-m2.jsonl")
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data["records_summarized"], 2)
        self.assertTrue(result.data["truncated"])
        self.assertFalse(result.data["statistics_complete"])

    def test_unrecognized_results_are_controlled_errors(self):
        self.write_jsonl("out/unknown.jsonl", [{"secret": "not exposed"}])
        result = self.registry.dispatch(
            decision("summarize_results", results_path="out/unknown.jsonl")
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error, "unrecognized_or_empty_results_file")
        self.assertNotIn("secret", json.dumps(result.to_dict()))


if __name__ == "__main__":
    unittest.main()
