"""Resolution pipeline tests, including one M2 → M3 pass on a fixture."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import FIXTURES, load_fixture, write_jsonl

from app.cpe.importer import import_dictionary
from app.cpe.pipeline import ResolveError, resolve_outcomes
from app.pipeline import run_pipeline


class TestCpePipeline(unittest.TestCase):
    def test_streaming_provenance_and_bad_lines(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "dict.sqlite"
            import_dictionary(str(FIXTURES / "cpe_dictionary_sample.json"), str(db_path))
            src = Path(tmp) / "outcomes.jsonl"
            dst = Path(tmp) / "resolutions.jsonl"
            rows = [
                {
                    "outcome": "matched",
                    "record_id": "rec-1",
                    "candidates": [
                        {
                            "candidate_id": "c-nginx",
                            "product_name": "nginx",
                            "vendor": None,
                            "version": "1.24.0",
                            "source_path": "t80.http.result.response.headers.server",
                            "raw_value": "nginx/1.24.0",
                            "signal_type": "header",
                            "extractor_id": "http.server_header.v1",
                            "evidence_strength": "strong",
                            "evidence_refs": [],
                            "normalized_record_id": "rec-1",
                        }
                    ],
                },
                {
                    "outcome": "matched",
                    "record_id": "rec-2",
                    "candidates": [
                        {
                            "candidate_id": "c-weak",
                            "product_name": "nginx",
                            "version": "1.24.0",
                            "source_path": "t80.http.result.response.headers.server",
                            "evidence_strength": "weak",
                            "normalized_record_id": "rec-2",
                        }
                    ],
                },
            ]
            src.write_text("\n".join(json.dumps(row) for row in rows) + "\n{bad\n", encoding="utf-8")
            stats = resolve_outcomes(str(src), str(dst), str(db_path))
            self.assertEqual(stats["records"], 3)
            self.assertEqual(stats["errors"], 1)
            lines = dst.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 3)
            first, second, third = [json.loads(line) for line in lines]
            self.assertEqual(first["record_id"], "rec-1")
            self.assertEqual(first["source_outcome"], "matched")
            self.assertEqual(first["candidate_resolutions"][0]["candidate_id"], "c-nginx")
            self.assertEqual(first["candidate_resolutions"][0]["resolution_status"], "exact_match")
            self.assertEqual(first["candidate_resolutions"][0]["source_path"], "t80.http.result.response.headers.server")
            self.assertEqual(second["candidate_resolutions"][0]["resolution_status"], "skipped_weak")
            self.assertEqual(third["record_id"], None)
            self.assertIn("invalid JSON", third["error"])
            again = resolve_outcomes(str(src), str(dst), str(db_path))
            self.assertEqual(again["records"], stats["records"])
            self.assertEqual(dst.read_text(encoding="utf-8"), "\n".join(lines) + "\n")

    def test_refuses_to_overwrite_input(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "dict.sqlite"
            import_dictionary(str(FIXTURES / "cpe_dictionary_sample.json"), str(db_path))
            src = Path(tmp) / "outcomes.jsonl"
            src.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(ResolveError):
                resolve_outcomes(str(src), str(src), str(db_path))

    def test_m2_fixture_then_m3(self):
        with TemporaryDirectory() as tmp:
            scan = Path(tmp) / "scan.jsonl"
            outcomes = Path(tmp) / "outcomes.jsonl"
            resolved = Path(tmp) / "resolved.jsonl"
            db_path = Path(tmp) / "dict.sqlite"
            write_jsonl(scan, [json.dumps(load_fixture("ssh"))])
            run_pipeline(str(scan), str(outcomes))
            import_dictionary(str(FIXTURES / "cpe_dictionary_sample.json"), str(db_path))
            resolve_outcomes(str(outcomes), str(resolved), str(db_path))
            row = json.loads(resolved.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(row["source_outcome"], "matched")
            hit = row["candidate_resolutions"][0]
            self.assertEqual(hit["resolution_status"], "exact_match")
            self.assertEqual(hit["product"], "openssh")
            self.assertEqual(hit["version"], "9.6p1")
            self.assertEqual(hit["vendor"], "openbsd")
            self.assertEqual(hit["part"], "a")
            self.assertTrue(hit["normalized_record_id"])


if __name__ == "__main__":
    unittest.main()
