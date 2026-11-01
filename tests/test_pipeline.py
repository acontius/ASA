"""End-to-end pipeline tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import FIXTURES, load_fixture, write_jsonl

from app.ingestion.checkpoint import load_checkpoint
from app.ingestion.reader import iter_jsonl_records
from app.pipeline import PipelineError, run_pipeline


def _line(name: str) -> str:
    return json.dumps(load_fixture(name), ensure_ascii=False)


class TestPipeline(unittest.TestCase):
    def test_incremental_output_and_provenance(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.jsonl"
            dst = Path(tmp) / "out.jsonl"
            ckpt = Path(tmp) / "c.json"
            write_jsonl(
                src,
                [
                    _line("ssh"),
                    "{bad",
                    _line("unsupported"),
                    _line("ftp"),
                    _line("http"),
                    _line("mongodb"),
                ],
            )
            stats = run_pipeline(str(src), str(dst), str(ckpt))
            self.assertEqual(stats["processed"], 6)
            self.assertEqual(stats["errors"], 1)
            lines = dst.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 6)
            outcomes = [json.loads(line) for line in lines]
            kinds = [item["outcome"] for item in outcomes]
            self.assertEqual(
                kinds,
                [
                    "matched",
                    "processing_error",
                    "unsupported_protocol",
                    "matched",
                    "matched",
                    "matched",
                ],
            )
            self.assertIn("source_path=", outcomes[0]["notes"])
            self.assertIn("scan_time=1762417273", outcomes[0]["notes"])
            self.assertEqual(outcomes[0]["candidates"][0]["product_name"], "OpenSSH")
            loaded = load_checkpoint(str(ckpt), input_size=src.stat().st_size)
            self.assertEqual(loaded.next_offset, src.stat().st_size)
            self.assertEqual(loaded.records_completed, 6)

    def test_resume_does_not_skip_or_drop_the_tail(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.jsonl"
            dst = Path(tmp) / "out.jsonl"
            ckpt = Path(tmp) / "c.json"
            write_jsonl(src, [_line("ssh"), _line("http"), _line("mongodb")])
            items = list(iter_jsonl_records(str(src)))
            # Process only the first record by truncating a copy, then resume on the full file.
            partial = Path(tmp) / "partial.jsonl"
            partial.write_bytes(src.read_bytes()[: items[0].next_offset])
            run_pipeline(str(partial), str(dst), str(ckpt))
            self.assertEqual(len(dst.read_text(encoding="utf-8").splitlines()), 1)
            stats = run_pipeline(str(src), str(dst), str(ckpt), resume=True)
            self.assertEqual(stats["processed"], 2)
            lines = dst.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 3)
            ids = [json.loads(line)["record_id"] for line in lines]
            self.assertEqual(len(ids), len(set(ids)))

    def test_refuses_to_overwrite_input(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.jsonl"
            write_jsonl(src, [_line("ssh")])
            with self.assertRaises(PipelineError):
                run_pipeline(str(src), str(src))

    def test_sample_file_streams_without_loading_api(self):
        sample = FIXTURES.parents[1] / "Data" / "PartOfMe.json"
        if not sample.exists():
            self.skipTest("sample dataset not present")
        with TemporaryDirectory() as tmp:
            dst = Path(tmp) / "out.jsonl"
            stats = run_pipeline(str(sample), str(dst))
            self.assertGreater(stats["processed"], 1000)
            # Output exists and first line is a single outcome object.
            with dst.open(encoding="utf-8") as handle:
                first = handle.readline()
            parsed = json.loads(first)
            self.assertIn(parsed["outcome"], {
                "matched",
                "ambiguous",
                "no_match",
                "insufficient_evidence",
                "processing_error",
                "unsupported_protocol",
            })


if __name__ == "__main__":
    unittest.main()
