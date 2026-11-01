"""Streaming JSONL reader tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import write_jsonl

from app.ingestion.checkpoint import CheckpointError, load_checkpoint, save_checkpoint, Checkpoint
from app.ingestion.reader import iter_jsonl_records


class TestReader(unittest.TestCase):
    def test_incremental_offsets_and_line_numbers(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "in.jsonl"
            write_jsonl(path, ['{"a": 1}', '{"b": 2}'])
            items = list(iter_jsonl_records(str(path)))
            self.assertEqual([i.line_number for i in items], [1, 2])
            self.assertEqual(items[0].byte_offset, 0)
            self.assertEqual(items[1].byte_offset, items[0].next_offset)
            self.assertEqual(items[0].document, {"a": 1})
            self.assertIsNone(items[0].error)
            # Does not return a materialized list from the reader itself.
            self.assertTrue(hasattr(iter_jsonl_records(str(path)), "__next__"))

    def test_malformed_and_empty_and_no_trailing_newline(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "in.jsonl"
            path.write_bytes(b'{"ok": true}\n{bad\n{"tail": 1}')
            items = list(iter_jsonl_records(str(path)))
            self.assertEqual(len(items), 3)
            self.assertEqual(items[0].document, {"ok": True})
            self.assertIsNotNone(items[1].error)
            self.assertIn("invalid JSON", items[1].error or "")
            self.assertEqual(items[2].document, {"tail": 1})
            self.assertFalse(path.read_bytes().endswith(b"\n"))

            empty = Path(tmp) / "empty.jsonl"
            empty.write_bytes(b"")
            self.assertEqual(list(iter_jsonl_records(str(empty))), [])

    def test_resume_offset_skips_prior_bytes(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "in.jsonl"
            write_jsonl(path, ['{"n": 1}', '{"n": 2}', '{"n": 3}'])
            first = list(iter_jsonl_records(str(path)))
            rest = list(iter_jsonl_records(str(path), start_offset=first[0].next_offset))
            self.assertEqual([i.document["n"] for i in rest], [2, 3])
            self.assertEqual(rest[0].line_number, 2)

    def test_non_object_json(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "in.jsonl"
            write_jsonl(path, ["[1, 2]"])
            item = next(iter_jsonl_records(str(path)))
            self.assertIsNone(item.document)
            self.assertIn("expected JSON object", item.error or "")


class TestCheckpoint(unittest.TestCase):
    def test_roundtrip_and_invalid(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.json"
            save_checkpoint(str(path), Checkpoint(next_offset=12, records_completed=3))
            loaded = load_checkpoint(str(path), input_size=20)
            self.assertEqual(loaded.next_offset, 12)
            self.assertEqual(loaded.records_completed, 3)
            path.write_text(json.dumps({"version": 9, "next_offset": 0}), encoding="utf-8")
            with self.assertRaises(CheckpointError):
                load_checkpoint(str(path))
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(CheckpointError):
                load_checkpoint(str(path))
            path.write_text(
                json.dumps({"version": 1, "next_offset": 100, "records_completed": 0}),
                encoding="utf-8",
            )
            with self.assertRaises(CheckpointError):
                load_checkpoint(str(path), input_size=10)


if __name__ == "__main__":
    unittest.main()
