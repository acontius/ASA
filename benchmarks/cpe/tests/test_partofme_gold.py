from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.cpe.src.partofme_gold import (
    SourceFormatError,
    evaluate_pilot,
    iter_json_documents,
    prepare,
    validate,
)


def record(source_id: str, proto: str = "ssh", software: str = "OpenSSH_9.6p1") -> dict:
    source = {"id": source_id, "proto": proto, "port": {"ssh": "t22", "http": "t80", "ftp": "t21", "mongodb": "t27017"}.get(proto, "t22"),
              "ip": "192.0.2.1", "scanTime": "2026-11-01T00:00:00Z", "appId": "synthetic", "path": "/synthetic"}
    if proto == "ssh":
        source["t22"] = {"ssh": {"result": {"server_id": {"software": software}}}}
    elif proto == "http":
        source["t80"] = {"http": {"result": {"response": {"headers": {"server": [software]}}}}}
    elif proto == "ftp":
        source["t21"] = {"ftp": {"result": {"banner": software}}}
    elif proto == "mongodb":
        source["t27017"] = {"mongodb": {"result": {"version": software}}}
    return {"_id": "elastic-" + source_id, "_source": source}


class PartOfMeGoldTests(unittest.TestCase):
    def test_concatenated_and_pretty_json_objects_decode_across_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json"
            path.write_text('{"_source":{"id":"a"}}\n  {\n "_source": {"id":"b"}\n}\n', encoding="utf-8")
            self.assertEqual([row["_source"]["id"] for row in iter_json_documents(path, chunk_size=5)], ["a", "b"])

    def test_malformed_or_non_object_stream_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"_source":{}} not-json', encoding="utf-8")
            with self.assertRaises(SourceFormatError):
                list(iter_json_documents(path, chunk_size=4))
            path.write_text('[1,2]', encoding="utf-8")
            with self.assertRaises(SourceFormatError):
                list(iter_json_documents(path))

    def test_prepare_is_reproducible_and_gold_stays_unreviewed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "partofme.json"
            docs = [record(f"id-{i}", proto) for i, proto in enumerate(("ssh", "http", "ftp", "mongodb") * 3)]
            source.write_text("\n".join(json.dumps(doc) for doc in docs), encoding="utf-8")
            one = prepare(source, root / "pilot-a", size=8, seed=17)
            two = prepare(source, root / "pilot-b", size=8, seed=17)
            self.assertEqual(one["source_records"], 12)
            self.assertEqual(one["sample_records"], 8)
            for name in ("source.jsonl", "manifest.jsonl", "gold.jsonl"):
                self.assertEqual((root / "pilot-a" / name).read_bytes(), (root / "pilot-b" / name).read_bytes())
            manifest = [json.loads(line) for line in (root / "pilot-a/manifest.jsonl").read_text().splitlines()]
            gold = [json.loads(line) for line in (root / "pilot-a/gold.jsonl").read_text().splitlines()]
            self.assertTrue(all(row["gold_label_generated"] is False for row in manifest))
            self.assertTrue(all(row["annotation_status"] == "unreviewed" for row in manifest))
            self.assertTrue(all(row["annotation_status"] == "unreviewed" and not row["expected_identities"] for row in gold))
            self.assertTrue(all(row["annotation"]["adjudication_status"] == "pending" for row in gold))
            self.assertGreater(sum(bool(row["source_evidence_refs"]) for row in manifest), 0)
            self.assertTrue(all("source_observation" in row for row in manifest[0]["field_review_hints"].values()))
            self.assertTrue(all(ref["source_observation"] == "directly_supported_by_source" for ref in manifest[0]["source_evidence_refs"]))
            self.assertTrue(all(ref["identity_interpretation"] == "requires_human_review" for ref in manifest[0]["source_evidence_refs"]))
            self.assertEqual(len({row["record_id"] for row in manifest}), 8)
            self.assertEqual(len({row["source_hash"] for row in manifest}), 8)
            self.assertEqual(validate(root / "pilot-a")["scorable_records"], 0)
            from benchmarks.cpe.ui.server import UIApplication
            ui = UIApplication(root / "pilot-a/source.jsonl", root / "pilot-a/gold.jsonl")
            queue = ui.list_records("", "unreviewed", 0, 200)
            self.assertEqual(queue["total"], 8)
            first = ui.record(queue["records"][0]["record_id"])
            self.assertFalse(first["stale"])
            self.assertEqual(first["record"]["annotation_status"], "unreviewed")
            self.assertTrue(all(json.loads(line)["expected_identities"] == [] for line in (root / "pilot-a/gold.jsonl").read_text().splitlines()))
            report = evaluate_pilot(root / "pilot-a", root / "pilot-a/evaluation.json")
            self.assertFalse(report["accuracy_available"])
            self.assertEqual(report["scorable_gold_records"], 0)
            self.assertIsNone(report["extraction_metrics"]["product_name_metrics"]["f1"])
            self.assertEqual(report["cpe_metrics"]["mapped_gold_identities"], 0)
            with self.assertRaises(FileExistsError):
                evaluate_pilot(root / "pilot-a", root / "pilot-a/evaluation.json")

    def test_validation_rejects_stale_manifest_hash_and_evidence_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            source.write_text(json.dumps(record("stale")), encoding="utf-8")
            prepare(source, root / "pilot", size=1, seed=2)
            manifest_path = root / "pilot/manifest.jsonl"
            manifest = json.loads(manifest_path.read_text().splitlines()[0])
            manifest["source_hash"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "stale source hash"):
                validate(root / "pilot")
            manifest["source_hash"] = json.loads((root / "pilot/gold.jsonl").read_text().splitlines()[0])["source_hash"]
            if manifest["source_evidence_refs"]:
                manifest["source_evidence_refs"][0]["path"] = "_source.missing.evidence"
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid or stale evidence path"):
                validate(root / "pilot")

    def test_multiservice_record_keeps_both_raw_evidence_paths(self):
        document = record("multi")
        document["_source"]["t80"] = {"http": {"result": {"response": {"headers": {"server": ["nginx/1.25.3"]}}}}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            source.write_text(json.dumps(document), encoding="utf-8")
            prepare(source, root / "pilot", size=1, seed=3)
            manifest = json.loads((root / "pilot/manifest.jsonl").read_text().splitlines()[0])
        paths = {item["path"] for item in manifest["source_evidence_refs"]}
        self.assertTrue(any("server_id.software" in path for path in paths))
        self.assertTrue(any("headers.server[0]" in path for path in paths))

    def test_duplicate_stable_source_id_is_rejected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            source.write_text(json.dumps(record("duplicate")) + "\n" + json.dumps(record("duplicate")), encoding="utf-8")
            with self.assertRaises(SourceFormatError):
                prepare(source, root / "pilot", size=1, seed=1)
            self.assertFalse((root / "pilot").exists())

    def test_prepare_refuses_existing_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            source.write_text(json.dumps(record("one")), encoding="utf-8")
            output = root / "pilot"
            output.mkdir()
            with self.assertRaises(FileExistsError):
                prepare(source, output, size=1, seed=1)


if __name__ == "__main__":
    unittest.main()
