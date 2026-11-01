"""Normalizer tests."""

from __future__ import annotations

import unittest

from tests.helpers import load_fixture

from app.ingestion.normalizer import NormalizationError, normalize


class TestNormalizer(unittest.TestCase):
    def test_ssh_fixture_preserves_scan_time_and_block(self):
        record = normalize(load_fixture("ssh"), line_number=4, byte_offset=100)
        self.assertEqual(record["record_id"], "3104055211")
        self.assertEqual(record["scan_time"], "1762417273")
        self.assertEqual(record["merge_time"], "2025-11-06T11:51:27+03:30")
        self.assertNotEqual(record["scan_time"], record["merge_time"])
        self.assertEqual(record["declared_proto"], "ssh")
        self.assertEqual(record["app_id"], "pub-zgrab2")
        self.assertEqual(record["provenance"]["original_line"], 4)
        self.assertIn("#L4@100", record["source_path"])
        self.assertEqual(len(record["port_blocks"]), 1)
        block = record["port_blocks"][0]
        self.assertEqual(block["port_key"], "t22")
        self.assertEqual(block["protocol"], "ssh")
        self.assertIn("server_id", block["raw_block"]["result"])

    def test_multi_port_examines_every_block(self):
        record = normalize(load_fixture("multi_port"), line_number=1, byte_offset=0)
        keys = [b["port_key"] for b in record["port_blocks"]]
        self.assertEqual(keys, ["t443", "t80"])
        self.assertTrue(all(b["protocol"] == "http" for b in record["port_blocks"]))

    def test_ftp_and_mongodb_wrappers(self):
        ftp = normalize(load_fixture("ftp"), line_number=1, byte_offset=0)
        self.assertEqual(ftp["app_id"], "pub-tgrab")
        self.assertEqual(ftp["port_blocks"][0]["protocol"], "ftp")
        self.assertIn("banner", ftp["port_blocks"][0]["raw_block"]["result"])
        mongo = normalize(load_fixture("mongodb"), line_number=2, byte_offset=5)
        self.assertEqual(mongo["port_blocks"][0]["protocol"], "mongodb")

    def test_missing_fields_and_bad_types(self):
        with self.assertRaises(NormalizationError):
            normalize({"_source": {"ip": "203.0.113.1"}}, line_number=1, byte_offset=0)
        with self.assertRaises(NormalizationError):
            normalize({"nope": 1}, line_number=1, byte_offset=0)
        doc = load_fixture("ssh")
        doc["_source"]["ip"] = 5
        with self.assertRaises(NormalizationError):
            normalize(doc, line_number=1, byte_offset=0)

    def test_invalid_port_block_type_is_kept(self):
        doc = {
            "_source": {
                "ip": "203.0.113.9",
                "scanTime": "1",
                "proto": "ssh",
                "port": "t22",
                "appId": "pub-zgrab2",
                "path": "/data/x.json",
                "t22": "not-a-dict",
                "u53": {"dns": {"result": {"banner": "x"}}},
            }
        }
        record = normalize(doc, line_number=1, byte_offset=0)
        protocols = {b["port_key"]: b["protocol"] for b in record["port_blocks"]}
        self.assertEqual(set(protocols), {"t22", "u53"})
        self.assertEqual(protocols["u53"], "dns")


if __name__ == "__main__":
    unittest.main()
