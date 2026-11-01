"""M1 contract and fixture validation tests.

Run with: python -m pytest tests/test_contracts.py -v
or:       python tests/test_contracts.py
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

# Allow importing schemas from repo root
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schemas.models import (  # noqa: E402
    REQUIRED_SOURCE_KEYS,
    ExtractionCandidate,
    NormalizedRecord,
    ProcessingOutcome,
    is_port_key,
)

FIXTURES = ROOT / "tests" / "fixtures"


class TestPortKeyHelper(unittest.TestCase):
    def test_valid_keys(self):
        self.assertTrue(is_port_key("t22"))
        self.assertTrue(is_port_key("t80"))
        self.assertTrue(is_port_key("t443"))
        self.assertTrue(is_port_key("t27017"))
        self.assertTrue(is_port_key("u53"))

    def test_invalid_keys(self):
        self.assertFalse(is_port_key("port"))
        self.assertFalse(is_port_key("t"))
        self.assertFalse(is_port_key("22"))
        self.assertFalse(is_port_key("http"))
        self.assertFalse(is_port_key(""))


class TestFixtureLoadability(unittest.TestCase):
    """Every fixture must be valid JSON and contain a usable _source."""

    def _load(self, name: str) -> dict:
        path = FIXTURES / f"fixture_{name}.json"
        self.assertTrue(path.exists(), f"missing fixture: {path}")
        with path.open() as f:
            return json.load(f)

    def test_ssh_fixture(self):
        data = self._load("ssh")
        src = data["_source"]
        self.assertTrue(REQUIRED_SOURCE_KEYS.issubset(src.keys()))
        self.assertEqual(src["proto"], "ssh")
        self.assertTrue(any(is_port_key(k) for k in src))
        # Primary signal path exists
        t22 = src.get("t22", {})
        software = (
            t22.get("ssh", {})
            .get("result", {})
            .get("server_id", {})
            .get("software")
        )
        self.assertIsInstance(software, str)
        self.assertTrue(len(software) > 0)

    def test_http_fixture(self):
        data = self._load("http")
        src = data["_source"]
        self.assertTrue(REQUIRED_SOURCE_KEYS.issubset(src.keys()))
        self.assertEqual(src["proto"], "http")
        self.assertTrue(any(is_port_key(k) for k in src))

    def test_ftp_fixture(self):
        data = self._load("ftp")
        src = data["_source"]
        self.assertEqual(src["proto"], "ftp")
        banner = (
            src.get("t21", {})
            .get("ftp", {})
            .get("result", {})
            .get("banner")
        )
        self.assertIsInstance(banner, str)
        self.assertTrue(banner.startswith("220"))

    def test_mongodb_fixture(self):
        data = self._load("mongodb")
        src = data["_source"]
        self.assertEqual(src["proto"], "mongodb")
        version = (
            src.get("t27017", {})
            .get("mongodb", {})
            .get("result", {})
            .get("build_info", {})
            .get("version")
        )
        self.assertIsInstance(version, str)

    def test_multi_port_fixture(self):
        data = self._load("multi_port")
        src = data["_source"]
        port_keys = [k for k in src if is_port_key(k)]
        self.assertGreaterEqual(len(port_keys), 2)

    def test_unsupported_fixture(self):
        data = self._load("unsupported")
        src = data["_source"]
        self.assertNotIn(src["proto"], {"ssh", "http", "ftp", "mongodb"})


class TestContractShapes(unittest.TestCase):
    """Smoke-test that example objects satisfy the TypedDict shapes."""

    def test_normalized_record_example(self):
        rec: NormalizedRecord = {
            "record_id": "test-1",
            "source_path": "/data/ip/example.json",
            "ip": "203.0.113.1",
            "scan_time": "1762417273",
            "app_id": "pub-zgrab2",
            "declared_proto": "ssh",
            "declared_port": "t22",
            "port_blocks": [
                {
                    "port_key": "t22",
                    "protocol": "ssh",
                    "raw_block": {},
                    "status": "success",
                }
            ],
            "provenance": {"original_line": 0, "jid": "3", "host": None},
        }
        self.assertEqual(rec["declared_proto"], "ssh")

    def test_candidate_example(self):
        cand: ExtractionCandidate = {
            "candidate_id": "c1",
            "product_name": "OpenSSH",
            "version": "9.6p1",
            "source_path": "t22.ssh.result.server_id.software",
            "raw_value": "OpenSSH_9.6p1",
            "signal_type": "banner",
            "extractor_id": "ssh.server_id.v1",
            "evidence_strength": "strong",
            "evidence_refs": ["server_id.software"],
            "normalized_record_id": "test-1",
        }
        self.assertEqual(cand["evidence_strength"], "strong")

    def test_outcome_example(self):
        out: ProcessingOutcome = {
            "outcome": "matched",
            "record_id": "test-1",
            "candidates": [],
            "notes": None,
            "error": None,
        }
        self.assertEqual(out["outcome"], "matched")


if __name__ == "__main__":
    unittest.main()
