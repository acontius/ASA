"""Outcome classification tests."""

from __future__ import annotations

import unittest

from app.extractors import EXTRACTORS, extract_candidates
from app.extractors.base import candidate
from app.ingestion.normalizer import normalize
from app.outcomes import classify
from tests.helpers import load_fixture


def _record():
    return {
        "record_id": "1",
        "source_path": "x",
        "ip": "203.0.113.1",
        "scan_time": "1",
        "app_id": "pub-zgrab2",
        "declared_proto": "http",
        "declared_port": "t80",
        "port_blocks": [],
        "provenance": {},
    }


def _cand(product, version, strength):
    rec = _record()
    return candidate(
        rec,
        product_name=product,
        version=version,
        raw_value=product,
        source_path=f"p.{product}",
        signal_type="header",
        extractor_id="t",
        evidence_strength=strength,
    )


class TestOutcomes(unittest.TestCase):
    def test_each_outcome(self):
        self.assertEqual(
            classify("1", [], supported_block_present=False, error="bad json")["outcome"],
            "processing_error",
        )
        self.assertEqual(
            classify("1", [], supported_block_present=False)["outcome"],
            "unsupported_protocol",
        )
        self.assertEqual(
            classify("1", [], supported_block_present=True)["outcome"],
            "no_match",
        )
        self.assertEqual(
            classify("1", [_cand("WAF", None, "weak")], supported_block_present=True)["outcome"],
            "insufficient_evidence",
        )
        self.assertEqual(
            classify("1", [_cand("nginx", "1.24.0", "strong")], supported_block_present=True)["outcome"],
            "matched",
        )
        mixed = classify(
            "1",
            [_cand("nginx", "1.24.0", "strong"), _cand("Apache", "2.4.52", "strong")],
            supported_block_present=True,
        )
        self.assertEqual(mixed["outcome"], "ambiguous")

    def test_fixture_dispatch(self):
        ssh = normalize(load_fixture("ssh"), line_number=1, byte_offset=0)
        found = extract_candidates(ssh, EXTRACTORS)
        self.assertEqual(classify(ssh["record_id"], found, supported_block_present=True)["outcome"], "matched")

        unsupported = normalize(load_fixture("unsupported"), line_number=1, byte_offset=0)
        self.assertFalse(any(b["protocol"] == "ssh" for b in unsupported["port_blocks"]))
        self.assertEqual(unsupported["port_blocks"][0]["protocol"], "winbox")
        self.assertEqual(
            classify(unsupported["record_id"], [], supported_block_present=False)["outcome"],
            "unsupported_protocol",
        )

        multi = normalize(load_fixture("multi_port"), line_number=1, byte_offset=0)
        found = extract_candidates(multi, EXTRACTORS)
        self.assertGreaterEqual(len(found), 2)
        self.assertTrue(all(item["evidence_strength"] == "weak" for item in found))


if __name__ == "__main__":
    unittest.main()
