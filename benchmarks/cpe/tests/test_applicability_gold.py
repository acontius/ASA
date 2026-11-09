from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.cpe.src.applicability_gold import (
    CVE_ENDPOINT, GOLD_SCHEMA, MANIFEST_SCHEMA, canonical_hash, stable_case_id,
    validate_gold_file, validate_gold_row, validate_manifest_row,
)


def manifest():
    source = {"_source": {"id": "asset-1", "t80": {"http": {"result": {"headers": {"server": "nginx/1.24"}}}}}}
    source_hash = canonical_hash(source)
    configs = [{"nodes": [{"operator": "OR", "cpeMatch": []}]}]
    config_hash = canonical_hash({"present": True, "value": configs})
    cve = {"cve_id": "CVE-2026-1234", "published": "2026-01-01T00:00:00Z",
           "last_modified": "2026-01-02T00:00:00Z", "configurations_hash": config_hash,
           "configurations_present": True, "configurations": configs, "nvd_source": CVE_ENDPOINT,
           "descriptions": [{"lang": "en", "value": "Fixture"}], "metrics": {}}
    row = {"schema_version": MANIFEST_SCHEMA, "source_record_id": "asset-1", "source_hash": source_hash,
           "case_id": stable_case_id("asset-1", source_hash, cve["cve_id"], config_hash),
           "asset_snapshot": {"inventory_completeness": "passive_incomplete", "identities": [],
                              "evidence_paths": ["t80.http.result.headers.server"], "identity_references": []},
           "cve_snapshot": cve, "sample_strata": ["single_criterion"]}
    return source, row


def review(label="true", reviewer="reviewer-1"):
    return {"reviewer_id": reviewer, "reviewed_at": "2026-11-09T12:00:00Z",
            "expected_applicability": label, "reason_codes": ["version_in_range"],
            "notes": "Independent synthetic annotation.",
            "supporting_evidence_paths": ["t80.http.result.headers.server"],
            "supporting_identity_ids": ["identity-1"], "reviewed_configuration_references": ["configurations[0].nodes[0].cpeMatch[0]"]}


def gold(label="true", status="reviewed"):
    _, row = manifest()
    result = {**row, "schema_version": GOLD_SCHEMA, "expected_applicability": label,
              "annotation_status": status, "reviews": [review(label)] if status != "unreviewed" else [],
              "adjudication": None, "annotation_history": []}
    return result


class ApplicabilityGoldTests(unittest.TestCase):
    def test_valid_true_false_and_unknown_human_labels(self):
        for label in ("true", "false", "unknown"):
            self.assertEqual(validate_gold_row(gold(label)), [])

    def test_invalid_truth_and_status_are_rejected(self):
        row = gold("true"); row["expected_applicability"] = "potentially_affected"
        self.assertTrue(any("expected_applicability" in error for error in validate_gold_row(row)))
        row = gold("true"); row["annotation_status"] = "prediction"
        self.assertTrue(any("annotation_status" in error for error in validate_gold_row(row)))

    def test_reviewed_requires_human_metadata_and_evidence(self):
        row = gold("true"); row["reviews"][0]["reviewer_id"] = ""
        self.assertTrue(any("reviewer_id" in error for error in validate_gold_row(row)))
        row = gold("true"); row["reviews"][0]["supporting_evidence_paths"] = []
        row["reviews"][0]["supporting_identity_ids"] = []
        row["reviews"][0]["reviewed_configuration_references"] = []
        self.assertTrue(any("supporting evidence" in error for error in validate_gold_row(row)))

    def test_conflicting_reviewers_must_be_adjudicated(self):
        row = gold("true")
        row["reviews"].append(review("false", "reviewer-2"))
        self.assertTrue(any("agreeing human labels" in error for error in validate_gold_row(row)))
        row["annotation_status"] = "disputed"; row["expected_applicability"] = None
        self.assertEqual(validate_gold_row(row), [])

    def test_adjudication_requires_two_independent_reviews(self):
        row = gold("true")
        row["annotation_status"] = "adjudicated"
        row["adjudication"] = {"adjudicator_id": "judge", "adjudicated_at": "2026-11-10T12:00:00Z",
            "expected_applicability": "false", "notes": "Reviewed both sources.",
            "reviewed_configuration_references": ["configurations[0]"]}
        row["expected_applicability"] = "false"
        self.assertTrue(any("at least two reviews" in error for error in validate_gold_row(row)))
        row["reviews"].append(review("unknown", "reviewer-2"))
        self.assertEqual(validate_gold_row(row), [])

    def test_unreviewed_and_non_scored_statuses_never_have_labels(self):
        row = gold(None, "unreviewed"); self.assertEqual(validate_gold_row(row), [])
        row = gold("true", "insufficient_evidence")
        self.assertTrue(validate_gold_row(row))

    def test_duplicate_cases_and_stale_source_and_cve_snapshots_are_reported(self):
        source, row = manifest()
        reviewed = gold("true")
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp); source_path = tmp / "source.jsonl"; manifest_path = tmp / "manifest.jsonl"; gold_path = tmp / "gold.jsonl"
            source_path.write_text(json.dumps(source) + "\n", encoding="utf-8")
            manifest_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            gold_path.write_text(json.dumps(reviewed) + "\n" + json.dumps(reviewed) + "\n", encoding="utf-8")
            report = validate_gold_file(gold_path, manifest_path, source_path)
            self.assertTrue(any("duplicate case_id" in " ".join(item["errors"]) for item in report["errors"]))
            changed = dict(source); changed["_source"] = dict(source["_source"]); changed["_source"]["t80"] = {}
            source_path.write_text(json.dumps(changed) + "\n", encoding="utf-8")
            report = validate_gold_file(gold_path, manifest_path, source_path)
            self.assertEqual(report["stale_source_cases"], 1)
            altered = gold("true"); altered["cve_snapshot"]["configurations_hash"] = "0" * 64
            self.assertTrue(any("snapshot hash" in error for error in validate_gold_row(altered)))

    def test_manifest_validates_case_and_snapshot_hashes(self):
        _, row = manifest()
        self.assertEqual(validate_manifest_row(row), [])
        row["case_id"] = "0" * 64
        self.assertTrue(any("case_id does not match" in error for error in validate_manifest_row(row)))


if __name__ == "__main__":
    unittest.main()
