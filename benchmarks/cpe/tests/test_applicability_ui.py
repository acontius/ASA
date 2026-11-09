from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.cpe.src.applicability_gold import CVE_ENDPOINT, MANIFEST_SCHEMA, canonical_hash, stable_case_id
from benchmarks.cpe.ui.applicability_server import ApplicabilityStore, StaleCase, serve


def fixture(root):
    source = {"_source": {"id": "asset-ui"}, "t80": {"http": {"result": {"headers": {"server": "nginx/1.24"}}}}}
    source_path = root / "source.jsonl"; source_path.write_text(json.dumps(source) + "\n")
    configs = [{"operator": "AND", "nodes": [{"operator": "OR", "cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": True,
         "versionEndIncluding": "1.24"},
        {"criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "vulnerable": False}]}]}]
    source_hash = canonical_hash(source); cve_id = "CVE-2026-6789"
    conf_hash = canonical_hash({"present": True, "value": configs})
    case_id = stable_case_id("asset-ui", source_hash, cve_id, conf_hash)
    manifest = {"schema_version": MANIFEST_SCHEMA, "case_id": case_id, "source_record_id": "asset-ui", "source_hash": source_hash,
        "asset_snapshot": {"inventory_completeness": "passive_incomplete", "identities": [{
            "identity_id": "identity-ui", "extracted_identity": {"product_name": "nginx", "version": "1.24"},
            "cpe23": "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*", "resolution_status": "exact_match",
            "inferred_components": [], "evidence_paths": ["t80.http.result.headers.server"]}],
            "evidence_paths": ["t80.http.result.headers.server"], "identity_references": ["identity-ui"]},
        "cve_snapshot": {"cve_id": cve_id, "published": "2026-01-01T00:00:00Z", "last_modified": "2026-01-02T00:00:00Z",
            "configurations_hash": conf_hash, "configurations_present": True, "configurations": configs,
            "nvd_source": CVE_ENDPOINT, "descriptions": [{"lang": "en", "value": "synthetic vulnerability"}],
            "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 8.0}}]}}, "sample_strata": ["and_only", "version_range"]}
    manifest_path = root / "manifest.jsonl"; manifest_path.write_text(json.dumps(manifest) + "\n")
    return source_path, manifest_path, root / "gold.jsonl", manifest


class ApplicabilityUiTests(unittest.TestCase):
    def test_evidence_and_nvd_configurations_are_render_data_without_predictions(self):
        with tempfile.TemporaryDirectory() as temp:
            source, manifest, gold, row = fixture(Path(temp))
            store = ApplicabilityStore(manifest, source, gold)
            result = store.get_case(row["case_id"])
            self.assertEqual(result["evidence"][0]["value"], '"nginx/1.24"')
            self.assertEqual(result["manifest"]["cve_snapshot"]["configurations"], row["cve_snapshot"]["configurations"])
            self.assertNotIn("prediction", json.dumps(result).lower())
            self.assertTrue(store.list_cases()["cases"][0]["status"] == "unreviewed")

    def test_two_reviewers_conflict_then_adjudication_and_history_persist(self):
        with tempfile.TemporaryDirectory() as temp:
            source, manifest, gold, case_row = fixture(Path(temp)); store = ApplicabilityStore(manifest, source, gold)
            common = {"case_id": case_row["case_id"], "action": "review", "reason_codes": ["criteria_reviewed"],
                "notes": "Reviewed scan evidence and NVD configuration.", "evidence_paths": ["t80.http.result.headers.server"],
                "identity_ids": ["identity-ui"], "configuration_references": ["configurations[0].nodes[0].cpeMatch[0]"]}
            store.save({**common, "actor_id": "reviewer-a", "label": "true"})
            disputed = store.save({**common, "actor_id": "reviewer-b", "label": "unknown"})
            self.assertEqual(disputed["annotation_status"], "disputed")
            adjudicated = store.save({"case_id": case_row["case_id"], "action": "adjudicate", "actor_id": "adjudicator",
                "label": "true", "notes": "Configuration and version boundary reviewed.",
                "configuration_references": ["configurations[0].nodes[0]"]})
            self.assertEqual(adjudicated["annotation_status"], "adjudicated")
            saved = json.loads(gold.read_text())
            self.assertEqual(saved["expected_applicability"], "true")
            history = saved["annotation_history"]
            self.assertEqual(len(history), 2)
            self.assertEqual((history[0]["actor_id"], history[0]["action"], history[0]["annotation_status"]),
                             ("reviewer-b", "review", "reviewed"))
            self.assertEqual(history[0]["reviews"][0]["reviewer_id"], "reviewer-a")
            self.assertEqual((history[1]["actor_id"], history[1]["action"], history[1]["annotation_status"]),
                             ("adjudicator", "adjudicate", "disputed"))
            self.assertEqual(len(history[1]["reviews"]), 2)
            self.assertEqual(len(saved["reviews"]), 2)

    def test_non_scored_statuses_and_duplicate_reviewer_are_safe(self):
        with tempfile.TemporaryDirectory() as temp:
            source, manifest, gold, row = fixture(Path(temp)); store = ApplicabilityStore(manifest, source, gold)
            payload = {"case_id": row["case_id"], "action": "non_scored", "actor_id": "reviewer",
                "label": None, "status": "insufficient_evidence", "reason_codes": ["missing_os"],
                "notes": "No operating system evidence in this passive record.", "evidence_paths": ["t80.http.result.headers.server"],
                "identity_ids": ["identity-ui"], "configuration_references": ["configurations[0]"]}
            self.assertEqual(store.save(payload)["annotation_status"], "insufficient_evidence")
            saved = json.loads(gold.read_text()); self.assertIsNone(saved["expected_applicability"])
            with self.assertRaisesRegex(ValueError, "already submitted"):
                store.save({**payload, "action": "review", "label": "false"})

    def test_stale_source_is_warned_and_prevents_save(self):
        with tempfile.TemporaryDirectory() as temp:
            source, manifest, gold, row = fixture(Path(temp)); store = ApplicabilityStore(manifest, source, gold)
            source.write_text(json.dumps({"_source": {"id": "asset-ui", "changed": True}}) + "\n")
            result = store.get_case(row["case_id"])
            self.assertTrue(result["stale"])
            with self.assertRaises(StaleCase):
                store.save({"case_id": row["case_id"], "actor_id": "reviewer"})

    def test_localhost_binding_and_no_external_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            source, manifest, gold, _ = fixture(Path(temp))
            with self.assertRaisesRegex(ValueError, "127.0.0.1"):
                serve(str(manifest), str(source), str(gold), host="0.0.0.0")
            html = (Path(__file__).parents[1] / "ui" / "applicability_static" / "index.html").read_text()
            html = (Path(__file__).parents[1] / "ui" / "applicability_static" / "index.html").read_text()
            self.assertNotIn("https://", html)
            self.assertNotIn("http://", html)
            self.assertIn("ASA prediction is intentionally hidden", html)


if __name__ == "__main__":
    unittest.main()
