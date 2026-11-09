from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.cpe.src.applicability_gold import CVE_ENDPOINT, GOLD_SCHEMA, MANIFEST_SCHEMA, canonical_hash, stable_case_id
from benchmarks.cpe.src.applicability_metrics import evaluate_applicability_gold


def case(index: int, label: str, status="reviewed"):
    record_id = f"asset-{index}"
    source = {"_source": {"id": record_id, "banner": f"service-{index}"}}
    source_hash = canonical_hash(source)
    cve_id = f"CVE-2026-{1000 + index}"
    configs = [{"nodes": [{"operator": "OR", "cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "vulnerable": True}]}]}]
    config_hash = canonical_hash({"present": True, "value": configs})
    case_id = stable_case_id(record_id, source_hash, cve_id, config_hash)
    manifest = {"schema_version": MANIFEST_SCHEMA, "case_id": case_id, "source_record_id": record_id,
        "source_hash": source_hash, "asset_snapshot": {"inventory_completeness": "passive_incomplete", "identities": [],
        "evidence_paths": ["_source.banner"], "identity_references": []},
        "cve_snapshot": {"cve_id": cve_id, "published": "2026-01-01T00:00:00Z", "last_modified": "2026-01-02T00:00:00Z",
            "configurations_hash": config_hash, "configurations_present": True, "configurations": configs,
            "nvd_source": CVE_ENDPOINT, "descriptions": [{"lang": "en", "value": "fixture"}], "metrics": {}},
        "sample_strata": ["single_criterion"]}
    review = {"reviewer_id": f"reviewer-{index}", "reviewed_at": "2026-11-09T12:00:00Z",
        "expected_applicability": label, "reason_codes": ["manual_review"], "notes": "Independent test label.",
        "supporting_evidence_paths": ["_source.banner"], "supporting_identity_ids": [],
        "reviewed_configuration_references": ["configurations[0].nodes[0]"]}
    gold = {**manifest, "schema_version": GOLD_SCHEMA, "expected_applicability": label,
        "annotation_status": status, "reviews": [review] if status == "reviewed" else [], "adjudication": None, "annotation_history": []}
    return source, manifest, gold, configs, cve_id


def prediction(source, cve_id, configs, value, *, source_hash=None):
    rid = source["_source"]["id"]
    return {"schema_version": "online-assessment-v1", "record_id": rid,
        "source_hash": source_hash or canonical_hash(source),
        "cve_retrieval": {"cves": [{"cve": {"id": cve_id, "configurations": configs}}]},
        "applicability_assessments": [{"source_record_id": rid, "cve_id": cve_id, "logic_value": value}]}


class ApplicabilityMetricsTests(unittest.TestCase):
    def _write(self, root, rows):
        source_path, manifest_path, gold_path, predictions_path = [root / name for name in ("source.jsonl", "manifest.jsonl", "gold.jsonl", "predictions.jsonl")]
        files = ((source_path, [row[0] for row in rows]), (manifest_path, [row[1] for row in rows]),
                 (gold_path, [row[2] for row in rows]), (predictions_path, [row[3] for row in rows]))
        for path, values in files:
            path.write_text("".join(json.dumps(value) + "\n" for value in values), encoding="utf-8")
        return evaluate_applicability_gold(str(gold_path), str(manifest_path), str(predictions_path), str(source_path))

    def test_confusion_positive_metrics_and_coverage(self):
        labels = [("true", "true"), ("false", "true"), ("unknown", "unknown")]
        values = []
        for i, (gold_label, predicted) in enumerate(labels):
            source, manifest, gold, configs, cve_id = case(i, gold_label)
            values.append((source, manifest, gold, prediction(source, cve_id, configs, predicted)))
        with tempfile.TemporaryDirectory() as tmp:
            report = self._write(Path(tmp), values)
        self.assertEqual(report["eligible_reviewed_cases"], 3)
        self.assertEqual(report["confusion_matrix"]["true"], {"true": 1, "false": 0, "unknown": 0})
        self.assertEqual(report["security_positive_true"]["fp"], 1)
        self.assertEqual(report["security_positive_true"]["gold_true_predicted_unknown"], 0)
        self.assertAlmostEqual(report["decision_coverage"], 2 / 3)
        self.assertAlmostEqual(report["unknown_prediction_rate"], 1 / 3)
        self.assertEqual(report["accuracy_on_definite_decisions"], 0.5)

    def test_unreviewed_disputed_and_stale_cases_are_excluded(self):
        values = []
        for i, (label, status) in enumerate((("true", "reviewed"), (None, "unreviewed"), (None, "disputed"))):
            source, manifest, gold, configs, cve_id = case(i, label, status)
            pred = prediction(source, cve_id, configs, "true")
            values.append((source, manifest, gold, pred))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._write(root, values)
            source_path = root / "source.jsonl"
            source_path.write_text(json.dumps({"_source": {"id": "asset-0", "banner": "edited"}}) + "\n" +
                "".join(json.dumps(row[0]) + "\n" for row in values[1:]), encoding="utf-8")
            report = evaluate_applicability_gold(str(root / "gold.jsonl"), str(root / "manifest.jsonl"), str(root / "predictions.jsonl"), str(source_path))
        self.assertEqual(report["eligible_reviewed_cases"], 0)
        self.assertEqual(report["stale_source_cases"], 1)
        self.assertEqual(report["excluded_cases"]["unreviewed"], 1)
        self.assertEqual(report["excluded_cases"]["disputed"], 1)
        self.assertIsNone(report["decision_coverage"])
        self.assertFalse(report["independent_accuracy_available"])

    def test_stale_cve_configuration_and_duplicate_prediction_excluded(self):
        source, manifest, gold, configs, cve_id = case(1, "true")
        changed_configs = [{"nodes": []}]
        pred = prediction(source, cve_id, changed_configs, "true")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._write(root, [(source, manifest, gold, pred)])
        self.assertEqual(report["eligible_reviewed_cases"], 0)
        self.assertEqual(report["stale_cve_config_cases"], 1)
        source, manifest, gold, configs, cve_id = case(2, "true")
        pred = prediction(source, cve_id, configs, "true")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._write(root, [(source, manifest, gold, pred)])
            path = root / "predictions.jsonl"; path.write_text(path.read_text() + json.dumps(pred) + "\n")
            report = evaluate_applicability_gold(str(root / "gold.jsonl"), str(root / "manifest.jsonl"), str(path), str(root / "source.jsonl"))
        self.assertEqual(report["duplicate_prediction_cases"], 1)
        self.assertEqual(report["missing_predictions"], 1)

    def test_missing_prediction_counts_as_positive_false_negative_and_null_denominators(self):
        source, manifest, gold, configs, cve_id = case(5, "true")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, rows in (("source.jsonl", [source]), ("manifest.jsonl", [manifest]), ("gold.jsonl", [gold]), ("predictions.jsonl", [])):
                (root / name).write_text("".join(json.dumps(row) + "\n" for row in rows))
            report = evaluate_applicability_gold(str(root / "gold.jsonl"), str(root / "manifest.jsonl"), str(root / "predictions.jsonl"), str(root / "source.jsonl"))
        self.assertEqual(report["security_positive_true"]["fn"], 1)
        self.assertEqual(report["security_positive_true"]["gold_true_missing_prediction"], 1)
        self.assertIsNone(report["accuracy_on_definite_decisions"])


if __name__ == "__main__":
    unittest.main()
