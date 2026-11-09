from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.cpe.src.applicability_annotation_sample import create_applicability_manifest
from benchmarks.cpe.src.applicability_gold import CVE_ENDPOINT, MANIFEST_SCHEMA, canonical_hash, validate_manifest_row


def source_record(record_id):
    return {"_source": {"id": record_id, "t80": {"http": {"result": {"headers": {"server": "nginx/1.24"}}}}}}


def cve(cve_id, config, relationships):
    return {"cve": {"id": cve_id, "published": "2026-01-01T00:00:00Z", "lastModified": "2026-01-02T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "fixture"}], "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 9.0}}]},
        "configurations": config, "affected": [{"source": "fixture"}]}, "relationships": relationships}


class ApplicabilitySamplingTests(unittest.TestCase):
    def _inputs(self, root):
        source = root / "source.jsonl"
        assessments = root / "assessment.jsonl"
        docs = [source_record("asset-a"), source_record("asset-b"), source_record("asset-c")]
        with source.open("w", encoding="utf-8") as stream:
            for doc in docs:
                stream.write(json.dumps(doc) + "\n")
        rows = []
        for index, doc in enumerate(docs):
            record_id = doc["_source"]["id"]
            identities = [{"candidate_id": f"id-{record_id}", "extracted_identity": {"product_name": "nginx", "version": "1.24"},
                           "cpe23": "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*", "resolution_status": "exact_match", "nvd_metadata": {"inferred_components": []},
                           "source_path": "t80.http.result.headers.server"}]
            if index == 1:
                identities.append({"candidate_id": "id-other", "extracted_identity": {"product_name": "openssl", "version": "3.0"},
                                   "cpe23": None, "resolution_status": "review_required", "nvd_metadata": {"inferred_components": ["vendor"]},
                                   "source_path": "t80.http.result.headers.server"})
            configurations = [{"nodes": [{"operator": "OR", "cpeMatch": [{"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": True}]}]}]
            if index == 1:
                configurations = [{"nodes": [{"operator": "AND", "negate": False, "cpeMatch": [
                    {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": True, "versionEndIncluding": "1.24"},
                    {"criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "vulnerable": False}]}]}]
            cve_row = cve(f"CVE-2026-{1000 + index}", configurations,
                          [{"identity_id": identities[0]["candidate_id"], "source_record_id": record_id, "cpe23": identities[0]["cpe23"]}])
            rows.append({"schema_version": "online-assessment-v1", "record_id": record_id,
                "source_hash": canonical_hash(doc), "extraction": {"identities": [
                    {"identity_id": row["candidate_id"], "evidence_paths": [row["source_path"]]} for row in identities]},
                "cpe_resolution": {"identities": identities},
                "cve_retrieval": {"source": "nvd_cve_api_2.0", "api_endpoint": CVE_ENDPOINT, "cves": [cve_row]}})
        # Repeated CVE in one record must be deduplicated.
        rows[0]["cve_retrieval"]["cves"].append(rows[0]["cve_retrieval"]["cves"][0])
        with assessments.open("w", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row) + "\n")
            stale = dict(rows[0]); stale["source_hash"] = "0" * 64
            stream.write(json.dumps(stale) + "\n")
        return source, assessments

    def test_deterministic_seed_structural_strata_and_duplicate_prevention(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source, assessments = self._inputs(root)
            a = create_applicability_manifest(source, assessments, root / "a.jsonl", size=3, seed=17)
            b = create_applicability_manifest(source, assessments, root / "b.jsonl", size=3, seed=17)
            a_rows = [json.loads(x) for x in (root / "a.jsonl").read_text().splitlines()]
            b_rows = [json.loads(x) for x in (root / "b.jsonl").read_text().splitlines()]
            self.assertEqual(a_rows, b_rows)
            self.assertEqual(len({row["case_id"] for row in a_rows}), 3)
            self.assertTrue(all(row["schema_version"] == MANIFEST_SCHEMA for row in a_rows))
            self.assertTrue(all(validate_manifest_row(row) == [] for row in a_rows))
            self.assertGreaterEqual(a["candidate_cases"], 3)
            self.assertEqual(a["duplicate_record_cve_pairs"], 1)
            self.assertEqual(a["stale_or_unlinked_assessment_rows"], 1)
            self.assertTrue(any("environmental_prerequisite" in row["sample_strata"] for row in a_rows))
            self.assertTrue(any(len(row["asset_snapshot"]["identities"]) == 2 for row in a_rows))
            self.assertTrue(all("prediction" not in json.dumps(row).lower() for row in a_rows))

    def test_size_below_or_above_population_and_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source, assessments = self._inputs(root)
            small = create_applicability_manifest(source, assessments, root / "small.jsonl", size=1)
            large = create_applicability_manifest(source, assessments, root / "large.jsonl", size=50)
            self.assertEqual(small["selected_cases"], 1)
            self.assertEqual(large["selected_cases"], 3)
            with self.assertRaises(FileExistsError):
                create_applicability_manifest(source, assessments, root / "large.jsonl", size=2)

    def test_empty_and_malformed_inputs_are_reported_without_fake_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / "source.jsonl"; assessments = root / "assessment.jsonl"
            source.write_text("not-json\n[]\n", encoding="utf-8")
            assessments.write_text("{bad\n", encoding="utf-8")
            result = create_applicability_manifest(source, assessments, root / "empty.jsonl", size=10)
            self.assertEqual(result["selected_cases"], 0)
            self.assertEqual(result["malformed_source_rows"], 1)
            self.assertEqual(result["malformed_assessment_rows"], 1)
            self.assertEqual((root / "empty.jsonl").read_text(), "")


if __name__ == "__main__":
    unittest.main()
