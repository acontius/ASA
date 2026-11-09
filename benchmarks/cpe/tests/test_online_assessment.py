import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.vulnerability.nvd.cpe_client import ENDPOINT as CPE_ENDPOINT, NvdApiError, NvdBudgetExceeded
from app.vulnerability.nvd.cpe_client import SearchResult
from app.vulnerability.nvd.cve_client import ENDPOINT as CVE_ENDPOINT, NvdCveApiError, NvdCveBudgetExceeded
from app.vulnerability.nvd.pipeline import OnlineAssessmentError, run_online_assessment
from tests.helpers import load_fixture

CPE_NGINX = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
MATCH_ID = "11111111-1111-1111-1111-111111111111"


def candidate(product="nginx", vendor="nginx", version="1.24.0", part="a", identity_id="id-1"):
    return {"candidate_id": identity_id, "product_name": product, "vendor": vendor,
            "version": version, "update": None, "part": part,
            "source_path": "t80.http.server", "raw_value": "private-banner-fixture",
            "signal_type": "header", "extractor_id": "synthetic", "evidence_strength": "strong",
            "evidence_refs": ["server"], "normalized_record_id": "record-1"}


def cve_record(cve_id, matches, operator="AND"):
    return {"cve": {"id": cve_id, "published": "2026-01-01T00:00:00Z",
        "lastModified": "2026-01-02T00:00:00Z", "descriptions": [{"lang": "en", "value": "synthetic"}],
        "references": [], "configurations": [{"operator": "AND", "nodes": [
            {"operator": operator, "cpeMatch": matches}]}],
        "metrics": {"ssvcV203": [{"ssvcData": {"version": "2.0.3"}}]},
        "affected": [{"source": "synthetic", "affectedData": []}]}}


def cm(criteria, *, vulnerable=True, **bounds):
    return {"criteria": criteria, "matchCriteriaId": MATCH_ID,
            "vulnerable": vulnerable, **bounds}


class FakeCpeClient:
    endpoint = CPE_ENDPOINT
    api_key = "fake-test-key"
    min_interval = 0.0
    results_per_page = 200
    def __init__(self, names=None, *, error=None, complete=True):
        self.names = names or {"nginx": CPE_NGINX}
        self.error, self.complete = error, complete
        self.request_count = 0
        self.cache_hits = 0
        self.scheduler = None
    def search(self, parameters, *, budget=None):
        if not self.scheduler.acquire(): raise NvdBudgetExceeded()
        self.request_count += 1
        if self.error:
            raise self.error
        product = parameters.get("cpeMatchString", "").split(":")[4].casefold()
        name = self.names.get(product, CPE_NGINX)
        cpe = {"cpeName": name, "cpeNameId": MATCH_ID, "deprecated": False,
               "deprecatedBy": [], "titles": [{"title": product, "lang": "en"}], "refs": []}
        return SearchResult([{"cpe": cpe}], dict(parameters), 1 if self.complete else 2, 1, 1, self.complete,
                            "2026-11-09T00:00:00Z", "NVD_CPE", "2.0", 0, 200)


class FakeCveClient:
    endpoint = CVE_ENDPOINT
    api_key = "fake-test-key"
    min_interval = 0.0
    def __init__(self, cves, *, error=None, complete=True):
        self.rows = cves
        self.error, self.complete = error, complete
        self.request_count = 0
        self.cache_hits = 0
        self.scheduler = None
        self.cache = {}
    def fetch_by_cpe(self, cpe, *, max_requests):
        if cpe in self.cache:
            self.cache_hits += 1
            return self.cache[cpe]
        if not self.scheduler.acquire():
            raise NvdCveBudgetExceeded()
        self.request_count += 1
        if self.error:
            raise self.error
        value = SimpleNamespace(cves=self.rows, total_results=len(self.rows), pages_fetched=1,
            requests_made=1, pagination_complete=self.complete, timestamp="2026-11-09T00:00:00Z",
            retry_count=0, cache_hit=False, parameters={"cpeName": cpe}, error_category=None,
            error_message=None, truncated_reason=None if self.complete else "max_pages_reached", http_status=200, response_bytes=512,
            format="NVD_CVE", version="2.0", schema_version="2.2.4")
        self.cache[cpe] = value
        return value


class OnlineAssessmentTests(unittest.TestCase):
    def _run(self, temp, *, candidates=None, cves=None, cpe=None, cve=None, checkpoint=False,
             resume=False, max_requests=50):
        temp = Path(temp)
        source = temp / "source.jsonl"
        source.write_text(json.dumps(load_fixture("http")) + "\n", encoding="utf-8")
        output = temp / "result.jsonl"
        ckpt = temp / "checkpoint.json" if checkpoint else None
        cpe = cpe or FakeCpeClient()
        cve = cve or FakeCveClient(cves or [])
        patcher = patch("app.vulnerability.nvd.pipeline.process_m2_item", return_value={
            "record_id": "record-1", "outcome": "matched", "notes": None, "error": None,
            "candidates": candidates or [candidate()]})
        with patcher:
            stats = run_online_assessment(str(source), str(output), str(ckpt) if ckpt else None,
                resume=resume, max_requests_per_run=max_requests, max_requests_per_identity=3,
                cpe_client=cpe, cve_client=cve)
        return source, output, ckpt, stats, cpe, cve

    def test_full_pipeline_outputs_true_false_unknown_and_preserves_payload(self):
        records = [
            cve_record("CVE-2026-10001", [cm("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", versionEndIncluding="1.24.9")]),
            cve_record("CVE-2026-10002", [cm("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", versionStartIncluding="1.30.0")]),
            cve_record("CVE-2026-10003", [cm("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"),
                cm("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", vulnerable=False)]),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            _, out, _, stats, cpe, cve = self._run(tmp, cves=records)
            row = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
            serialized = out.read_text(encoding="utf-8")
        self.assertEqual(row["schema_version"], "online-assessment-v1")
        self.assertEqual([x["assessment_status"] for x in row["applicability_assessments"]],
                         ["potentially_affected", "not_applicable", "unknown"])
        self.assertEqual(stats["api_requests"], 2)
        self.assertEqual(stats["cpe_requests"], 1)
        self.assertEqual(stats["cve_requests"], 1)
        self.assertEqual(row["cve_retrieval"]["cves"][0]["cve"]["affected"], records[0]["cve"]["affected"])
        self.assertEqual(row["cve_retrieval"]["cves"][0]["cve"]["metrics"], records[0]["cve"]["metrics"])
        self.assertNotIn("private-banner-fixture", serialized)
        self.assertNotIn("fake-test-key", serialized)

    def test_actual_m2_unknown_vendor_is_not_promoted_and_does_not_query_cve(self):
        raw = load_fixture("ssh")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.jsonl"
            source.write_text(json.dumps(raw) + "\n", encoding="utf-8")
            output = Path(tmp) / "out.jsonl"
            cpe = FakeCpeClient({"openssh": "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"})
            cve = FakeCveClient([])
            run_online_assessment(str(source), str(output), cpe_client=cpe, cve_client=cve)
            row = json.loads(output.read_text().splitlines()[0])
        self.assertEqual(row["extraction"]["identities"][0]["product"], "OpenSSH")
        self.assertEqual(row["cpe_resolution"]["identities"][0]["resolution_status"], "review_required")
        self.assertEqual(cve.request_count, 0)

    def test_review_required_and_ambiguous_identities_never_retrieve_cves(self):
        rows = [candidate(identity_id="review"), candidate(identity_id="ambiguous")]
        cves = [cve_record("CVE-2026-10010", [cm("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")])]
        client = FakeCveClient(cves)
        cpe = FakeCpeClient()
        # Force statuses by making M2 rows distinct and patching the shared resolver output.
        def m2(_item):
            return {"record_id": "record-1", "outcome": "ambiguous", "notes": None, "error": None,
                    "candidates": rows}
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.jsonl"; source.write_text(json.dumps(load_fixture("http")) + "\n")
            output = Path(tmp) / "out.jsonl"
            from app.vulnerability.nvd import pipeline as module
            with patch.object(module, "process_m2_item", side_effect=m2), patch.object(
                    module, "resolve_candidate_nvd", side_effect=[
                        {"candidate_id": "review", "resolution_status": "review_required"},
                        {"candidate_id": "ambiguous", "resolution_status": "ambiguous"}]):
                run_online_assessment(str(source), str(output), cpe_client=cpe, cve_client=client)
            result = json.loads(output.read_text().splitlines()[0])
        self.assertEqual(client.request_count, 0)
        self.assertEqual([x["retrieval_status"] for x in result["cve_retrieval"]["identities"]],
                         ["skipped_review_required", "skipped_ambiguous"])

    def test_multiple_identities_deduplicate_cve_but_keep_both_relationships(self):
        mongo = "cpe:2.3:a:mongodb:mongodb:7.0.12:*:*:*:*:*:*:*"
        cves = [cve_record("CVE-2026-10020", [
            cm("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"),
            cm("cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*")])]
        candidates = [candidate(identity_id="nginx"), candidate("mongodb", "mongodb", "7.0.12", "a", "mongo")]
        fake_cpe = FakeCpeClient({"nginx": CPE_NGINX, "mongodb": mongo})
        fake_cve = FakeCveClient(cves)
        with tempfile.TemporaryDirectory() as tmp:
            _, out, _, stats, _, _ = self._run(tmp, candidates=candidates, cves=cves,
                                                cpe=fake_cpe, cve=fake_cve)
            row = json.loads(out.read_text().splitlines()[0])
        self.assertEqual(stats["cpe_requests"], 2)
        self.assertEqual(row["summary"]["cve_count"], 1)
        links = row["applicability_assessments"][0]["relationships"]
        self.assertEqual({link["identity_id"] for link in links}, {"nginx", "mongo"})
        self.assertEqual(row["applicability_assessments"][0]["logic_value"], "true")

    def test_missing_key_fails_before_output_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.jsonl"; source.write_text("{}\n")
            output = Path(tmp) / "out.jsonl"
            with patch("app.vulnerability.nvd.pipeline.load_api_key", return_value=None):
                with self.assertRaisesRegex(OnlineAssessmentError, "NVD_API_KEY is required"):
                    run_online_assessment(str(source), str(output), dotenv_path=Path(tmp) / "absent.env")
            self.assertFalse(output.exists())

    def test_resume_uses_existing_checkpoint_and_output_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out, ckpt, _, cpe, cve = self._run(tmp, checkpoint=True)
            first_count = len(out.read_text().splitlines())
            with source.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(load_fixture("ssh")) + "\n")
            def m2(item):
                return {"record_id": f"r{item.line_number}", "outcome": "no_match", "candidates": [],
                        "notes": None, "error": None}
            from app.vulnerability.nvd import pipeline as module
            with patch.object(module, "process_m2_item", side_effect=m2):
                stats = run_online_assessment(str(source), str(out), str(ckpt), resume=True,
                    cpe_client=cpe, cve_client=cve)
            self.assertEqual(first_count, 1)
            self.assertEqual(len(out.read_text().splitlines()), 2)
            self.assertEqual(stats["records"], 1)

    def test_output_overwrite_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.jsonl"; source.write_text("{}\n")
            output = Path(tmp) / "out.jsonl"; output.write_text("existing\n")
            with self.assertRaisesRegex(OnlineAssessmentError, "output already exists"):
                run_online_assessment(str(source), str(output), cpe_client=FakeCpeClient(),
                                      cve_client=FakeCveClient([]))

    def test_cpe_timeout_and_incomplete_pagination_remain_explicit(self):
        for fake, expected in ((FakeCpeClient(error=NvdApiError("network_error", "timeout")), "api_unavailable"),
                               (FakeCpeClient(complete=False), "incomplete_lookup")):
            with tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / "in.jsonl"; source.write_text(json.dumps(load_fixture("http")) + "\n")
                output = Path(tmp) / "out.jsonl"
                cve = FakeCveClient([])
                with patch("app.vulnerability.nvd.pipeline.process_m2_item", return_value={
                    "record_id": "r", "outcome": "matched", "candidates": [candidate()], "notes": None, "error": None}):
                    stats = run_online_assessment(str(source), str(output), cpe_client=fake, cve_client=cve)
                row = json.loads(output.read_text().splitlines()[0])
                self.assertEqual(row["cpe_resolution"]["identities"][0]["resolution_status"], expected)
                self.assertEqual(row["record_status"], "partial_error")
                self.assertEqual(cve.request_count, 0)
                self.assertEqual(stats["errors"], 1)

    def test_cve_timeout_and_truncated_pagination_are_not_no_cves(self):
        cve_row = cve_record("CVE-2026-10030", [cm("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")])
        scenarios = ((FakeCveClient([], error=NvdCveApiError("network_error", "timeout")), "api_unavailable"),
                     (FakeCveClient([cve_row], complete=False), "incomplete_lookup"))
        for cve, expected in scenarios:
            with tempfile.TemporaryDirectory() as tmp:
                _, out, _, _, _, _ = self._run(tmp, cves=[cve_row], cve=cve)
                result = json.loads(out.read_text().splitlines()[0])
                self.assertEqual(result["cve_retrieval"]["identities"][0]["retrieval_status"], expected)
                self.assertEqual(result["record_status"], "partial_error")


if __name__ == "__main__":
    unittest.main()
