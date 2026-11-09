from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from benchmarks.cpe.src import runner
from benchmarks.cpe.src.nvd_api import NvdCpeClient


class Response:
    def __init__(self, body): self.body = json.dumps(body).encode(); self.headers = {}
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def getcode(self): return 200
    def read(self, size=-1): return self.body if size < 0 else self.body[:size]


class NvdRunnerTests(unittest.TestCase):
    def test_runner_deterministic_uses_nvd_and_writes_new_output(self):
        raw = {"_source": {"id": "synthetic-ssh", "ip": "192.0.2.1", "scanTime": "2026-01-01T00:00:00Z",
                            "proto": "ssh", "port": "t22", "appId": "test", "path": "/synthetic",
                            "t22": {"ssh": {"result": {"server_id": {"software": "OpenSSH_9.6p1"}}}}}}
        cpe = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"
        body = {"resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "format": "NVD_CPE", "version": "2.0",
                "timestamp": "2026-11-08T00:00:00Z", "products": [{"cpe": {"cpeName": cpe,
                "cpeNameId": str(uuid4()), "deprecated": False, "deprecatedBy": [], "titles": [], "refs": []}}]}
        client = NvdCpeClient(api_key="test-key", min_interval=0, opener=lambda *a, **k: Response(body))
        record = {"record_id": "synthetic-ssh", "raw": raw, "protocol": "ssh"}
        original_config = runner.config()
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp) / "benchmarks" / "cpe"
            (base / "results").mkdir(parents=True)
            out = base / "results" / "api-smoke.jsonl"
            sample_path = base / "results" / "pilot-sample.jsonl"
            sample_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with patch.object(runner, "BASE", base), patch.object(runner, "config", return_value=original_config), \
                 patch.object(runner.NvdCpeClient, "from_config", return_value=client), \
                 patch.object(runner.NvdCveClient, "from_config") as cve_client_factory:
                rows = runner.run("deterministic", sample_path_override=sample_path, output_path=out)
                cve_client_factory.assert_not_called()
            self.assertEqual(rows[0]["cpe_source"], "nvd_api_2.0")
            self.assertTrue(rows[0]["api_key_configured"])
            self.assertEqual(rows[0]["final_cpe_resolutions"][0]["cpe23"], cpe)
            self.assertEqual(rows[0]["final_cpe_resolutions"][0]["resolution_kind"], "nvd_api_2.0")
            self.assertEqual(rows[0]["api_requests"], 1)
            self.assertTrue(out.exists())
            serialized = out.read_text()
            self.assertNotIn("test-key", serialized)
            self.assertEqual(json.loads(serialized)["record_id"], "synthetic-ssh")

    def test_include_cves_rejects_non_deterministic_methods(self):
        with self.assertRaisesRegex(ValueError, "only with --method deterministic"):
            runner.run("agent", include_cves=True, records=[])

    def test_opt_in_retrieves_cves_only_after_exact_deterministic_resolution(self):
        raw = {"_source": {"id": "synthetic-ssh", "ip": "192.0.2.1", "scanTime": "2026-01-01T00:00:00Z",
            "proto": "ssh", "port": "t22", "appId": "test", "path": "/synthetic",
            "t22": {"ssh": {"result": {"server_id": {"software": "OpenSSH_9.6p1"}}}}}}
        record = {"record_id": "synthetic-ssh", "raw": raw, "protocol": "ssh"}
        class CpeClient:
            endpoint = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
            api_key = "test-key"
            request_count = 0
        class CveClient:
            endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            api_key = "test-key"
            request_count = 0
            cache_hits = 0
            def fetch_by_cpe(self, name, *, max_requests):
                self.request_count += 1
                return SimpleNamespace(cves=[{"cve": {"id": "CVE-2025-1234", "configurations": []}}],
                    total_results=1, pages_fetched=1, requests_made=1, pagination_complete=True,
                    timestamp="2026-01-01T00:00:00Z", retry_count=0, cache_hit=False,
                    parameters={"cpeName": name}, error_category=None, error_message=None,
                    http_status=200, response_bytes=50, truncated_reason=None,
                    format="NVD_CVE", version="2.0", schema_version="2.2.4")
        original_config = runner.config()
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp) / "benchmarks" / "cpe"
            (base / "results").mkdir(parents=True)
            out = base / "results" / "cve-opt-in.jsonl"
            cve = CveClient()
            with patch.object(runner, "BASE", base), patch.object(runner, "config", return_value=original_config), \
                 patch.object(runner.NvdCpeClient, "from_config", return_value=CpeClient()), \
                 patch.object(runner.NvdCveClient, "from_config", return_value=cve), \
                 patch.object(runner, "resolve_candidate_nvd", return_value={"resolution_status": "exact_match",
                    "resolution_basis": "exact", "cpe_name": "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*",
                    "nvd_metadata": {"deprecated": False}}):
                rows = runner.run("deterministic", records=[record], output_path=out, include_cves=True,
                                  evaluate_applicability=True)
            self.assertEqual(cve.request_count, 1)
            retrieval = rows[0]["cve_retrieval"]
            self.assertEqual(retrieval["identities"][0]["retrieval_status"], "retrieved")
            self.assertEqual(retrieval["cves"][0]["cve"]["id"], "CVE-2025-1234")
            self.assertEqual(rows[0]["cve_applicability"]["evaluations"][0]["assessment_status"], "unknown")
            self.assertEqual(cve.request_count, 1)  # pure evaluator makes no additional API calls
            self.assertNotIn("test-key", out.read_text(encoding="utf-8"))

    def test_online_cve_path_requires_api_key(self):
        class Client:
            endpoint = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
            api_key = None
        with patch.object(runner.NvdCpeClient, "from_config", return_value=Client()), \
             patch.object(runner.NvdCveClient, "from_config") as cve_factory:
            cve_factory.return_value = type("Cve", (), {"api_key": None})()
            with self.assertRaisesRegex(ValueError, "requires NVD_API_KEY"):
                runner.run("deterministic", include_cves=True, records=[])

    def test_custom_sample_must_be_inside_benchmark_results(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "inside benchmarks/cpe/results"):
                runner.run("deterministic", sample_path_override=Path(temp) / "private.jsonl")


if __name__ == "__main__": unittest.main()
