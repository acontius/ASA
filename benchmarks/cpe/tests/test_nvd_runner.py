from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from benchmarks.cpe.src import runner
from benchmarks.cpe.src.nvd_api import NvdCpeClient


class Response:
    def __init__(self, body): self.body = json.dumps(body).encode(); self.headers = {}
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def getcode(self): return 200
    def read(self): return self.body


class NvdRunnerTests(unittest.TestCase):
    def test_runner_deterministic_uses_nvd_and_writes_new_output(self):
        raw = {"_source": {"id": "synthetic-ssh", "ip": "192.0.2.1", "scanTime": "2026-01-01T00:00:00Z",
                            "proto": "ssh", "port": "t22", "appId": "test", "path": "/synthetic",
                            "t22": {"ssh": {"result": {"server_id": {"software": "OpenSSH_9.6p1"}}}}}}
        cpe = "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"
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
                 patch.object(runner.NvdCpeClient, "from_config", return_value=client):
                rows = runner.run("deterministic", sample_path_override=sample_path, output_path=out)
            self.assertEqual(rows[0]["cpe_source"], "nvd_api_2.0")
            self.assertTrue(rows[0]["api_key_configured"])
            self.assertEqual(rows[0]["final_cpe_resolutions"][0]["cpe23"], cpe)
            self.assertEqual(rows[0]["final_cpe_resolutions"][0]["resolution_kind"], "nvd_api_2.0")
            self.assertEqual(rows[0]["api_requests"], 1)
            self.assertTrue(out.exists())
            serialized = out.read_text()
            self.assertNotIn("test-key", serialized)
            self.assertEqual(json.loads(serialized)["record_id"], "synthetic-ssh")

    def test_custom_sample_must_be_inside_benchmark_results(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "inside benchmarks/cpe/results"):
                runner.run("deterministic", sample_path_override=Path(temp) / "private.jsonl")


if __name__ == "__main__": unittest.main()
