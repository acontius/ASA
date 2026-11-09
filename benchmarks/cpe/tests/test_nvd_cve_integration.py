import os
import unittest

from benchmarks.cpe.src.nvd_cve_api import NvdCveClient


@unittest.skipUnless(os.environ.get("NVD_CVE_LIVE_TEST") == "1",
                     "set NVD_CVE_LIVE_TEST=1 to query the official NVD CVE API")
class NvdCveLiveIntegrationTests(unittest.TestCase):
    def test_official_cve_api_returns_valid_page(self):
        # Harmless public product identity; no scan record or host data is sent.
        client = NvdCveClient(timeout=30, max_retries=1, max_pages=1,
            results_per_page=5, max_requests_per_run=1)
        result = client.fetch_by_cpe(
            "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*", max_requests=1)
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.format, "NVD_CVE")
        self.assertEqual(result.version, "2.0")
        self.assertGreaterEqual(result.total_results, 0)
        self.assertLessEqual(len(result.cves), 5)


if __name__ == "__main__": unittest.main()
