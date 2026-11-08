"""Opt-in connectivity check; normal unit tests never contact NVD."""
from __future__ import annotations

import os
import unittest

from benchmarks.cpe.src.nvd_api import NvdCpeClient


@unittest.skipUnless(os.environ.get("NVD_LIVE_TEST") == "1", "set NVD_LIVE_TEST=1 for the official NVD integration check")
class NvdLiveIntegrationTests(unittest.TestCase):
    def test_official_cpe_api_returns_valid_response(self):
        client = NvdCpeClient()
        result = client.search({"cpeMatchString": "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"})
        self.assertEqual(result.version, "2.0")
        self.assertEqual(result.http_status, 200)
        self.assertTrue(result.timestamp)
        self.assertIsInstance(result.products, list)


if __name__ == "__main__": unittest.main()
