import json
import unittest
import urllib.error
from urllib.parse import parse_qs, urlsplit

from benchmarks.cpe.src.nvd_cve_api import (
    ENDPOINT, NvdCveApiError, NvdCveClient, validate_cve_name,
)


CPE = "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"
NOW = "2026-01-01T00:00:00.000Z"


def item(cve_id="CVE-2025-1234"):
    return {"cve": {"id": cve_id, "published": NOW, "lastModified": NOW,
        "descriptions": [{"lang": "en", "value": "example"}], "references": [],
        "configurations": [{"operator": "AND", "nodes": [{"cpeMatch": [{
            "criteria": CPE, "matchCriteriaId": "00000000-0000-4000-8000-000000000001",
            "vulnerable": True, "versionEndExcluding": "2.0"}]}]}],
        "affected": [{"vendor": "acme", "product": "widget"}],
        "metrics": {"ssvcV203": [{"version": "2.0"}]}}}


def page(rows, start=0, total=None):
    return {"resultsPerPage": len(rows), "startIndex": start,
        "totalResults": len(rows) if total is None else total,
        "format": "NVD_CVE", "version": "2.0", "timestamp": NOW,
        "vulnerabilities": rows}


class Response:
    def __init__(self, body, status=200): self.body, self.status = body, status
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def getcode(self): return self.status
    def read(self, n=-1): return self.body[:n]


class NvdCveApiTests(unittest.TestCase):
    def client(self, bodies, **kwargs):
        calls = []
        def opener(req, timeout):
            calls.append((req, timeout))
            body = bodies.pop(0)
            return Response(body if isinstance(body, bytes) else json.dumps(body).encode())
        return NvdCveClient(opener=opener, min_interval=0, sleeper=lambda _: None,
                            jitter=lambda: 0, **kwargs), calls

    def test_validates_exact_concrete_cpe_components(self):
        self.assertEqual(validate_cve_name(CPE)["version"], "1.2")
        with self.assertRaises(ValueError): validate_cve_name("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*")

    def test_exact_query_header_pagination_and_lossless_data(self):
        client, calls = self.client([page([item()], total=2), page([item("CVE-2025-5678")], start=1, total=2)],
                                   api_key="secret", results_per_page=1, max_pages=3)
        result = client.fetch_by_cpe(CPE)
        self.assertTrue(result.pagination_complete)
        self.assertEqual(len(result.cves), 2)
        self.assertIn("configurations", result.cves[0]["cve"])
        self.assertIn("affected", result.cves[0]["cve"])
        self.assertIn("ssvcV203", result.cves[0]["cve"]["metrics"])
        self.assertEqual(parse_qs(urlsplit(calls[0][0].full_url).query)["cpeName"], [CPE])
        self.assertEqual(calls[0][0].get_header("Apikey"), "secret")
        self.assertNotIn("secret", calls[0][0].full_url)

    def test_zero_results_is_complete_no_cves(self):
        client, _ = self.client([page([])])
        result = client.fetch_by_cpe(CPE)
        self.assertEqual(result.total_results, 0)
        self.assertTrue(result.pagination_complete)
        self.assertEqual(result.cves, [])

    def test_page_limit_returns_incomplete_not_empty_success(self):
        client, _ = self.client([page([item()], total=2)], results_per_page=1, max_pages=1)
        result = client.fetch_by_cpe(CPE)
        self.assertFalse(result.pagination_complete)
        self.assertEqual(result.truncated_reason, "max_pages_reached")

    def test_invalid_cve_response_is_rejected(self):
        bad = page([{"cve": {"id": "not-a-cve"}}])
        client, _ = self.client([bad])
        with self.assertRaises(NvdCveApiError) as raised: client.fetch_by_cpe(CPE)
        self.assertEqual(raised.exception.category, "invalid_response")

    def test_oversized_response_is_classified(self):
        client, _ = self.client([b"x" * 100], max_response_bytes=10)
        with self.assertRaises(NvdCveApiError) as raised: client.fetch_by_cpe(CPE)
        self.assertEqual(raised.exception.category, "response_too_large")

    def test_429_retry_after_is_honored_and_bounded(self):
        calls, delays = [], []
        def opener(req, timeout):
            calls.append(req)
            if len(calls) == 1:
                raise urllib.error.HTTPError(req.full_url, 429, "limited", {"Retry-After": "2"}, None)
            return Response(json.dumps(page([])).encode())
        client = NvdCveClient(opener=opener, api_key="key", min_interval=0, max_retries=1,
            retry_after_cap=1, sleeper=delays.append, jitter=lambda: 0)
        result = client.fetch_by_cpe(CPE)
        self.assertTrue(result.pagination_complete)
        self.assertEqual(client.request_count, 2)
        self.assertEqual(delays, [1])

    def test_malformed_json_is_invalid_response(self):
        client, _ = self.client([b"not-json"])
        with self.assertRaises(NvdCveApiError) as raised: client.fetch_by_cpe(CPE)
        self.assertEqual(raised.exception.category, "invalid_response")

    def test_run_budget_exhaustion_is_incomplete(self):
        client, _ = self.client([page([item()], total=2)], results_per_page=1,
                                max_pages=3, max_requests_per_run=1)
        result = client.fetch_by_cpe(CPE, max_requests=3)
        self.assertFalse(result.pagination_complete)
        self.assertEqual(result.truncated_reason, "request_budget_exhausted")

    def test_endpoint_is_pinned_to_official_service(self):
        with self.assertRaises(ValueError): NvdCveClient(endpoint="https://example.com/rest/json/cves/2.0")
        self.assertEqual(ENDPOINT, "https://services.nvd.nist.gov/rest/json/cves/2.0")


if __name__ == "__main__": unittest.main()
