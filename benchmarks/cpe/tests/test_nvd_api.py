from __future__ import annotations

import json
import urllib.error
import urllib.parse
import unittest
from email.message import Message
from uuid import uuid4

from benchmarks.cpe.src.nvd_api import ENDPOINT, NvdApiError, NvdCpeClient, RequestBudget, load_api_key


def response(products=None, *, start=0, total=None):
    products = products or []
    return {"resultsPerPage": len(products), "startIndex": start,
            "totalResults": len(products) if total is None else total,
            "format": "NVD_CPE", "version": "2.0", "timestamp": "2026-11-08T00:00:00.000",
            "products": products}


def product(name="cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*", *, deprecated=False):
    return {"cpe": {"cpeName": name, "cpeNameId": str(uuid4()), "deprecated": deprecated,
                     "deprecatedBy": [], "titles": [{"title": "nginx", "lang": "en"}], "refs": []}}


class FakeResponse:
    def __init__(self, body, status=200, headers=None):
        self.payload = json.dumps(body).encode(); self.status = status
        self.headers = headers or {}
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def getcode(self): return self.status
    def read(self): return self.payload


class RawResponse(FakeResponse):
    def __init__(self, payload, status=200):
        self.payload = payload; self.status = status; self.headers = {}


class NvdApiTests(unittest.TestCase):
    def test_endpoint_params_and_api_key_header(self):
        seen = []
        client = NvdCpeClient(api_key="secret-test", min_interval=0,
                              opener=lambda req, timeout: (seen.append((req, timeout)) or FakeResponse(response([product()]))))
        result = client.search({"cpeMatchString": "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"})
        req, timeout = seen[0]
        self.assertTrue(req.full_url.startswith(ENDPOINT + "?"))
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(req.full_url).query)["cpeMatchString"], ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"])
        self.assertEqual(req.get_header("Apikey"), "secret-test")
        self.assertEqual(timeout, 30)
        self.assertEqual(result.version, "2.0")
        self.assertNotIn("secret-test", repr(result))

    def test_api_key_is_not_in_error_text(self):
        client = NvdCpeClient(api_key="do-not-log", min_interval=0, max_retries=0,
                              opener=lambda *a, **k: (_ for _ in ()).throw(TimeoutError("offline")))
        with self.assertRaises(NvdApiError) as caught: client.search({"keywordSearch": "nginx"})
        self.assertNotIn("do-not-log", str(caught.exception))

    def test_key_reading_and_public_rate_mode(self):
        self.assertEqual(load_api_key({"NVD_API_KEY": "x"}, "/missing"), "x")
        self.assertIsNone(load_api_key({}, "/missing"))
        self.assertEqual(NvdCpeClient(min_interval=None).min_interval, 6.1)
        self.assertEqual(NvdCpeClient(api_key="x", min_interval=None).min_interval, 0.7)
        self.assertEqual(NvdCpeClient(min_interval=0).results_per_page, 500)

    def test_rate_pacing(self):
        now = [0.0]; sleeps = []
        def sleep(n): sleeps.append(n); now[0] += n
        client = NvdCpeClient(min_interval=6.1, clock=lambda: now[0], sleeper=sleep,
                              opener=lambda *a, **k: FakeResponse(response()))
        client.search({"keywordSearch": "nginx"})
        client.search({"keywordSearch": "apache"})
        self.assertEqual(sleeps, [6.1])

    def test_pagination(self):
        seen = []
        names = ["cpe:2.3:a:f5:nginx:1:*:*:*:*:*:*:*", "cpe:2.3:a:f5:nginx:2:*:*:*:*:*:*:*"]
        def opener(req, timeout):
            start = int(urllib.parse.parse_qs(urllib.parse.urlsplit(req.full_url).query)["startIndex"][0]); seen.append(start)
            return FakeResponse(response([product(names[start])], start=start, total=2))
        client = NvdCpeClient(min_interval=0, results_per_page=1, max_pages=3, opener=opener)
        result = client.search({"keywordSearch": "nginx"})
        self.assertEqual(seen, [0, 1]); self.assertTrue(result.pagination_complete)
        self.assertEqual(result.pages_fetched, 2)

    def test_incomplete_page_is_not_marked_complete(self):
        client = NvdCpeClient(min_interval=0, results_per_page=1, max_pages=1,
                              opener=lambda *a, **k: FakeResponse(response([product()], total=3)))
        result = client.search({"keywordSearch": "nginx"})
        self.assertFalse(result.pagination_complete)
        self.assertEqual(result.truncated_reason, "max_pages_reached")

    def test_retries_transient_and_respects_retry_after(self):
        delays = []; calls = [0]
        def opener(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                headers = Message(); headers["Retry-After"] = "2"
                raise urllib.error.HTTPError(ENDPOINT, 429, "slow down", headers, None)
            return FakeResponse(response())
        client = NvdCpeClient(min_interval=0, max_retries=2, opener=opener, sleeper=delays.append, jitter=lambda: 0)
        result = client.search({"keywordSearch": "nginx"})
        self.assertEqual(delays, [2.0]); self.assertEqual(result.retry_count, 1)

    def test_retries_server_error_and_timeout(self):
        calls = [0]; delays = []
        def opener(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1: raise urllib.error.HTTPError(ENDPOINT, 503, "busy", Message(), None)
            if calls[0] == 2: raise TimeoutError("timeout")
            return FakeResponse(response())
        client = NvdCpeClient(min_interval=0, max_retries=2, opener=opener,
                              sleeper=delays.append, jitter=lambda: 0)
        result = client.search({"keywordSearch": "nginx"})
        self.assertEqual(result.retry_count, 2)
        self.assertEqual(calls[0], 3)
        self.assertEqual(delays, [1, 2])

    def test_invalid_json_and_schema_are_explicit(self):
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: FakeResponse({"bad": True}))
        with self.assertRaises(NvdApiError) as caught: client.search({"keywordSearch": "x"})
        self.assertEqual(caught.exception.category, "invalid_response")
        broken = NvdCpeClient(min_interval=0, opener=lambda *a, **k: RawResponse(b"not json"))
        with self.assertRaises(NvdApiError) as caught_json: broken.search({"keywordSearch": "x"})
        self.assertIn("malformed JSON", str(caught_json.exception))

    def test_bad_candidate_rejected(self):
        malformed = response([{"cpe": {"cpeName": "not-cpe", "cpeNameId": str(uuid4()), "deprecated": False}}])
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: FakeResponse(malformed))
        with self.assertRaises(NvdApiError) as caught: client.search({"keywordSearch": "x"})
        self.assertEqual(caught.exception.category, "invalid_response")

    def test_budget_and_parameter_validation(self):
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: FakeResponse(response()))
        with self.assertRaises(ValueError): client.search({"keywordSearch": "x", "cpeMatchString": "y"})
        with self.assertRaises(NvdApiError) as caught: client.search({"keywordSearch": "x"}, budget=RequestBudget(0))
        self.assertEqual(caught.exception.category, "request_budget_exceeded")


if __name__ == "__main__": unittest.main()
