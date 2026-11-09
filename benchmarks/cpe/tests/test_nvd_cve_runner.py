import unittest
from types import SimpleNamespace

from benchmarks.cpe.src.nvd_cve_runner import retrieve_record_cves
from benchmarks.cpe.src.nvd_cve_api import ENDPOINT


CPE = "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"
LIGHTTPD = "cpe:2.3:a:lighttpd:lighttpd:1.4.29:*:*:*:*:*:*:*"


class FakeClient:
    endpoint = ENDPOINT
    def __init__(self): self.queries = []; self.request_count = 0; self.cache_hits = 0; self.cache = {}
    def fetch_by_cpe(self, name, *, max_requests):
        if name in self.cache:
            self.cache_hits += 1
            return self.cache[name]
        self.queries.append(name)
        self.request_count += 1
        result = SimpleNamespace(cves=[{"cve": {"id": "CVE-2025-1234", "configurations": []}}],
            total_results=1, pages_fetched=1, requests_made=1, pagination_complete=True,
            timestamp="2026-01-01T00:00:00Z", retry_count=0, cache_hit=False,
            parameters={"cpeName": name}, error_category=None, truncated_reason=None,
            http_status=200, response_bytes=100, error_message=None,
            format="NVD_CVE", version="2.0", schema_version="2.2.4")
        self.cache[name] = result
        return result


def resolution(identity, status="exact_match", **extra):
    return {"candidate_id": identity, "source_path": "service.banner", "resolution_status": status,
        "cpe23": CPE, **extra}


class NvdCveRunnerTests(unittest.TestCase):
    def test_exact_queries_and_uncertain_identities_are_skipped(self):
        client = FakeClient()
        rows = [resolution("one"), resolution("lighttpd", "review_required", cpe23=LIGHTTPD,
                nvd_metadata={"inferred_components": ["vendor", "part"]}),
                resolution("ambiguous", "ambiguous"), resolution("deprecated", "exact_match",
                deprecated=True), resolution("unknown-version", "exact_match",
                cpe23="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*")]
        result = retrieve_record_cves("record-1", rows, client)
        self.assertEqual(client.queries, [CPE])
        self.assertEqual([x["retrieval_status"] for x in result["identities"]],
            ["retrieved", "skipped_review_required", "skipped_ambiguous",
             "skipped_deprecated", "skipped_nonconcrete_version"])

    def test_multiple_identities_retain_links_for_duplicate_cve(self):
        client = FakeClient()
        result = retrieve_record_cves("record-1", [resolution("one"), resolution("two")], client)
        self.assertEqual(result["unique_cve_count"], 1)
        self.assertEqual(len(result["relationships"]["CVE-2025-1234"]), 2)
        self.assertEqual(result["request_count"], 1)  # second same CPE came from in-run client cache in real client

    def test_nonexact_and_nonconcrete_inputs_never_query(self):
        client = FakeClient()
        result = retrieve_record_cves("r", [resolution("review", "review_required"),
            resolution("wild", "exact_match", cpe23="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*")], client)
        self.assertEqual(client.queries, [])
        self.assertEqual(result["request_count"], 0)


if __name__ == "__main__": unittest.main()
