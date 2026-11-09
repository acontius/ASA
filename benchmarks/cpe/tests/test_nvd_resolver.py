from __future__ import annotations

import json
import unittest
from uuid import uuid4

from benchmarks.cpe.src.nvd_api import NvdCpeClient
from benchmarks.cpe.src.nvd_resolver import build_match_string, compare_nvd_cpe_identity, escape_cpe_component, resolve_candidate_nvd
from benchmarks.cpe.src.deterministic import process


class Response:
    def __init__(self, body): self.body = json.dumps(body).encode(); self.headers = {}
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def getcode(self): return 200
    def read(self, size=-1): return self.body if size < 0 else self.body[:size]


def doc(names=(), total=None):
    rows = [{"cpe": {"cpeName": name, "cpeNameId": str(uuid4()), "deprecated": False,
                      "deprecatedBy": [], "titles": [{"lang": "en", "title": "test"}], "refs": []}} for name in names]
    return {"resultsPerPage": len(rows), "startIndex": 0, "totalResults": len(rows) if total is None else total,
            "format": "NVD_CPE", "version": "2.0", "timestamp": "2026-11-08T00:00:00Z", "products": rows}


def candidate(**kwargs):
    return {"candidate_id": "r1", "source_path": "ports[0].banner", "product_name": "nginx", "vendor": "f5",
            "part": "a", "version": "1.25.3", "update": None, "evidence_strength": "strong", **kwargs}


CFG = {"nvd_max_requests_per_identity": 5, "nvd_keyword_fallback": True}


class NvdResolverTests(unittest.TestCase):
    def test_query_escaping_and_components(self):
        query = build_match_string(candidate(product_name="foo:bar/baz"))
        self.assertEqual(query, "cpe:2.3:a:f5:foo\\:bar\\/baz:1.25.3:*:*:*:*:*:*:*")
        self.assertEqual(escape_cpe_component("a*b?"), "a\\*b\\?")
        self.assertEqual(escape_cpe_component("two words"), "two\\ words")
        self.assertEqual(build_match_string(candidate(), wildcard_version=True), "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")

    def test_escaped_dictionary_component_is_unbound_before_comparison(self):
        name = r"cpe:2.3:a:vendor:foo\/bar:1.0:*:*:*:*:*:*:*"
        self.assertTrue(compare_nvd_cpe_identity(name, {"product_name": "foo/bar", "version": "1.0"})["valid"])
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(doc([name])))
        result = resolve_candidate_nvd(candidate(product_name="foo/bar", vendor="vendor", version="1.0"), client, CFG)
        self.assertEqual(result["resolution_status"], "exact_match")

    def test_unobserved_concrete_cpe_platform_attributes_are_rejected(self):
        fields = ("update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other")
        indexes = {name: i for i, name in enumerate(("part", "vendor", "product", "version", *fields))}
        for field in fields:
            components = ["a", "f5", "nginx", "1.25.3", "*", "*", "*", "*", "*", "*", "*"]
            components[indexes[field]] = "specific"
            name = "cpe:2.3:" + ":".join(components)
            with self.subTest(field=field):
                comparison = compare_nvd_cpe_identity(name, candidate(update=None))
                self.assertFalse(comparison["valid"])
                self.assertFalse(comparison["fields"][field])

    def test_gnu_product_prefix_avoids_invalid_space_query_and_keeps_derivation_auditable(self):
        name = "cpe:2.3:a:gnu:inetutils:1.4.1:*:*:*:*:*:*:*"
        calls = []
        def opener(req, timeout):
            from urllib.parse import parse_qs, urlsplit
            params = parse_qs(urlsplit(req.full_url).query)
            calls.append(params)
            self.assertNotIn("%5C+", req.full_url)
            self.assertEqual(params.get("cpeMatchString"), ["cpe:2.3:*:gnu:inetutils:1.4.1:*:*:*:*:*:*:*"])
            return Response(doc([name]))
        client = NvdCpeClient(min_interval=0, opener=opener)
        result = resolve_candidate_nvd(candidate(product_name="GNU inetutils", vendor=None, part=None, version="1.4.1"), client, CFG)
        self.assertEqual(result["resolution_status"], "review_required")
        self.assertEqual(result["cpe_name"], name)
        metadata = result["nvd_metadata"]
        self.assertEqual(metadata["identity_derivation"]["rule"], "gnu_publisher_prefix")
        self.assertEqual(metadata["inferred_components"], ["part"])
        self.assertEqual(metadata["source_observed_components"], ["product_name", "version"])
        self.assertEqual(metadata["request_count"], 1)
        self.assertEqual(sum(a["request_count"] for a in metadata["query_attempts"]), 1)
        self.assertEqual(len(calls), 1)

    def test_openssh_p_release_is_split_for_cpe_lookup_but_keeps_missing_identity_components_under_review(self):
        name = "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"
        queries = []
        def opener(req, timeout):
            from urllib.parse import parse_qs, urlsplit
            params = parse_qs(urlsplit(req.full_url).query)
            queries.append(params.get("cpeMatchString", [None])[0])
            return Response(doc([name]))
        source = candidate(product_name="OpenSSH", vendor=None, part=None, version="8.9p1", update=None)
        result = resolve_candidate_nvd(source, NvdCpeClient(min_interval=0, opener=opener), CFG)
        self.assertEqual(queries, ["cpe:2.3:*:*:OpenSSH:8.9:p1:*:*:*:*:*:*"])
        self.assertEqual(result["resolution_status"], "review_required")
        self.assertEqual(result["cpe_name"], name)
        metadata = result["nvd_metadata"]
        self.assertEqual(metadata["identity_derivation"], {
            "rule": "openssh_p_release_to_cpe_update", "source_component": "version",
            "observed_value": "8.9p1", "derived_version": "8.9", "derived_update": "p1",
            "requires_review": False,
        })
        self.assertEqual(metadata["inferred_components"], ["vendor", "part"])
        self.assertEqual(metadata["derived_cpe_components"], ["version", "update"])
        self.assertEqual(metadata["source_observed_components"], ["product_name", "version"])
        self.assertEqual(metadata["source_verified_components"], ["product_name", "version"])
        self.assertEqual(metadata["query_strategy"], "structured_openssh_version_update")
        self.assertIn("release suffix is mapped", result["notes"])

        fully_observed = candidate(product_name="OpenSSH", vendor="openbsd", part="a",
                                   version="9.6p1", update=None)
        active_name = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"
        exact = resolve_candidate_nvd(fully_observed,
            NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(doc([active_name]))), CFG)
        self.assertEqual(exact["resolution_status"], "exact_match")
        self.assertEqual(exact["nvd_metadata"]["inferred_components"], [])

    def test_openssh_release_split_does_not_apply_to_other_products_or_wrong_update(self):
        from urllib.parse import parse_qs, urlsplit
        wrong = "cpe:2.3:a:openbsd:openssh:8.9:p2:*:*:*:*:*:*"
        seen = []
        def opener(req, timeout):
            params = parse_qs(urlsplit(req.full_url).query)
            seen.append(params.get("cpeMatchString", [""])[0])
            return Response(doc([wrong]))
        result = resolve_candidate_nvd(candidate(product_name="OpenSSH", vendor=None, part=None,
                                                version="8.9p1", update=None),
                                       NvdCpeClient(min_interval=0, opener=opener), CFG)
        self.assertEqual(seen[0], "cpe:2.3:*:*:OpenSSH:8.9:p1:*:*:*:*:*:*")
        self.assertNotEqual(result.get("cpe_name"), wrong)
        self.assertNotEqual(result["resolution_status"], "exact_match")

        seen.clear()
        other = "cpe:2.3:a:vendor:example:8.9:p1:*:*:*:*:*:*"
        def other_opener(req, timeout):
            params = parse_qs(urlsplit(req.full_url).query)
            seen.append(params.get("cpeMatchString", [""])[0])
            return Response(doc([other]))
        resolve_candidate_nvd(candidate(product_name="Example", vendor="vendor", part="a",
                                        version="8.9p1", update=None),
                              NvdCpeClient(min_interval=0, opener=other_opener), CFG)
        self.assertEqual(seen[0], "cpe:2.3:a:vendor:Example:8.9p1:*:*:*:*:*:*:*")

    def test_exact_identity(self):
        name = "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(doc([name])))
        result = resolve_candidate_nvd(candidate(), client, CFG)
        self.assertEqual(result["resolution_status"], "exact_match")
        self.assertEqual(result["cpe_name"], name)
        self.assertEqual(result["nvd_metadata"]["cpe_source"], "nvd_api_2.0")
        self.assertEqual(result["nvd_metadata"]["query_strategy"], "structured_exact")

    def test_unique_lighttpd_candidate_with_inferred_vendor_and_part_requires_review(self):
        name = "cpe:2.3:a:lighttpd:lighttpd:1.4.29:*:*:*:*:*:*:*"
        source = candidate(product_name="lighttpd", vendor=None, part=None, version="1.4.29")
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(doc([name])))

        result = resolve_candidate_nvd(source, client, CFG)

        self.assertEqual(result["resolution_status"], "review_required")
        self.assertEqual(result["cpe_name"], name)
        self.assertEqual(result["nvd_metadata"]["inferred_components"], ["vendor", "part"])
        self.assertEqual(result["nvd_metadata"]["source_verified_components"], ["product_name", "version"])
        self.assertEqual(result["nvd_metadata"]["source_observed_components"], ["product_name", "version"])

    def test_vendor_product_version_mismatch_not_selected(self):
        variants = ["cpe:2.3:a:other:nginx:1.25.3:*:*:*:*:*:*:*",
                    "cpe:2.3:a:f5:apache:1.25.3:*:*:*:*:*:*:*",
                    "cpe:2.3:a:f5:nginx:1.25.2:*:*:*:*:*:*:*"]
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(doc(variants)))
        result = resolve_candidate_nvd(candidate(), client, CFG)
        self.assertNotEqual(result.get("cpe_name"), variants[0])
        self.assertNotEqual(result.get("cpe_name"), variants[1])
        self.assertNotEqual(result.get("cpe_name"), variants[2])

    def test_keyword_fallback_includes_observed_version_for_bounded_discovery(self):
        from urllib.parse import parse_qs, urlsplit
        terms=[]
        def opener(req, timeout):
            params=parse_qs(urlsplit(req.full_url).query)
            if "keywordSearch" in params: terms.extend(params["keywordSearch"])
            return Response(doc([]))
        client=NvdCpeClient(min_interval=0,opener=opener)
        result=resolve_candidate_nvd(candidate(),client,CFG)
        self.assertEqual(result["resolution_status"],"no_match")
        self.assertEqual(terms,["nginx f5 1.25.3"])

    def test_checkmk_mikrotik_plugin_candidates_are_rejected(self):
        plugin_names = [
            "cpe:2.3:a:tomtretbar:mikrotik:2.5.5:*:*:*:*:checkmk:*:*",
            "cpe:2.3:a:tomtretbar:mikrotik:2.5.3:*:*:*:*:checkmk:*:*",
        ]
        def opener(req, timeout):
            from urllib.parse import parse_qs, urlsplit
            params = parse_qs(urlsplit(req.full_url).query)
            match = params.get("cpeMatchString", [""])[0].casefold()
            if ":mikrotik:6.49.18:" in match:
                return Response(doc([]))
            if ":mikrotik:*:" in match:
                return Response(doc(plugin_names))
            return Response(doc(plugin_names))
        client = NvdCpeClient(min_interval=0, opener=opener)
        result = resolve_candidate_nvd(candidate(product_name="MikroTik", vendor=None, version="6.49.18"), client, CFG)
        self.assertEqual(result["resolution_status"], "no_match")
        self.assertNotIn("cpe_name", result)
        self.assertEqual(result.get("candidates"), [])
        rejected = result["nvd_metadata"]["rejected_candidates"]
        self.assertTrue(rejected)
        self.assertTrue(all("target_sw" in item["rejected_fields"] for item in rejected))
        self.assertEqual(result["nvd_metadata"]["request_count"], client.request_count)

    def test_candidate_with_unobserved_concrete_update_is_rejected(self):
        names = ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*", "cpe:2.3:a:f5:nginx:1.25.3:patch1:*:*:*:*:*:*"]
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(doc(names)))
        result = resolve_candidate_nvd(candidate(), client, CFG)
        self.assertEqual(result["resolution_status"], "exact_match")
        self.assertEqual(result["cpe_name"], names[0])
        self.assertEqual(result["nvd_metadata"]["rejected_candidates"][0]["cpe_name"], names[1])
        self.assertIn("update", result["nvd_metadata"]["rejected_candidates"][0]["rejected_fields"])

    def test_multiple_unobserved_vendors_remain_ambiguous(self):
        names = ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
                 "cpe:2.3:a:other:nginx:1.25.3:*:*:*:*:*:*:*"]
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(doc(names)))
        result = resolve_candidate_nvd(candidate(vendor=None), client, CFG)
        self.assertEqual(result["resolution_status"], "ambiguous")
        self.assertNotIn("cpe_name", result)

    def test_missing_version_does_not_choose_version(self):
        names = ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"]
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(doc(names)))
        result = resolve_candidate_nvd(candidate(version=None), client, CFG)
        self.assertEqual(result["resolution_status"], "product_only")
        self.assertNotIn("cpe_name", result)

    def test_weak_evidence_does_not_make_request(self):
        client = NvdCpeClient(min_interval=0)
        result = resolve_candidate_nvd(candidate(evidence_strength="weak"), client, CFG)
        self.assertEqual(result["resolution_status"], "skipped_weak")
        self.assertEqual(client.request_count, 0)

    def test_api_error_is_not_no_match(self):
        def fail(*a, **k): raise TimeoutError("offline")
        client = NvdCpeClient(min_interval=0, max_retries=0, opener=fail)
        result = resolve_candidate_nvd(candidate(), client, CFG)
        self.assertEqual(result["resolution_status"], "api_unavailable")
        self.assertNotEqual(result["resolution_status"], "no_match")

    def test_truncated_candidate_page_cannot_resolve(self):
        name = "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"
        client = NvdCpeClient(min_interval=0, results_per_page=1, max_pages=1,
                              opener=lambda *a, **k: Response(doc([name], total=2)))
        result = resolve_candidate_nvd(candidate(), client, CFG)
        self.assertEqual(result["resolution_status"], "incomplete_lookup")
        self.assertNotIn("cpe_name", result)

    def test_deprecated_exact_not_auto_selected(self):
        name = "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"
        body = doc([name]); body["products"][0]["cpe"]["deprecated"] = True
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(body))
        result = resolve_candidate_nvd(candidate(), client, CFG)
        self.assertEqual(result["resolution_status"], "deprecated_only")
        self.assertNotIn("cpe_name", result)

    def test_synthetic_m2_to_nvd_to_resolution_pipeline(self):
        raw = {"_source": {"id": "synthetic-ssh", "ip": "192.0.2.1", "scanTime": "2026-01-01T00:00:00Z",
                            "proto": "ssh", "port": "t22", "appId": "test", "path": "/synthetic",
                            "t22": {"ssh": {"result": {"server_id": {"software": "OpenSSH_9.6p1"}}}}}}
        m2 = process(raw, "synthetic-ssh", 1)
        self.assertEqual(len(m2["outcome"]["candidates"]), 1)
        extracted = m2["outcome"]["candidates"][0]
        self.assertEqual((extracted["product_name"], extracted["version"]), ("OpenSSH", "9.6p1"))
        name = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"
        client = NvdCpeClient(min_interval=0, opener=lambda *a, **k: Response(doc([name])))
        resolved = resolve_candidate_nvd(extracted, client, CFG)
        self.assertEqual(resolved["resolution_status"], "review_required")
        self.assertEqual(resolved["cpe_name"], name)
        self.assertEqual(resolved["nvd_metadata"]["cpe_source"], "nvd_api_2.0")
        self.assertEqual(resolved["nvd_metadata"]["inferred_components"], ["vendor", "part"])


if __name__ == "__main__": unittest.main()
