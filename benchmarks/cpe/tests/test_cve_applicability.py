import unittest

from benchmarks.cpe.src.cve_applicability import (
    Truth, compare_versions, evaluate_cve_applicability, truth_and, truth_not, truth_or,
)

APACHE = "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
LINUX = "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*"


def identity(iid, cpe, status="exact_match", **extra):
    return {"candidate_id": iid, "cpe23": cpe, "resolution_status": status, **extra}


def criterion(cpe, vulnerable=True, **extra):
    return {"criteria": cpe, "matchCriteriaId": "00000000-0000-0000-0000-000000000001",
            "vulnerable": vulnerable, **extra}


def cve(*matches, operator="AND", configs=True):
    return {"id": "CVE-2026-12345", "configurations": ([{"operator": operator,
            "nodes": [{"operator": operator, "cpeMatch": list(matches)}]}] if configs else None)}


class TruthTests(unittest.TestCase):
    def test_complete_truth_tables(self):
        vals = (Truth.TRUE, Truth.FALSE, Truth.UNKNOWN)
        and_expected = ((Truth.TRUE, Truth.FALSE, Truth.UNKNOWN),
                        (Truth.FALSE, Truth.FALSE, Truth.FALSE),
                        (Truth.UNKNOWN, Truth.FALSE, Truth.UNKNOWN))
        or_expected = ((Truth.TRUE, Truth.TRUE, Truth.TRUE),
                       (Truth.TRUE, Truth.FALSE, Truth.UNKNOWN),
                       (Truth.TRUE, Truth.UNKNOWN, Truth.UNKNOWN))
        for i, left in enumerate(vals):
            for j, right in enumerate(vals):
                self.assertEqual(truth_and([left, right]), and_expected[i][j])
                self.assertEqual(truth_or([left, right]), or_expected[i][j])
        self.assertEqual([truth_not(x) for x in vals], [Truth.FALSE, Truth.TRUE, Truth.UNKNOWN])


class VersionTests(unittest.TestCase):
    def test_numeric_comparison_and_incomparable_formats(self):
        self.assertEqual(compare_versions("1.2", "1.2.0"), 0)
        self.assertEqual(compare_versions("1.2.1", "1.2"), 1)
        self.assertIsNone(compare_versions("1.2.3ubuntu4", "1.2.4"))
        self.assertIsNone(compare_versions("2.0p1", "2.0"))

    def test_range_boundaries(self):
        inv = [identity("apache", APACHE)]
        def run(**bounds):
            result = evaluate_cve_applicability(cve(criterion(
                "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", **bounds)), inv)
            return result["applicability"]
        self.assertEqual(run(versionStartIncluding="2.4.58", versionEndIncluding="2.4.58"), "true")
        self.assertEqual(run(versionStartExcluding="2.4.58"), "false")
        self.assertEqual(run(versionEndExcluding="2.4.58"), "false")
        self.assertEqual(run(versionStartIncluding="2.4.59"), "false")
        self.assertEqual(run(versionEndIncluding="2.4.57"), "false")
        self.assertEqual(run(versionStartIncluding="2.4.57", versionEndExcluding="2.4.59"), "true")
        self.assertEqual(run(versionStartIncluding="2.4.58-rc1"), "unknown")


class ApplicabilityTests(unittest.TestCase):
    def test_exact_applicable_preserves_matched_identity(self):
        result = evaluate_cve_applicability(cve(criterion(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", versionEndIncluding="2.4.60")),
            [identity("apache-id", APACHE)], source_record_id="r1")
        self.assertEqual(result["assessment_status"], "potentially_affected")
        self.assertEqual(result["matched_vulnerable_identities"][0]["identity_id"], "apache-id")

    def test_known_version_outside_range_is_false(self):
        result = evaluate_cve_applicability(cve(criterion(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", versionStartIncluding="2.4.70")),
            [identity("apache-id", APACHE)])
        self.assertEqual(result["assessment_status"], "not_applicable")

    def test_missing_platform_is_unknown_not_false(self):
        result = evaluate_cve_applicability(cve(
            criterion("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", versionEndIncluding="2.4.60"),
            criterion("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", vulnerable=False)),
            [identity("apache-id", APACHE)])
        self.assertEqual(result["logic_value"], "unknown")
        self.assertEqual(result["assessment_status"], "unknown")
        self.assertTrue(result["matched_vulnerable_identities"])
        self.assertIn("criterion_not_observed_in_passive_inventory", result["reason_codes"])

    def test_same_record_identities_satisfy_and_but_cross_records_do_not_mix(self):
        cv = cve(criterion("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", versionEndIncluding="2.4.60"),
                 criterion("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", vulnerable=False))
        both = evaluate_cve_applicability(cv, [identity("web", APACHE), identity("os", LINUX)])
        only_web = evaluate_cve_applicability(cv, [identity("web", APACHE)])
        self.assertEqual(both["logic_value"], "true")
        self.assertEqual(only_web["logic_value"], "unknown")
        self.assertEqual([x["identity_id"] for x in both["matched_environmental_identities"]], ["os"])
        explicit_cross = evaluate_cve_applicability(
            cve(criterion("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")),
            [{**identity("foreign", APACHE), "source_record_id": "other"}], source_record_id="r1")
        self.assertEqual(explicit_cross["logic_value"], "unknown")
        self.assertTrue(any("cross_record_excluded" in x for x in explicit_cross["unresolved_requirements"]))

    def test_untrusted_identities_do_not_prove_match(self):
        for status in ("review_required", "ambiguous", "deprecated_only"):
            result = evaluate_cve_applicability(cve(criterion("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")),
                                                [identity("x", APACHE, status)])
            self.assertEqual(result["logic_value"], "unknown")

    def test_known_vendor_part_and_version_mismatches_disprove_anchored_product(self):
        asset = [identity("apache", APACHE)]
        for criterion_cpe in (
            "cpe:2.3:a:other_vendor:http_server:2.4.58:*:*:*:*:*:*:*",
            "cpe:2.3:o:apache:http_server:2.4.58:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.70:*:*:*:*:*:*:*",
        ):
            result = evaluate_cve_applicability(cve(criterion(criterion_cpe)), asset)
            self.assertEqual(result["logic_value"], "false", criterion_cpe)
        absent = evaluate_cve_applicability(cve(criterion(
            "cpe:2.3:a:apache:other_product:2.4.58:*:*:*:*:*:*:*")), asset)
        self.assertEqual(absent["logic_value"], "unknown")

    def test_concrete_target_platform_missing_from_cpe_is_unknown(self):
        result = evaluate_cve_applicability(cve(criterion(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:linux:*:*")), [identity("apache", APACHE)])
        self.assertEqual(result["logic_value"], "unknown")

    def test_unsupported_operators_and_embedded_version_globs_are_unknown(self):
        bad_operator = {"id": "CVE-2026-3", "configurations": [{"operator": "XOR",
            "nodes": [{"operator": "AND", "cpeMatch": [criterion("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")]}]}]}
        self.assertEqual(evaluate_cve_applicability(bad_operator, [identity("a", APACHE)])["logic_value"], "unknown")
        glob = evaluate_cve_applicability(cve(criterion(
            "cpe:2.3:a:apache:http_server:2.4.*:*:*:*:*:*:*:*", versionEndIncluding="2.4.60")),
            [identity("a", APACHE)])
        self.assertEqual(glob["logic_value"], "unknown")

    def test_or_negation_and_multiple_configurations(self):
        no_match = criterion("cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*")
        cv = {"id": "CVE-2026-23456", "configurations": [
            {"operator": "AND", "nodes": [{"operator": "OR", "negate": True,
              "cpeMatch": [no_match]}]},
            {"operator": "AND", "nodes": [{"operator": "AND", "cpeMatch": [
              criterion("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")]}]}]}
        result = evaluate_cve_applicability(cv, [identity("a", APACHE)])
        self.assertEqual(result["logic_value"], "true")

    def test_malformed_and_missing_configuration_are_unknown(self):
        self.assertEqual(evaluate_cve_applicability({"id": "CVE-2026-1"}, [])["logic_value"], "unknown")
        bad = {"id": "CVE-2026-2", "configurations": [{"nodes": []}]}
        self.assertEqual(evaluate_cve_applicability(bad, [])["logic_value"], "unknown")

    def test_does_not_mutate_nvd_payload_or_treat_escaped_glob_as_regex(self):
        cv = cve(criterion(r"cpe:2.3:a:vendor:literal\*:1.0:*:*:*:*:*:*:*"))
        before = repr(cv)
        result = evaluate_cve_applicability(cv, [identity("x", r"cpe:2.3:a:vendor:literal\*:1.0:*:*:*:*:*:*:*")])
        self.assertEqual(result["logic_value"], "true")
        self.assertEqual(repr(cv), before)


if __name__ == "__main__": unittest.main()
