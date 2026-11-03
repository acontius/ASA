"""Three-valued configuration evaluator tests."""

from __future__ import annotations

import unittest

from app.vulnerability.applicability import (
    FALSE,
    TRUE,
    UNKNOWN,
    CriteriaMapping,
    assessment_status,
    evaluate_configurations,
    evidence_for,
)


def _lookup(table: dict[str, tuple[str, set[str]]]):
    def lookup(criteria_id: str):
        if criteria_id not in table:
            return None
        status, names = table[criteria_id]
        return CriteriaMapping(status, frozenset(names))

    return lookup


def _leaf(criteria_id: str, vulnerable: bool = True, **extra) -> dict:
    body = {"vulnerable": vulnerable, "criteria": "cpe:2.3:a:example:item:*:*:*:*:*:*:*:*", "matchCriteriaId": criteria_id}
    body.update(extra)
    return body


def _node(operator: str, matches=None, children=None, negate: bool = False) -> dict:
    body = {"operator": operator, "negate": negate, "cpeMatch": matches or []}
    if children is not None:
        body["children"] = children
    return body


def _config(nodes, operator: str = "AND", negate: bool = False) -> dict:
    return {"operator": operator, "negate": negate, "nodes": nodes}


class TestApplicability(unittest.TestCase):
    def setUp(self):
        self.table = {
            "crit-a": ("Active", {"cpe-a"}),
            "crit-b": ("Active", {"cpe-b"}),
            "crit-os": ("Active", {"cpe-os"}),
            "crit-inactive": ("Inactive", {"cpe-a"}),
            "crit-empty": ("Active", set()),
        }
        self.lookup = _lookup(self.table)

    def test_single_matching_vulnerable_leaf(self):
        configs = [_config([_node("OR", [_leaf("crit-a", True)])])]
        result = evaluate_configurations(configs, {"cpe-a"}, self.lookup)
        self.assertEqual(result.value, TRUE)
        self.assertEqual(assessment_status("Analyzed", result), "potentially_affected")

    def test_non_matching_leaf_is_unknown_not_false(self):
        configs = [_config([_node("OR", [_leaf("crit-a", True)])])]
        result = evaluate_configurations(configs, {"cpe-other"}, self.lookup)
        self.assertEqual(result.value, UNKNOWN)
        self.assertNotEqual(result.value, FALSE)
        self.assertIn("product_not_observed", result.reasons)
        self.assertEqual(assessment_status("Analyzed", result), "not_evaluated")

    def test_and_with_all_conditions_present(self):
        configs = [_config([
            _node("OR", [_leaf("crit-a", True)]),
            _node("OR", [_leaf("crit-os", False)]),
        ])]
        result = evaluate_configurations(configs, {"cpe-a", "cpe-os"}, self.lookup)
        self.assertEqual(result.value, TRUE)
        self.assertEqual(assessment_status("Analyzed", result), "potentially_affected")
        evidence = evidence_for(result, {"cpe-a": ["cand-a"], "cpe-os": ["cand-os"]})
        self.assertEqual(evidence["vulnerable_candidate_ids"], ["cand-a"])
        self.assertEqual(evidence["context_candidate_ids"], ["cand-os"])

    def test_and_with_one_condition_absent_is_unknown(self):
        configs = [_config([
            _node("OR", [_leaf("crit-a", True)]),
            _node("OR", [_leaf("crit-os", False)]),
        ])]
        result = evaluate_configurations(configs, {"cpe-a"}, self.lookup)
        self.assertEqual(result.value, UNKNOWN)
        self.assertNotEqual(result.value, FALSE)
        self.assertEqual(assessment_status("Analyzed", result), "not_evaluated")

    def test_or_with_one_true_branch(self):
        configs = [_config([_node("OR", [_leaf("crit-a", True), _leaf("crit-b", True)])])]
        result = evaluate_configurations(configs, {"cpe-b"}, self.lookup)
        self.assertEqual(result.value, TRUE)
        self.assertEqual(result.vulnerable[0].criteria_id, "crit-b")
        self.assertEqual(assessment_status("Analyzed", result), "potentially_affected")

    def test_nested_and_or(self):
        nested = _node(
            "AND",
            children=[
                _node("OR", [_leaf("crit-a", True), _leaf("crit-b", True)]),
                _node("OR", [_leaf("crit-os", False)]),
            ],
        )
        result = evaluate_configurations([_config([nested])], {"cpe-b", "cpe-os"}, self.lookup)
        self.assertEqual(result.value, TRUE)
        self.assertEqual(assessment_status("Analyzed", result), "potentially_affected")
        self.assertEqual({hit.criteria_id for hit in result.vulnerable}, {"crit-b"})
        self.assertEqual({hit.criteria_id for hit in result.context}, {"crit-os"})

    def test_negated_nodes(self):
        matched = evaluate_configurations(
            [_config([_node("OR", [_leaf("crit-a", True)], negate=True)])],
            {"cpe-a"},
            self.lookup,
        )
        self.assertEqual(matched.value, FALSE)
        self.assertIsNone(assessment_status("Analyzed", matched))
        unknown = evaluate_configurations(
            [_config([_node("OR", [_leaf("crit-a", True)], negate=True)])],
            set(),
            self.lookup,
        )
        self.assertEqual(unknown.value, UNKNOWN)
        self.assertIn("negated_unknown", unknown.reasons)
        self.assertNotEqual(unknown.value, TRUE)

    def test_unknown_operator(self):
        result = evaluate_configurations([_config([_node("XOR", [_leaf("crit-a")])])] , {"cpe-a"}, self.lookup)
        self.assertEqual(result.value, UNKNOWN)
        self.assertIn("unsupported_operator", result.reasons)

    def test_missing_match_criteria_id(self):
        leaf = {"vulnerable": True, "criteria": "cpe:2.3:a:example:item:*:*:*:*:*:*:*:*"}
        result = evaluate_configurations([_config([_node("OR", [leaf])])], {"cpe-a"}, self.lookup)
        self.assertEqual(result.value, UNKNOWN)
        self.assertIn("missing_match_criteria_id", result.reasons)

    def test_criteria_without_local_mapping(self):
        result = evaluate_configurations(
            [_config([_node("OR", [_leaf("crit-missing")])])] ,
            {"cpe-a"},
            self.lookup,
        )
        self.assertEqual(result.value, UNKNOWN)
        self.assertIn("missing_cpe_match_mapping", result.reasons)
        self.assertEqual(assessment_status("Analyzed", result), "not_evaluated")

    def test_context_only_match(self):
        result = evaluate_configurations(
            [_config([_node("OR", [_leaf("crit-os", False)])])],
            {"cpe-os"},
            self.lookup,
        )
        self.assertEqual(result.value, TRUE)
        self.assertEqual(assessment_status("Analyzed", result), "context_only")

    def test_vulnerable_plus_required_context(self):
        configs = [_config([
            _node("OR", [_leaf("crit-a", True)]),
            _node("OR", [_leaf("crit-os", False)]),
        ])]
        result = evaluate_configurations(configs, {"cpe-a", "cpe-os"}, self.lookup)
        self.assertEqual(assessment_status("Analyzed", result), "potentially_affected")

    def test_context_only_branch_is_not_potentially_affected(self):
        configs = [_config([_node("OR", [_leaf("crit-os", False), _leaf("crit-a", True)])])]
        result = evaluate_configurations(configs, {"cpe-os"}, self.lookup)
        self.assertEqual(result.value, TRUE)
        self.assertEqual(assessment_status("Analyzed", result), "context_only")
        self.assertNotEqual(assessment_status("Analyzed", result), "potentially_affected")

    def test_multiple_top_level_configurations(self):
        configs = [
            _config([_node("OR", [_leaf("crit-b", True)])]),
            _config([_node("OR", [_leaf("crit-a", True)])]),
        ]
        result = evaluate_configurations(configs, {"cpe-a"}, self.lookup)
        self.assertEqual(result.value, TRUE)
        self.assertEqual(result.vulnerable[0].criteria_id, "crit-a")
        self.assertTrue(result.path.startswith("configurations[1]"))

    def test_rejected_cve_is_not_an_active_finding(self):
        result = evaluate_configurations(
            [_config([_node("OR", [_leaf("crit-a", True)])])],
            {"cpe-a"},
            self.lookup,
        )
        self.assertEqual(result.value, TRUE)
        self.assertEqual(assessment_status("Rejected", result), "rejected")
        self.assertNotEqual(assessment_status("Rejected", result), "potentially_affected")

    def test_inactive_criteria_is_not_a_positive_match(self):
        result = evaluate_configurations(
            [_config([_node("OR", [_leaf("crit-inactive", True)])])],
            {"cpe-a"},
            self.lookup,
        )
        self.assertEqual(result.value, UNKNOWN)
        self.assertIn("inactive_criteria", result.reasons)

    def test_multiple_candidate_identities_stay_on_their_cpes(self):
        result = evaluate_configurations(
            [_config([_node("OR", [_leaf("crit-a", True), _leaf("crit-b", True)])])],
            {"cpe-a", "cpe-b"},
            self.lookup,
        )
        evidence = evidence_for(result, {"cpe-a": ["c1", "c2"], "cpe-b": ["c3"]})
        self.assertEqual(evidence["vulnerable_candidate_ids"], ["c1", "c2", "c3"])
        self.assertEqual(evidence["matched_cpe_name_ids"], ["cpe-a", "cpe-b"])


if __name__ == "__main__":
    unittest.main()
