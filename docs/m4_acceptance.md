# M4 acceptance

Local command: `python3.11 -m unittest discover -s tests -v` on 2026-11-03. Result: 105 tests, OK (61 previous + 44 M4).

Memory: a child process imported 2,000 synthetic CVE records (846,968 JSON bytes, gzipped) and peaked at 20,028 KB RSS (`ru_maxrss` on Linux). The official CPE Match feed was not part of that measurement.

| Criterion | Expected Result | Status | Evidence |
| --------- | --------------- | ------ | -------- |
| NVD CVE 2.0 JSON | `format=NVD_CVE`, `version=2.0`, `vulnerabilities[].cve` | PASS | `tests/test_cve_importer.py` valid feed; wrong version and missing array fail |
| NVD CPE Match 2.0 | `format=NVD_CPE_Match_String`, `version=2.0`, `matchStrings[].matchString` | PASS | `tests/test_cpematch_importer.py` |
| Local packaging | `.json`, `.json.gz`, `.zip` members, directory of chunks | PASS | gzip/zip/directory tests in both importer modules |
| Repeatable imports | second import does not duplicate CVE or criteria rows | PASS | idempotency and repeatable-import tests |
| Modified CVE upsert | existing CVE description and `lastModified` change, one row remains | PASS | `test_modified_feed_updates_existing_cve` |
| Match criteria index | criteria id and CPE name id indexes exist; ranges stored | PASS | `idx_cve_criteria_mid`, `idx_cpe_match_name`, nginx range assertions |
| Large archive memory | members and array elements are not loaded as one document | PASS for the streaming design and a 2,000-record synthetic gzip (peak RSS 20,028 KB). NOT a measurement of the official ~836 MB feed | `feedio.iter_array_items`; child-process `ru_maxrss` |
| Recursive configurations | nested nodes evaluated, not flattened | PASS | `test_nested_and_or` |
| AND, OR, negate | Kleene tests including NOT UNKNOWN stays UNKNOWN | PASS | `tests/test_applicability.py` |
| Missing inventory is UNKNOWN | absent product is not FALSE | PASS | `test_and_with_one_condition_absent_is_unknown`, `test_non_matching_leaf_is_unknown_not_false` |
| Context cannot find by itself | `vulnerable: false` alone is `context_only` | PASS | `test_context_only_match`, `test_context_only_branch_is_not_potentially_affected` |
| Verified inventory only | `exact_match` plus cpe name id; review/weak/product_only excluded | PASS | `test_statuses_evidence_metrics_and_no_cross_record_leakage` |
| Evidence preserved | candidate ids, CPE name ids, criteria ids | PASS | nginx and M2→M3→M4 pipeline tests |
| Rejected CVEs | status stored and assessment is `rejected`, not `potentially_affected` | PASS | importer rejected count; `test_rejected_cve_is_not_an_active_finding` |
| CVSS sources and versions | v2, v3.1, and v4 objects copied with source and base score | PASS | CVE-2026-9001 assertions |
| M1–M3 compatibility | previous tests still pass; M2/M3 CLIs untouched | PASS | 105 tests OK, including the original 61 |
| Local tests | full suite | PASS | 105 OK |
| GitHub Actions on the M4 PR | tests workflow success on the PR head SHA | NOT VERIFIED | filled after the PR workflow finishes |
| GitHub Actions on main | push-to-main workflow success | NOT VERIFIED | filled after merge |
| Release artifact build | `release.yml` uploads the archive on the PR | NOT VERIFIED | filled after that workflow finishes |
| Archive excludes scan data | no `PartOfMe.json`, `out/`, or sqlite | PASS locally | `tests/test_release_archive.py` |
| Docs | this file and `m4_implementation.md` | PASS | both files present |
| No scan data leaves the process | no network client in M4 | PASS | importers and assessor take local paths only; CI uses synthetic fixtures |
| No confirmed-vulnerability claim | status set has no `confirmed_vulnerable` | PASS | `schemas/vulnerability.py`; pipeline tests search the output |
| Official full NVD feed import | a real CVE and CPE Match feed imported | NOT EXECUTED | only synthetic fixtures were imported |
