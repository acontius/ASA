# M3 Acceptance

| Criterion | Expected result | Status | Evidence |
| --------- | --------------- | ------ | -------- |
| CPE Dictionary 2.0 JSON shape | Importer reads `version` 2.0, `format` NVD_CPE, `products[].cpe` | PASS | `tests/test_cpe_importer.py` sample and chunk tests |
| Wrong schema rejected | Version other than 2.0 aborts | PASS | `test_wrong_version_rolls_back` |
| SQLite dictionary created | Rows and metadata written | PASS | importer tests open the database and count 6 rows |
| Transaction rollback | Failed import keeps no rows and no metadata | PASS | `test_wrong_version_rolls_back` |
| Repeat import | Second run inserts 0 and counts duplicates | PASS | `test_sample_and_idempotent_reimport` (`duplicates=6`) |
| Parser escapes and rejects | Escaped colon kept; short names and bad escapes rejected | PASS | `tests/test_cpe_parser.py` |
| Exact strong match only | Unique active product+version and strong evidence | PASS | `test_exact_strong_match_copies_vendor_and_part` |
| Wrong version | `no_match`, no invented CPE | PASS | `test_wrong_version_and_unknown_product` |
| Moderate evidence | `review_required`, not `exact_match` | PASS | `test_moderate_is_not_auto_resolved` |
| Weak evidence | `skipped_weak` | PASS | `test_weak_skipped_and_deprecated_only` |
| Ambiguous vendor/part | `ambiguous`, vendor not chosen | PASS | `test_ambiguous_vendors_are_not_guessed` |
| Deprecated only | `deprecated_only` | PASS | `test_weak_skipped_and_deprecated_only` |
| No alias guessing | MikroTik does not match another product | PASS | `test_invalid_candidate_and_no_alias` |
| Vendor not invented before a unique hit | Copied only from the matched row | PASS | exact-match test sets vendor `f5` from the row; candidate vendor was null |
| M2 contracts unchanged | Existing suite still passes | PASS | full `unittest discover`: 61 tests OK, including all M1/M2 tests |
| Incremental resolve | Line loop, bad line does not abort, provenance kept | PASS | `test_streaming_provenance_and_bad_lines` |
| Input not overwritten | Same path raises | PASS | `test_refuses_to_overwrite_input` |
| M2 then M3 on a fixture | SSH fixture resolves to synthetic OpenSSH CPE | PASS | `test_m2_fixture_then_m3` |
| CI workflow added | Python 3.11 unit tests on PR and `main` | PASS (file) | `.github/workflows/tests.yml`. GitHub run result is recorded in the PR, not in this file until the workflow executes |
| No scan data sent out | Resolver and importer take local paths only | PASS | `app/cpe/` has no HTTP client |
| Dictionary not committed | Gitignore covers `*.sqlite`; fixture is labeled synthetic | PASS | `.gitignore`, fixture `_comment` |
| Real NVD feed imported | Official feed imported and counted | NOT EXECUTED | No official feed was present. Tests use `tests/fixtures/cpe_dictionary_sample.json` only |
| 4 GB scan set | Not required for M3 | NOT EXECUTED | Unchanged from M2 |
