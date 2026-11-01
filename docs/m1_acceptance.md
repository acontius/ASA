# M1 Acceptance Criteria

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Input format correctly identified as JSONL with `_source` payload | PASS | Full parse of 1 618 records; documented in `docs/m1_data_profile.md` |
| 2 | Envelope fields catalogued with observed types | PASS | Profile + contracts |
| 3 | All observed `t*` / `u*` blocks recognised in contract | PASS | Multi-port analysis (64 multi-block records) |
| 4 | Wrapper differences (`pub-zgrab2` vs `pub-tgrab`) documented | PASS | Profile §4 |
| 5 | Supported-protocol signal paths verified against real data | PASS | SSH / HTTP / FTP / MongoDB examples extracted |
| 6 | Weak / ambiguous / missing-evidence cases characterised | PASS | Profile §6 + fixtures |
| 7 | Timestamp semantics (`scanTime` vs `timestamp`) clarified | PASS | Profile + contracts |
| 8 | Input / Normalized / Candidate / Outcome contracts defined | PASS | `docs/m1_contracts.md` |
| 9 | Representative sanitized fixtures created for each supported protocol + multi-port + unsupported | PASS | `tests/fixtures/` |
| 10 | Automated tests validating contract shapes and fixture loadability | PASS | `tests/test_contracts.py` (run results below) |
| 11 | Memory-conscious profiling performed (no full 4 GB assumption) | PASS | Entire sample (14 MB) streamed/parsed safely |
| 12 | Profiling procedure reproducible from repository state | PASS | Commands recorded in profile |
| 13 | Clear separation of observed facts / constraints / open questions | PASS | Profile §7 + handoff |
| 14 | No raw sensitive data committed in new fixtures | PASS | IPs replaced, geo-meta stripped |
| 15 | M2 handoff document produced | PASS | `docs/m2_handoff.md` |

**Overall M1 status:** COMPLETE (subject to PR review and CI if added later).
