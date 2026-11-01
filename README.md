# ASA — Agentic Vulnerability Scanner

Passive assessment pipeline that extracts software/product identification evidence from network scan output, preparing it for later CPE resolution and vulnerability assessment.

**Current milestone:** M1 — Data Understanding and Preparation (complete).

## Repository layout

```
Data/
  PartOfMe.json      # Sample scan dataset (JSONL, ~14 MB, 1 618 records)
  structure.md       # Early notes (evaluated in M1 profile)
docs/
  m1_data_profile.md # Observed data structures, quality issues, methodology
  m1_contracts.md    # Input / Normalized / Candidate / Outcome contracts
  m1_acceptance.md   # Acceptance checklist
  m2_handoff.md      # Recommended next steps
schemas/
  models.py          # Lightweight TypedDict contracts
tests/
  fixtures/          # Sanitized representative records
  test_contracts.py  # Contract & fixture validation
```

## Supported protocols (MVP)

- SSH
- HTTP / HTTPS
- FTP
- MongoDB

## Running M1 verification

```bash
# From repository root
python -m pytest tests/test_contracts.py -v
# or without pytest:
python tests/test_contracts.py
```

## Privacy & safety

- Actual scan data must not leave the local processing boundary.
- Fixtures are sanitized (IPs replaced, geo-meta stripped).
- No external LLM or online analysis APIs are used.

## License

MIT — see LICENSE.
