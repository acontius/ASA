# ASA — Agentic Vulnerability Scanner

Passive assessment pipeline that extracts software/product identification evidence from network scan output, preparing it for later CPE resolution and vulnerability assessment.

**Current milestone:** M4 — Offline CVE intelligence import and conservative applicability assessment.

## Run the pipeline

Requires Python 3.11 (3.10 can import the modules; the test suite is executed on 3.11). No third-party packages.

```bash
python3.11 -m app.cli \
  --input Data/PartOfMe.json \
  --output out/outcomes.jsonl \
  --checkpoint out/scan.ckpt.json

# resume after an interruption
python3.11 -m app.cli --input Data/PartOfMe.json \
  --output out/outcomes.jsonl --checkpoint out/scan.ckpt.json --resume
```

The CLI refuses to write outcomes onto the input path. Details: [docs/m2_implementation.md](docs/m2_implementation.md).

## M3 — resolve candidates to official CPE names

M3 does not change the M2 pipeline. It imports a **local** NVD CPE Dictionary 2.0 JSON file into SQLite, then resolves an outcomes file offline. It does not download NVD data and it does not send scan output anywhere.

```bash
python3.11 -m app.cpe.cli import \
  --source ./local-data/nvd-cpe-dictionary/ \
  --db ./out/cpe-dictionary.sqlite

python3.11 -m app.cpe.cli resolve \
  --input ./out/outcomes.jsonl \
  --output ./out/cpe-resolutions.jsonl \
  --db ./out/cpe-dictionary.sqlite
```

`--source` may be one `.json` / `.json.gz` document or a directory of those chunks. The feed `version` must be `2.0`. Only a unique active CPE with an exact product and version, plus **strong** evidence, becomes `exact_match`. Vendor and part are copied from that entry; they are never guessed. See [docs/m3_implementation.md](docs/m3_implementation.md).

## M4 — local CVE applicability

M4 does not change the M2 or M3 CLIs. It imports local NVD CVE 2.0 and CPE Match 2.0 files into a separate SQLite database, then evaluates M3 resolutions offline. It does not download NVD data and it does not send scan records, CPE lists, or assessments anywhere.

Download the feeds yourself from [NVD data feeds](https://nvd.nist.gov/vuln/data-feeds). Do not commit them.

```bash
python3.11 -m app.vulnerability.cli import-cves \
  --source ./local-data/nvd-cves/ \
  --db ./out/vulnerability-intelligence.sqlite

python3.11 -m app.vulnerability.cli import-cves \
  --source ./local-data/nvd-cves/modified/ \
  --db ./out/vulnerability-intelligence.sqlite \
  --kind incremental

python3.11 -m app.vulnerability.cli import-cpe-match \
  --source ./local-data/nvd-cpe-match/ \
  --db ./out/vulnerability-intelligence.sqlite

python3.11 -m app.vulnerability.cli assess \
  --input ./out/cpe-resolutions.jsonl \
  --output ./out/cve-assessments.jsonl \
  --db ./out/vulnerability-intelligence.sqlite
```

Only M3 `exact_match` rows with a `cpe_name_id`, strong evidence when that field is present, and `deprecated` not true are inventory. A result of `potentially_affected` means the NVD configuration tree evaluated true for that inventory. It is not a confirmed vulnerability. `no_match_in_local_feed` does not mean the asset is secure. See [docs/m4_implementation.md](docs/m4_implementation.md).

## Tests

```bash
python3.11 -m unittest discover -s tests -v
```

GitHub Actions (`.github/workflows/tests.yml`) runs that suite, plus a synthetic CLI smoke test, on pull requests, pushes to `main`, and `workflow_dispatch`. `.github/workflows/release.yml` builds a source archive on pull requests and publishes a GitHub Release only for a `v*` tag. The archive excludes scan data and databases.

## Layout

```
app/                 # M2 pipeline, app/cpe, and app/vulnerability
schemas/models.py    # M1 TypedDict contracts
schemas/cpe.py       # M3 resolution records
schemas/vulnerability.py  # M4 assessment records
tests/               # M1 through M4 tests, including synthetic NVD-shaped fixtures
docs/                # milestone notes
Data/PartOfMe.json   # sample JSONL (do not commit copies)
```

Supported protocols: SSH, HTTP/HTTPS, FTP, MongoDB. Other protocols are reported as `unsupported_protocol` unless the record also contains a supported port block.

## Privacy

Scan data stays on the local machine. No stage calls NVD, other APIs, or LLMs. Users download public NVD feeds separately and pass local paths. The CPE resolver and the CVE assessor read only local SQLite files. Fixtures use redacted addresses. Synthetic CVE, CPE Match, and CPE dictionary fixtures are not official NVD downloads. Database files and `out/` are gitignored. `potentially_affected` is not a statement that an asset is confirmed vulnerable.

## License

MIT — see LICENSE.
