# ASA — Agentic Vulnerability Scanner

Passive assessment pipeline that extracts software/product identification evidence from network scan output, preparing it for later CPE resolution and vulnerability assessment.

**Current milestone:** M3 — Offline CPE dictionary import and conservative resolution.

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

## Tests

```bash
python3.11 -m unittest discover -s tests -v
```

GitHub Actions runs the same command on pull requests and on pushes to `main` (`.github/workflows/tests.yml`).

## Layout

```
app/                 # M2 pipeline plus app/cpe for offline resolution
schemas/models.py    # M1 TypedDict contracts
schemas/cpe.py       # M3 resolution records
tests/               # M1, M2, and M3 tests
docs/                # milestone notes
Data/PartOfMe.json   # sample JSONL (do not commit copies)
```

Supported protocols: SSH, HTTP/HTTPS, FTP, MongoDB. Other protocols are reported as `unsupported_protocol` unless the record also contains a supported port block.

## Privacy

Scan data stays on the local machine. Neither pipeline calls external APIs or LLMs. The CPE resolver reads only the local SQLite dictionary. Fixtures use redacted addresses. The synthetic CPE fixture is not an official NVD download, and dictionary databases are gitignored.

## License

MIT — see LICENSE.
