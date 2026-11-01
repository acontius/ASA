# ASA — Agentic Vulnerability Scanner

Passive assessment pipeline that extracts software/product identification evidence from network scan output, preparing it for later CPE resolution and vulnerability assessment.

**Current milestone:** M2 — Streaming ingestion and deterministic extraction (complete).

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

The CLI refuses to write outcomes onto the input path. Details, outcome rules, and checkpoint semantics: [docs/m2_implementation.md](docs/m2_implementation.md).

## Tests

```bash
python3.11 -m unittest discover -s tests -v
```

## Layout

```
app/                 # reader, normalizer, extractors, pipeline, CLI
schemas/models.py    # M1 TypedDict contracts
tests/               # M1 contract tests + M2 unit/pipeline tests
docs/                # M1 profile and contracts, M2 handoff and implementation
Data/PartOfMe.json   # sample JSONL (do not commit copies)
```

Supported protocols: SSH, HTTP/HTTPS, FTP, MongoDB. Other protocols are reported as `unsupported_protocol` unless the record also contains a supported port block.

## Privacy

Scan data stays on the local machine. The pipeline does not call external APIs or LLMs. Fixtures use redacted addresses.

## License

MIT — see LICENSE.
