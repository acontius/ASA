# Deterministic NVD CPE API 2.0

The deterministic benchmark runs the existing M2 extraction and resolves each extracted identity with the official NVD CPE API 2.0. It does not use the local SQLite dictionary. Only extracted product, vendor, part, version, and update terms are sent to NVD; raw records, banners, IP addresses, and evidence paths remain local.

Set `NVD_API_KEY` in the environment, or keep it as the only setting in the repository's ignored `.env` file. The key is sent only as the NVD `apiKey` header and is never included in results. Requests are serialized and rate-limited; API/network failures remain distinct from `no_match`.

Run a quick five-record live check:

```bash
python -m benchmarks.cpe.src.runner --method deterministic --limit 5
```

Run the prepared 100-record pilot:

```bash
python -m benchmarks.cpe.src.runner \
  --method deterministic \
  --sample benchmarks/cpe/results/pilot-sample.jsonl \
  --limit 100
```

Custom samples must be JSONL files inside `benchmarks/cpe/results`. Each run creates a new JSONL result and summary there; existing outputs are not overwritten. The result records API provenance and per-identity resolution metadata. A nonempty `gold.jsonl` with independently reviewed labels is required for accuracy metrics; without it, accuracy is unavailable.

Run network-free tests:

```bash
python -m unittest \
  benchmarks.cpe.tests.test_nvd_api \
  benchmarks.cpe.tests.test_nvd_resolver \
  benchmarks.cpe.tests.test_nvd_runner -v
```

Optional live API test:

```bash
NVD_LIVE_TEST=1 python -m unittest benchmarks.cpe.tests.test_nvd_integration -v
```
