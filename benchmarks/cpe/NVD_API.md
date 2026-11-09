# Deterministic NVD CPE API 2.0

Only the deterministic benchmark method uses the online NVD CPE API 2.0:

```text
https://services.nvd.nist.gov/rest/json/cpes/2.0
```

It reuses existing M2 extraction and does not use the local SQLite dictionary. Direct LLM and Agent benchmark methods still use the local read-only CPE lookup; this document does not claim that they use NVD. No CVE retrieval or applicability assessment is implemented here.

Only extracted product, vendor, part, version, and update terms are sent to NVD. Raw records, banners, IP addresses, and evidence paths remain local.

Set `NVD_API_KEY` in the environment, or keep it as the only setting in the ignored `.env` file. The key is sent only as the NVD `apiKey` header. It is never included in URLs, logs, or results. Requests are serialized with a 0.7 second minimum interval when a key is configured and 6.1 seconds without one. Timeout, retry count, exponential backoff, page size, maximum pages, and per-identity request budget are configured in `config/benchmark.json`. Transient HTTP/network failures are retried a bounded number of times; `Retry-After` is respected when supplied.

The client validates each response and paginates only up to the configured page and request budgets. If the result set is truncated, status is `incomplete_lookup`; partial results cannot prove uniqueness or no-match. A real empty, fully retrieved response may produce `no_match`. API/network errors remain `api_unavailable` or `api_invalid_response`, never `no_match`.

Structured `cpeMatchString` lookup is preferred. Bounded keyword search is discovery only: its candidates are returned for review and never selected as a final CPE. Candidate selection compares parsed CPE 2.3 components; it requires an exact observed version and rejects unsupported concrete platform attributes and deprecated entries.

`exact_match` means one active CPE candidate matches the source-supported identity components and no material concrete component was filled in from the NVD candidate. If a unique candidate supplies a missing concrete identity component such as vendor or part, the CPE is retained but the status is `review_required`. The result distinguishes `source_observed_components`, `source_verified_components`, `inferred_components`, and `unresolved_components`; the original M2 identity is not rewritten. A GNU publisher-prefix lookup derivation also requires review.

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
