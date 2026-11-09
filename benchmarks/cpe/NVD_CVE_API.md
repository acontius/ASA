# NVD CVE API 2.0 retrieval

The deterministic benchmark can optionally retrieve complete CVE records from
the official NVD CVE API 2.0, using a validated, source-supported exact CPE
from the online deterministic CPE resolver. This stage retrieves evidence; it
does not establish that a CVE applies to an installed asset or that the asset
is vulnerable. Applicability evaluation is not implemented in this workflow.

Official references:

- Endpoint: <https://services.nvd.nist.gov/rest/json/cves/2.0>
- API documentation: <https://nvd.nist.gov/developers/vulnerabilities>
- JSON schema: <https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema>

The schema currently identifies itself as NVD Vulnerability Data API schema
2.2.4. The client validates the API 2.0 response envelope, pagination fields,
and required CVE identity/metadata while retaining each original `cve` object
losslessly. This preserves `configurations`, `affected`, SSVC metrics, all CVSS
metrics, and other current or future fields without interpreting them.
NVD-generated envelope timestamps may omit a timezone suffix; the client
accepts valid ISO timestamps in that response form while preserving the exact
source string.

## Enable retrieval

The normal deterministic benchmark remains CPE-only and makes no CVE API
requests. Add `--include-cves` to explicitly enable this stage:

```bash
python -m benchmarks.cpe.src.runner --method deterministic --limit 5 --include-cves
```

`--include-cves` is rejected for `llm` and `agent`; those benchmark methods
still use their existing local CPE lookup paths and are not integrated with
the online NVD CPE/CVE workflow.

The optional API key is read from `NVD_API_KEY` in the process environment or
the existing local `.env` loader and is sent only in the `apiKey` HTTP header.
It is never serialized. The client pins HTTPS to the official hostname,
disables redirects and environment-proxy discovery, serializes requests, and
never invokes a remote fallback.

Public-mode pacing defaults to 6.1 seconds per request; keyed-mode pacing
defaults to 0.7 seconds. `nvd_cve_min_interval_seconds` can explicitly override
the interval in the benchmark config. Retries are bounded, exponential and
respect a capped `Retry-After`. The default timeout is 30 seconds. Pagination
uses `resultsPerPage` and `startIndex`; the documented API page maximum is
2,000, while benchmark configuration defaults to 100 per page and at most five
pages per identity. Per-identity and per-run request budgets, page limits, and
response-byte limits are configurable under `nvd_cve_*` in
`config/benchmark.json`. An interrupted/truncated result is never reported as
a complete empty result.
Rate-limit responses are retried as HTTP 429; permanent 4xx responses are
reported without retry. NIST describes the infrastructure change from
rate-limit HTTP 403 to HTTP 429 at <https://www.nist.gov/itl/nvd>.

## CPE eligibility and statuses

Only `resolution_status=exact_match` may be queried, and the CPE must parse as
CPE 2.3 with concrete part, vendor, product and version. Wildcard/NA versions,
deprecated entries, and entries whose resolution metadata lists inferred
components are excluded. `review_required` (including the lighttpd case where
NVD supplied missing vendor/part), ambiguous, weak, non-exact and invalid
resolutions are retained as explicit skipped identity rows; they are never
silently promoted to authoritative query inputs.

Retrieval statuses include `retrieved`, `no_cves`, `incomplete_lookup`,
`request_budget_exhausted`, `response_too_large`, `api_unavailable`,
`api_invalid_response`, `skipped_review_required`, `skipped_ambiguous`,
`skipped_deprecated`, `skipped_non_exact_cpe`,
`skipped_nonconcrete_version`, and `invalid_cpe`. These statuses describe
retrieval only. In particular, `no_cves` means a complete API query returned
zero results; API failure and incomplete pagination are distinct.

## Output and provenance

Each JSONL result has an additive `cve_retrieval` object. It contains per-
identity query and pagination provenance, CVE IDs, API response timestamp,
HTTP status, request/retry counts, and a lossless list of unique CVE wrapper
objects. Duplicate CVE IDs are deduplicated within a record, while each
record/identity/CPE relationship is preserved in the CVE `relationships`
metadata and the top-level relationship map. Identical CPE requests are served
from an in-memory cache for the current run; cache hits make zero HTTP calls.
No persistent vulnerability database or local feed is used.

NVD `configurations` are retained without flattening or evaluation, including
operators, negations, match criteria IDs, vulnerable flags, and version
boundaries. The `affected` field and SSVC data are likewise preserved and are
not substitutes for configuration evaluation. A CVE returned for a CPE is
only a retrieval result, not proof of applicability or vulnerability.

The existing offline M1–M4 workflow is unchanged. This online integration is
benchmark-only and currently applies to the deterministic method. Direct LLM
and Agent continue to use their existing local CPE lookup mechanisms.
