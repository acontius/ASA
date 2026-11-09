# Production Online NVD Assessment

## Scope and command

The production path is opt-in and does not change the legacy `app.cli` M2
command or the local-database M3/M4 commands:

```bash
python -m app.cli online-assess \
  --input Data/PartOfMe.json \
  --output out/online-assessment.jsonl \
  --checkpoint out/online-assessment.ckpt.json \
  --max-api-requests 500 \
  --max-api-requests-per-identity 5
```

It reads the existing JSONL stream contract (a single-line JSON object is also accepted) and
calls the existing `process_m2_item` boundary, which uses the M1 normalizer,
protocol extractors, and record classifier. There is no new extractor or
alternate input contract.

## Authentication and request control

Set `NVD_API_KEY` in the process environment or in the ignored local `.env`
file in the command's working directory. The key is required before a run
starts and is passed to both official clients in the `apiKey` request header.
The CPE and CVE clients are checked to use the same key. It is never written
to output or checkpoints.

Only these endpoints are configured:

- CPE API 2.0: `https://services.nvd.nist.gov/rest/json/cpes/2.0`
- CVE API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0`

The per-process scheduler spaces requests from both endpoints at the more
conservative client interval (0.7 seconds with the configured API key), and
enforces `--max-api-requests` across both clients, including retries. The
clients retain their existing bounded retries, timeout, pagination, response
size and per-identity limits. Requests are made serially by the streaming
pipeline. An exhausted budget produces incomplete/budget statuses; it is not
reported as a successful empty lookup. See the [official NVD API guidance](https://nvd.nist.gov/developers),
[CVE API schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
and [NVD API status page](https://www.nist.gov/itl/nvd) for current service
and schema information. The current schema identifies as 2.2.4.

## Identity and assessment stages

For each input record, the workflow:

1. Streams and normalizes one input record.
2. Extracts all identities with the existing deterministic M2 extractors.
3. Resolves each identity through the shared online NVD CPE resolver.
4. Queries CVEs only for active, exact, concrete-version CPE identities with
   no material inferred components.
5. Retains original NVD CVE payloads and retrieval provenance.
6. Builds an inventory only from eligible identities in that same scan
   record, then evaluates each deduplicated CVE's original configuration tree.

The NVD CPE resolver can return `review_required`, `ambiguous`, `no_match`,
`skipped_weak`, `incomplete_lookup`, or API failure. These remain visible and
do not trigger automatic CVE retrieval. Current M2 protocol extractors often
do not establish vendor or CPE part; those identities may therefore require
review and be excluded from automatic CVE lookup. This is an explicit
conservative limitation, not a claim that the software has no CVEs.

Applicability results use `true`, `false`, or `unknown` and preserve a trace.
Only true configurations with a matched vulnerable criterion are labeled
`potentially_affected`. Missing platform or product evidence remains unknown.
`not_applicable` is scoped to the supplied passive evidence and is not a
`confirmed_safe` result. No result is labeled `confirmed_vulnerable`.

## Output, failure and resume behavior

Each JSONL row conforms to
[`schemas/online_assessment.schema.json`](../schemas/online_assessment.schema.json)
and includes extraction identities, per-identity CPE resolution, per-identity
CVE retrieval, full retrieved CVE records, record-scoped applicability
assessments, summaries and source/request provenance. Input banner text and
the API key are not copied into output. The original NVD `configurations`,
`affected`, metrics, weaknesses, references and other fields are retained.

Fresh execution uses exclusive output creation and refuses an existing output
or checkpoint. `--resume` requires both the existing output and checkpoint.
The shared byte-offset checkpoint is the existing M1/M2 checkpoint format; it
does not contain an input fingerprint, so resume only against the exact same
unchanged input file. Output is flushed before checkpoint advancement. A crash
between those steps can replay one line; semantics are at-least-once, not
exactly-once. The output row is written even when a record has a parsing or
NVD lookup error, preserving record-level isolation.

The online command never reads local CPE/CVE SQLite data or local NVD feeds.
The legacy workflow remains separate:

```text
Legacy: M2 -> local CPE dictionary -> local CVE/CPE Match feeds -> M4
Online: M2 -> authenticated NVD CPE API -> NVD CVE API -> online evaluator
```

Direct LLM and Agent methods remain experimental benchmark methods and are
not connected to the production online assessment path. Existing extraction
and CPE Gold v2 data do not establish applicability accuracy. A separately
adjudicated CVE-applicability Gold dataset is still required to measure
end-to-end quality.
