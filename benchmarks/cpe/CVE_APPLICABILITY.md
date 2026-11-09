# Online NVD CVE applicability evaluation

The deterministic benchmark can optionally evaluate the original
`configurations` tree in each NVD CVE response against the exact CPE identities
supported by the same scan record. Enable both stages explicitly:

```bash
python -m benchmarks.cpe.src.runner --method deterministic --limit 5 \
  --include-cves --evaluate-applicability
```

The CPE and CVE clients use the shared `NVD_API_KEY` environment variable or
the existing `.env` loader and send it only in the official `apiKey` header.
The online CVE option fails before processing if the key is unavailable, and
verifies that both clients received the same configured key. The default CPE
benchmark remains unchanged and makes no CVE requests.

## Evaluation model

The pure evaluator is `benchmarks.cpe.src.cve_applicability`. It receives one
original NVD `cve` object and one record's CPE resolutions. It performs no
network, database, environment or filesystem access and never mutates the NVD
payload.

Only `exact_match` CPE resolutions with a valid concrete part, vendor, product
and version are admitted to the asset inventory. Deprecated or inferred
components and `review_required`, ambiguous, weak, incomplete and failed
resolutions remain excluded. Inventory is built separately for every source
record, so identities from different records cannot satisfy one configuration.

The evaluator uses Kleene three-valued logic (`true`, `false`, `unknown`) for
AND, OR and NOT. Top-level NVD configurations are alternatives (OR); nodes use
their explicit operator. Missing operators, malformed trees, unsupported CPE
wildcard patterns, or insufficient evidence produce `unknown`. A product not
observed in a passive scan is not assumed absent. A concrete mismatch can
disprove a criterion only after its part/vendor/product identity is anchored
to a source-supported inventory identity.

The criterion's `vulnerable` flag is retained. A true criterion marked
`vulnerable: false` is treated as environmental context, such as an operating
system prerequisite. It participates in the boolean tree but is not counted as
vulnerable software. A true configuration with no matched vulnerable
criterion is reported as `unknown`, not as a positive vulnerability result.

Numeric dotted versions (for example, `2.4.58`) are compared component-wise,
with trailing zero components treated as equal. Inclusive and exclusive NVD
start/end bounds are supported. Other formats, including distro suffixes,
lettered patch versions and prereleases, are not ordered heuristically and
produce `unknown` when a range decision depends on them. This conservative
implementation does not claim full CPE Name Matching (WFN) support for
embedded glob patterns; such patterns remain unknown. Exact escaped literal
punctuation is parsed through the shared benchmark CPE 2.3 parser.

## Output and interpretation

When enabled, each deterministic JSONL row adds `cve_applicability`, with one
assessment per deduplicated CVE in that source record. It preserves source
record and CVE-to-identity relationships, truth value, assessment status,
matched vulnerable/context identities, unresolved requirements, reason codes,
and a recursive configuration/criterion trace. Retrieved CVE payloads remain
in `cve_retrieval` unchanged.

Statuses are:

- `potentially_affected`: the complete evaluated configuration is true and at
  least one vulnerable criterion matched.
- `not_applicable`: available source-supported evidence makes the configuration
  false. This is scoped to this CVE/configuration evaluation and does not mean
  the asset is safe.
- `unknown`: evidence is missing, incomplete, malformed or unsupported.

`CVE retrieval != CVE applicability`; `CVE applicability != confirmed
vulnerability`. No exploitation or active scanning is performed.

## Current limitations

- Only numeric dotted version ordering is supported. Other version schemes
  return unknown for range checks.
- Escaped literal punctuation is supported by the shared parser; embedded CPE
  wildcard/glob semantics are not evaluated and return unknown.
- Missing configuration operators and malformed structures return unknown.
- The evaluator uses the NVD `configurations` field; it preserves but does not
  interpret `affected`, SSVC, CVSS or other advisory fields.
- Direct LLM and Agent remain on their existing local CPE paths and are not
  connected to online CVE retrieval/evaluation.
- This is benchmark-only; legacy offline M1–M4 behavior is unchanged.

The upstream data contract is documented by the [NVD CVE API schema 2.2.4](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
and [NVD vulnerability detail pages](https://nvd.nist.gov/vuln/Vulnerability-Detail-Pages).
