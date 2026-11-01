# M3 Implementation — Offline CPE Resolution

M3 adds one stage after M2. It does not change extraction, outcomes, or checkpointing.

## Objective

Turn M2 `ExtractionCandidate` values into conservative CPE resolutions using a local copy of the NVD CPE Dictionary 2.0. A resolution is not a vulnerability finding.

## Data flow

```
local NVD CPE 2.0 JSON chunks
  -> app.cpe.importer (one file at a time, one SQLite transaction)
  -> SQLite dictionary

M2 outcomes JSONL
  -> app.cpe.pipeline (one line at a time)
  -> app.cpe.resolver
  -> resolution JSONL
```

No step contacts NVD, an LLM, or any other network service.

## Dictionary input

The importer accepts the current CPE API 2.0 / dictionary JSON shape (the legacy XML feed is not supported):

```json
{
  "format": "NVD_CPE",
  "version": "2.0",
  "timestamp": "2026-01-01T00:00:00.000",
  "products": [
    {"cpe": {
      "deprecated": false,
      "cpeName": "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*",
      "cpeNameId": "uuid",
      "titles": [{"title": "Example", "lang": "en"}]
    }}
  ]
}
```

`--source` is one `.json` or `.json.gz` file, or a directory of those files. Each file is parsed and discarded before the next file is opened. `version` must be `2.0`. `format`, when present, must be `NVD_CPE`.

A bad schema version aborts the import and rolls the transaction back, so earlier chunks from that run are not kept. A single malformed CPE name, or a product object missing `cpeName` / `cpeNameId`, is counted and skipped. Re-importing the same `cpeNameId` does not insert a second row.

`tests/fixtures/cpe_dictionary_sample.json` follows this shape and is explicitly synthetic. The official NVD feed was **not** downloaded or imported in this milestone.

## SQLite

| Table | Contents |
|-------|----------|
| `dictionary_metadata` | schema version `2.0`, feed timestamp, import time, source note |
| `cpe_entries` | parsed components, English title, deprecated flag, normalized `product_key` / `version_key` / `vendor_key` |

Index: `(product_key, deprecated, version_key)`. The original feed document is not stored per row.

## CPE parsing

`app/cpe/parser.py` splits on colons that are not escaped with `\`. Recognized escapes are `\\`, `\:`, `\*`, and `\?`. A trailing backslash or any other escape is rejected. The name must contain exactly 13 fields and start with `cpe:2.3:`.

`*` is ANY, `-` is not-applicable, and any other unescaped `*` or `?` marks the component as a wildcard. Only `concrete` product and version values can satisfy an exact match. This is not a full CPE matching language (no wildcards-as-queries, no WFN).

## Resolution rules

Product keys are NFKC, case-folded, trimmed, then stripped of spaces, underscores, and hyphens. `OpenSSH` and `openssh` match. This is not a substring or fuzzy match, and titles are never searched.

Version keys are NFKC, case-folded, and trimmed. `9.6p1` does not match `9.6`. Ranges are not inferred.

| Status | When |
|--------|------|
| `exact_match` | Strong evidence, one active row, concrete product and version equal |
| `review_required` | Same unique row, but evidence is only moderate |
| `ambiguous` | More than one active row with that product and version |
| `product_only` | Active product rows exist and the candidate has no version |
| `no_match` | No active product, or the version does not match exactly |
| `deprecated_only` | The only rows that fit are deprecated |
| `skipped_weak` | Evidence strength is `weak` (no lookup result is returned) |
| `invalid_candidate` | Missing id, missing product, or an unknown strength |

If the candidate already has a vendor, it filters rows. A null vendor is not filled in unless the match is unique, in which case `vendor` and `part` are copied from that row. Deprecated rows are never auto-selected, and there is no alias table (MikroTik is not rewritten to another product).

M2 outcomes are not modified. Each output line keeps `record_id`, `source_outcome`, candidate id, and `source_path`.

## CLI

```bash
python3.11 -m app.cpe.cli import \
  --source ./local-data/nvd-cpe-dictionary/ \
  --db ./out/cpe-dictionary.sqlite

python3.11 -m app.cpe.cli resolve \
  --input ./out/outcomes.jsonl \
  --output ./out/cpe-resolutions.jsonl \
  --db ./out/cpe-dictionary.sqlite
```

Fatal problems (missing input, bad feed version, missing database, output path equal to the input) exit 2. A bad outcomes line is recorded and the file continues.

## Tests

```bash
python3.11 -m unittest discover -s tests -v
```

Observed on 2026-11-01: **61 tests, OK**. That includes the previous 41 M1/M2 tests and the M3 parser, importer, resolver, and pipeline tests. One pipeline test runs the M2 SSH fixture through resolution against the synthetic dictionary and expects `exact_match` for `openssh` `9.6p1`.

## Memory

Importing the 6-row synthetic fixture did not load a second copy of a large feed. `ru_maxrss` for that process was about 15 MB, which is the interpreter, not a feed measurement. The official dictionary was not imported, so no full-feed RSS number is claimed. Resolution reads outcomes with a line loop and writes each line immediately.

## Limitations

- Official NVD CPE Dictionary 2.0 bulk import was not executed here.
- CPE 2.3 wildcard matching (using `*` as a query) is not implemented.
- Version comparison is exact string equality after trim/case-fold. `9.6` plus update `p1` is not treated as `9.6p1`.
- No CVE, CPE Match feed, scoring, or alias curation.
- M2 resume is still at-least-once. Secondary HTTP blocks on non-MVP protocols are unchanged.
