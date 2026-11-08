# ASA CPE extraction benchmark

The benchmark reuses ASA's M2 normalizer/extractors and M3 resolver without changing production M1–M4 behavior. Its methods are `deterministic`, `llm` (local Direct extraction plus shared M3), and `agent` (local tool-using Agent). RAG is not implemented. Smoke runs call the existing runner; they do not download models or fall back to remote inference.

## Gold Dataset v2

Gold is JSONL with one row per source record. Each row has explicit `schema_version: "2.0"`, an opaque `record_id`, a SHA-256 `source_hash`, a record-level review status, zero or more `expected_identities`, and annotation metadata. The raw scan record stays in the input file and is never copied into Gold.

```json
{
  "schema_version": "2.0",
  "record_id": "rec-0123456789abcdef",
  "source_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "annotation_status": "reviewed",
  "expected_identities": [
    {
      "identity_id": "rec-0123456789abcdef-1",
      "expected_product": "ExampleServer",
      "expected_vendor": "ExampleOrg",
      "expected_version": "2.4",
      "expected_update": null,
      "expected_part": "a",
      "cpe_mapping_status": "mapped",
      "expected_cpe23": "cpe:2.3:a:exampleorg:exampleserver:2.4:*:*:*:*:*:*:*",
      "acceptable_cpes": [],
      "evidence_paths": ["_source.t80.http.result.headers.server"],
      "adjudication_notes": "Synthetic documentation example."
    }
  ],
  "annotation": {
    "annotator_id": "annotator-1",
    "reviewed_at": "2026-01-15T12:00:00Z",
    "adjudication_status": "reviewed",
    "reviewer_id": "reviewer-1",
    "notes": "Synthetic example only."
  }
}
```

Record statuses are `reviewed` (all identifiable identities recorded), `no_software_identity` (reviewed confirmed negative), `ambiguous`, `insufficient_evidence`, `out_of_scope`, and `unreviewed`. Primary scoring requires record status `reviewed` or `no_software_identity` **and** annotation adjudication status `reviewed` or `adjudicated`. A pending second review therefore does not enter primary scoring. Uncertain, excluded, unreviewed, stale, and malformed rows are counted separately and never treated as confirmed negatives.

Each identity requires a concrete product and evidence path. Vendor, version, update, and CPE part are optional; `null` means unknown/unscored. CPE mapping status is `mapped`, `not_in_dictionary`, `ambiguous`, `version_unresolved`, or `unreviewed`. `mapped` requires a primary CPE; other non-mapped statuses cannot claim one. `ambiguous` may list acceptable alternatives when those alternatives are human-reviewed. Every listed CPE is parsed and checked against the specified identity components. A wildcard CPE component is accepted only when that Gold component is unspecified or `*`; a specified concrete Gold component must match. The local NVD dictionary is a retrieval/validity resource, never the source of Gold labels.

Gold v1 remains readable with its original explicit legacy interpretation. It is not silently upgraded. To create a separate v2 file, supply the source input and a destination that does not exist:

```bash
python -m benchmarks.cpe.src.migrate_gold \
  --gold-v1 /path/to/gold-v1.jsonl \
  --input /path/to/source.jsonl \
  --output /tmp/asa-gold-v2.jsonl
```

Migrated rows are marked `unreviewed`; migration carries forward only existing labels and does not generate new ones. The source Gold file is never overwritten.

## Matching and scoring

Extraction-only evaluation uses only extracted product/vendor/version/update/part fields. It does not use a model's proposed CPE as extraction accuracy. Runtime candidates and Gold identities are sets, matched with deterministic maximum-cardinality one-to-one matching: product must agree after the benchmark's documented product normalization; specified vendor/version/update/part components constrain a pairing; unknown Gold components do not constrain it. A prediction and a Gold identity can each be paired at most once. Distinct versions of the same product remain distinct identities. Unmatched Gold identities count as missing; unmatched predictions count as extra. Field metrics skip optional Gold fields but count missing predictions for fields that Gold specified.

End-to-end CPE evaluation consumes actual final CPE resolutions/proposals and scores exact CPE only against Gold identities with `mapped` status and a valid expected/acceptable CPE. Unmapped identities remain eligible for extraction scoring and are reported separately. Stale source hashes are excluded from scoring. No accuracy is reported when the corresponding denominator is empty; partial Gold coverage is exposed rather than called a complete benchmark.

`record_id` is an opaque hash of an Elasticsearch source ID (`_source.id`, then `_id`) so edits to a known source record retain the ID and are caught by `source_hash`. If neither ID exists, line position is used as a fallback; moving such records can orphan a label, so provide stable source IDs for robust annotation workflows.

## Annotation manifest

Create a small, reproducible manifest (100 rows by default, no labels or raw records) stratified by protocol, M2 outcome, and candidate-count band. Malformed JSON and non-object lines are skipped and reported:

```bash
python -m benchmarks.cpe.src.annotation_sample \
  --input Data/PartOfMe.json \
  --output benchmarks/cpe/results/annotation-manifest.jsonl \
  --size 100 --seed 20261108
```

Review workflow: (1) inspect raw evidence; (2) enter every identifiable identity and evidence path; (3) mark uncertainty explicitly; (4) have a second reviewer check a representative subset and all disputed rows; (5) adjudicate disagreements; (6) include only reviewed/adjudicated records in primary scoring. Never create Gold from Deterministic, Direct, or Agent predictions. The UI does not display model predictions while annotating.

## Local annotation and smoke-test UI

The standard-library UI binds only to loopback and requires explicit input and Gold paths. It reads JSONL one record at a time, keeps raw input read-only, validates evidence/CPEs and source hashes, and atomically saves only the requested Gold file.

```bash
python -m benchmarks.cpe.ui \
  --input Data/PartOfMe.json \
  --gold benchmarks/cpe/data/gold.jsonl \
  --host 127.0.0.1 --port 8765
```

Open <http://127.0.0.1:8765/>. The Gold tab supports record search/navigation, status filters, raw JSON viewing, evidence paths, multiple identities, and validation before save. The smoke-test tab offers only implemented methods (`deterministic`, `llm`, `agent`), a 1–40 record bound (default 5), and configured local model aliases. Start a run explicitly. It reports progress, outcomes, errors, latency, output path, and accuracy only when Gold supports scoring. Missing Gold is shown as unavailable; incomplete or partly adjudicated Gold is shown as partial, not as a complete accuracy benchmark. LLM/Agent runs require an already-running local llama.cpp endpoint configured in `config/benchmark.json` and the chosen model already installed.

## CLI benchmark

```bash
python -m benchmarks.cpe.src.runner --prepare
python -m benchmarks.cpe.src.runner --method deterministic
python -m benchmarks.cpe.src.report
```

Direct/Agent inference is local-only and is not started by the UI unless the user explicitly requests a smoke run. The runner does not download model weights. Keep raw scan inputs, Gold labels, manifests, model files, and generated results out of Git; current `.gitignore` excludes `benchmarks/cpe/data/gold.jsonl`, `benchmarks/cpe/data/sample.jsonl`, model weights, and `benchmarks/cpe/results` outputs. Check `git status` before staging any benchmark source change.

## Current limits

No human Gold annotations are included. The UI is a local testing/annotation aid, not a multi-user service. Source records without stable IDs use line positions, and moving them may orphan annotations. Optional Gold components cannot be scored as correct or incorrect. CPE exact scoring is meaningful only for human-mapped Gold identities. Model-dependent methods require manually installed weights and a local server. Repeated-run dispersion, secondary text metrics, and RAG are not implemented.
