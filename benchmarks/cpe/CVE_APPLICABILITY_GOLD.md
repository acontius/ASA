# Independent CVE Applicability Gold

This workflow creates human-reviewed asset/CVE cases for evaluating ASA's online NVD applicability evaluator. It is separate from Gold v2, which evaluates extraction and CPE resolution.

## Independence and scope

The manifest contains source-linked identities, evidence paths, the NVD CVE configuration snapshot, and structural sampling strata. It deliberately contains no ASA applicability prediction. Reviewers assign `true`, `false`, or `unknown` from the scan evidence and NVD conditions. Missing evidence is not a `false` label. `insufficient_evidence`, `disputed`, and `out_of_scope` are annotation statuses, not truth labels.

Each case is one source record and one CVE. The source SHA-256 and hash of the exact NVD configurations are included in the stable case ID. A changed source or configuration makes the annotation stale. The Gold validator requires human reviewer metadata and evidence references; conflicting reviews remain disputed until an independent adjudicator resolves them. No tool in this workflow reads ASA's prediction to generate a label.

The initial metrics estimate applicability correctness **conditional on selected asset/CVE cases**. They do not estimate CVEs missed during retrieval. Gold v2 extraction/CPE metrics must be reported separately. A small pilot is not population-level accuracy evidence.

## Prepare a local manifest

Use the same original local JSONL file supplied to ASA and its versioned online assessment output. The commands create new files and refuse to overwrite an existing destination:

```bash
python -m benchmarks.cpe.src.applicability_annotation_sample \
  --source /path/to/scan.jsonl \
  --assessments /path/to/online-assessment.jsonl \
  --output benchmarks/cpe/data/applicability_manifest.jsonl \
  --size 75 --seed 20261109
```

Sampling is deterministic, stratified by observable configuration structure and uniform reservoir sampling within strata. It avoids forcing true/false/unknown proportions, which are not known before annotation. It is a review pilot, not a probability sample for population estimates. The sample includes useful configuration diversity when present: AND/OR, negation, ranges, environmental criteria, multiple configurations, multiple identities, and uncertain inventory.

The input scan, assessment results, manifest and real Gold annotations are local data. They are ignored by Git. Do not publish or commit them.

## Human review

The existing Gold v2 interface is specialized for identity/CPE annotation and does not display nested NVD configuration trees or asset/CVE applicability decisions. A separate minimal local UI is provided:

```bash
python -m benchmarks.cpe.ui.applicability_server \
  --manifest benchmarks/cpe/data/applicability_manifest.jsonl \
  --source /path/to/scan.jsonl \
  --gold benchmarks/cpe/data/applicability_gold.jsonl \
  --host 127.0.0.1 --port 8766
```

Open `http://127.0.0.1:8766` locally. The server refuses non-loopback binds. The UI renders only linked source evidence, identity snapshots and the original NVD configurations; it does not expose the evaluator prediction. Save independent reviews with distinct reviewer IDs. Two conflicting labels become `disputed`; adjudication requires a third, independent reviewer and notes. The UI writes atomically and preserves prior annotation states in `annotation_history`.

Only the source-linked path values referenced by a case are loaded for display. No telemetry, remote assets, NVD requests, or LLM calls are made by the annotation UI.

## Validate and score

Validate schema, hashes, duplicate keys, reviewer metadata and eligibility:

```bash
python -m benchmarks.cpe.src.applicability_gold validate \
  --gold benchmarks/cpe/data/applicability_gold.jsonl \
  --manifest benchmarks/cpe/data/applicability_manifest.jsonl \
  --source /path/to/scan.jsonl
```

After obtaining a fresh assessment output, compute a separate JSON and Markdown report:

```bash
python -m benchmarks.cpe.src.applicability_report \
  --gold benchmarks/cpe/data/applicability_gold.jsonl \
  --manifest benchmarks/cpe/data/applicability_manifest.jsonl \
  --source /path/to/scan.jsonl \
  --predictions /path/to/online-assessment.jsonl \
  --output benchmarks/cpe/results/applicability-report.json
```

The report includes a three-class confusion matrix, per-class precision/recall/F1/support, macro and micro scores, security-positive (`Gold true`) scores, missing predictions, prediction coverage, definite-decision coverage, unknown rate, and stale/excluded cases. Undefined denominators are `null` in JSON and `N/A` in Markdown. Unreviewed, disputed, insufficient-evidence, out-of-scope and stale cases are excluded from primary scoring. Predictions never modify the Gold file.

## Interpretation and limits

`CVE retrieval != applicability`; `potentially_affected != confirmed vulnerable`; and `unknown != false`. A CVE retrieved from the official NVD CVE API is not itself evidence that the asset is affected. The Gold labels assess NVD applicability conditions against the evidence available for one passive scan record. The observed inventory is incomplete by design, so missing products/platforms frequently warrant `unknown`.

No independently reviewed applicability labels are shipped with the repository. Until reviewers complete and validate a pilot, **no independent applicability accuracy measurement is available**. Synthetic unit tests verify mechanics only; they are not accuracy evidence.
