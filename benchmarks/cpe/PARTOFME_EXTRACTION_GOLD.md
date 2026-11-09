# PartOfMe Extraction Gold Pilot

## Dataset facts

`Data/PartOfMe.json` is a whitespace-separated stream of Elasticsearch JSON
objects, not strict JSONL. The preparation command parses the stream strictly,
canonicalizes each complete object to one JSONL row, and leaves the source file
untouched. The local source inspected for this pilot contained 1,618 objects,
including one pretty-printed multi-line object, with no malformed objects. The
stream adapter fails closed if any object is malformed or not a JSON object.

Each object has stable Elasticsearch identifiers (`_source.id` and `_id`), so
the existing opaque Gold record IDs can be reproduced without exposing those
identifiers. Source hashes detect edits. Exact duplicate records and repeated
host/protocol/port keys are counted in the local metadata without writing host
addresses into the manifest.

Protocols in the complete source were: HTTP 1,118; SSH 461; FTP 22; Winbox 6;
PPTP 6; RTSP 2; DNS 1; L2TP 1; MongoDB 1. The existing extractors cover HTTP,
SSH, FTP, and MongoDB. Fields such as HTTP `Server`, SSH `server_id.software`,
and FTP banners are evidence strings; they are not automatically accepted as
independently verified vendor/product/version labels. A banner may contain a
protocol version or an ambiguous implementation label.

## Prepare the local review pilot

```bash
python -m benchmarks.cpe.src.partofme_gold prepare \
  --input Data/PartOfMe.json \
  --output-dir benchmarks/cpe/data/local/partofme-extraction-gold-v1-pilot-20261109-r2 \
  --size 100 \
  --seed 20261109

python -m benchmarks.cpe.src.partofme_gold validate \
  --output-dir benchmarks/cpe/data/local/partofme-extraction-gold-v1-pilot-20261109-r2

python -m benchmarks.cpe.src.partofme_gold evaluate \
  --output-dir benchmarks/cpe/data/local/partofme-extraction-gold-v1-pilot-20261109-r2
```

Preparation refuses to overwrite an existing output directory. All outputs
must stay under the ignored `benchmarks/cpe/data/local/` directory. It creates:

- `source.jsonl`: the sampled original source records for the existing local UI.
- `manifest.jsonl`: stable IDs, canonical source hashes, M2-only sampling
  strata, and evidence paths. The sampling strata are not Gold labels.
- `gold.jsonl`: ASA Gold v2.0 rows initialized as `unreviewed`, with no
  expected identities and no CPE mappings.
- `dataset.json`: source hash, seed, aggregate counts, and review/scoring state.
- `evaluation.json`: when `evaluate` is run, a separate result from the existing
  M2/Gold metrics implementation.

The manifest's `source_evidence_refs` state that a raw field was directly
present and that interpreting it as an installed software identity requires
human review. `field_review_hints` distinguishes direct source observations
from fields absent in the evidence. They do not claim a product identity.

The existing benchmark sampler uses M2 outcomes only to stratify the sample;
it does not place M2 predictions into the annotation UI or Gold file. The UI
remains prediction-blind. Start it with:

```bash
python -m benchmarks.cpe.ui \
  --input benchmarks/cpe/data/local/partofme-extraction-gold-v1-pilot-20261109-r2/source.jsonl \
  --gold benchmarks/cpe/data/local/partofme-extraction-gold-v1-pilot-20261109-r2/gold.jsonl \
  --host 127.0.0.1 --port 8765
```

Review every identifiable software identity, preserve multiple identities in
one record, cite evidence paths, and mark unresolved values as unknown. A
reviewed `no_software_identity` status requires positive evidence that the
record contains no identifiable software; missing evidence alone is not a
negative. Use `ambiguous` or `insufficient_evidence` where warranted. Have a
second reviewer check a representative subset and all disagreements before
adjudication.

## CPE mapping and scoring boundaries

CPE mapping remains a separate evaluation track. The local NVD CPE dictionary
is a candidate retrieval/validation resource, not proof that a scan observed
the dictionary's vendor, product, part, or version. Only human-reviewed
identities should be mapped for Gold. Ambiguous candidates remain ambiguous;
NVD-supplied missing identity components are not promoted to confirmed Gold.

The first generated pilot has 100 unreviewed rows and zero Gold identities.
Therefore, extraction precision/recall/F1 and exact CPE accuracy are unavailable
until human labels are reviewed. The `evaluate` command reports null metrics
and zero scorable cases instead of inventing a denominator. Synthetic tests do
not count as real-data accuracy. The pilot is structurally stratified and is
not claimed to be statistically representative. Extraction/CPE accuracy on
selected cases also does not establish end-to-end CVE retrieval recall.

For the generated 100-record sample (seed `20261109`), the protocol distribution
is HTTP 52, SSH 25, FTP 22, and MongoDB 1. The M2-only sampling pass found 120
candidate identities across those records; 15 records had zero candidates, 53
had one, and 32 had multiple. These are predictions and sampling diagnostics,
not Gold identities. Raw source evidence references occur in 86 records. The
manifest marks product interpretation for human review in 85 records and
version interpretation in 86; vendor, update, and CPE part are absent from the
source evidence for all 100 sampled records. As a result, there are currently
zero Gold identities to send to the local CPE dictionary, so CPE Gold mapping
counts remain empty.

The available local dictionary was read-only inspected for provenance: schema
2.0, 1,804,614 entries, with NVD source timestamp `2026-11-04`. It was not used
to infer Gold identities or populate the annotation file.

Task 22's separate 400-record online assessment sample is not a substitute for
this independent Gold: its predictions were not used as labels. No raw records,
manifests, Gold annotations, assessment outputs, or local dictionary files are
tracked by Git.
