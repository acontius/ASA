# M1 Input / Output Contracts

These contracts are derived from the observed JSONL dataset and the project constraints.  
They are intentionally minimal and suitable for M2 streaming extraction.

## 1. Input Record Contract

**Encoding:** UTF-8 JSON Lines (one JSON object per line).  
**Boundary:** Newline (`\n`). Incomplete final line → processing_error.

### Required top-level fields
- `_source` (object)

### Required `_source` fields
| Field | Type | Notes |
|-------|------|-------|
| `ip` | string | Target address |
| `scanTime` | string | Preferred scan time (epoch-seconds string **or** ISO-8601) |
| `proto` | string | Declared primary protocol |
| `port` | string | Primary port key (`tNN` / `uNN`) |
| `appId` | string | `pub-zgrab2` \| `pub-tgrab` \| other |
| `path` | string | Provenance path |

### Optional / conditionally present
- `timestamp`, `@timestamp`, `jid`, `wip`, `nPr`, `host`, `id`, `tags`, `meta`
- Any number of `t<digits>` / `u<digits>` blocks (0-N). All must be examined.

### Malformed handling
- Missing `_source` or required fields → emit `processing_error` outcome, retain original line offset for provenance.
- Non-object after JSON parse → same.

### Multi-port rule
Iterate every key matching `^[tu]\d+$`. The top-level `proto`/`port` are advisory only.

## 2. Normalized Record Contract

A stable intermediate form produced by the ingestion layer before protocol-specific extraction.

```json
{
  "record_id": "string (hash or original _id)",
  "source_path": "string (original path or line offset)",
  "ip": "string",
  "scan_time": "string (canonicalized from scanTime)",
  "merge_time": "string|null (from timestamp if distinct)",
  "app_id": "string",
  "declared_proto": "string",
  "declared_port": "string",
  "port_blocks": [
    {
      "port_key": "t22",
      "protocol": "ssh",
      "raw_block": { "... truncated or referenced ..." },
      "status": "success|error|..."
    }
  ],
  "provenance": {
    "original_line": "integer|null",
    "jid": "string|null",
    "host": "string|null"
  }
}
```

- Large nested payloads should be referenced by offset or stored out-of-band; do not duplicate multi-megabyte banners into every candidate.
- `scan_time` must never be silently overwritten by `merge_time`.

## 3. Extraction Candidate Contract

Minimal unit handed to later CPE resolution.

```json
{
  "candidate_id": "string",
  "product_name": "string",
  "vendor": "string|null",
  "version": "string|null",
  "update": "string|null",
  "part": "a|o|h|null",
  "source_path": "string (JSONPath-like, e.g. t22.ssh.result.server_id.software)",
  "raw_value": "string",
  "signal_type": "banner|header|build_info|certificate|comment|other",
  "extractor_id": "string (e.g. ssh.server_id.v1)",
  "evidence_strength": "strong|moderate|weak",
  "evidence_refs": ["string"],
  "normalized_record_id": "string"
}
```

### Field rules
- `product_name` and `raw_value` are required for a candidate to be emitted.
- `vendor` and `part` remain null until a later resolution step (local NVD dictionary). Never guess.
- `evidence_strength` is qualitative for M1/M2; numeric confidence is deferred and must be calibrated.
- One input record may produce zero or more candidates (one per distinct signal).

## 4. Processing Outcome Contract

```json
{
  "outcome": "matched|ambiguous|no_match|insufficient_evidence|processing_error|unsupported_protocol",
  "record_id": "string",
  "candidates": [ /* ExtractionCandidate */ ],
  "notes": "string|null",
  "error": "string|null"
}
```

| Outcome | When |
|---------|------|
| `matched` | ≥1 candidate with strong/moderate evidence that can proceed to CPE lookup |
| `ambiguous` | Multiple conflicting candidates of similar strength |
| `no_match` | Record parsed, supported protocol, but no identification signal found |
| `insufficient_evidence` | Only weak signals (generic CDN, certificate CN alone, etc.) |
| `processing_error` | JSON parse failure, missing required fields, unexpected schema |
| `unsupported_protocol` | Protocol outside MVP scope (winbox, pptp, …) |

Do not conflate “no useful banner” with a processing failure.

## 5. CPE Boundary

- M1/M2 only extract product/version **evidence**.
- CPE 2.3 construction and validation happen in a later milestone using a local NVD CPE dictionary.
- Vendor strings and `part` values are **not** invented from banners.
- Certificate organization / CN fields are corroborating evidence only.

## 6. Formal Representation (lightweight)

Python 3.10+ TypedDicts / dataclasses are preferred over heavy schema libraries for the MVP.  
JSON Schema drafts may be added later for external validation; they are not required for M1 tests.
