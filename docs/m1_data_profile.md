# M1 Data Profile — Agentic Vulnerability Scanner (ASA)

**Date:** 2026-11-01  
**Dataset:** `Data/PartOfMe.json` (14.1 MiB, 1 618 records)  
**Profiling method:** Full sequential parse of the JSONL file (no sampling required; entire sample fits in memory).  
**Primary source of truth:** Observed records in the repository. Secondary source: `Data/structure.md` (evaluated below).

## 1. Input Format

| Property | Observation |
|----------|-------------|
| Encoding | UTF-8 JSON Lines (JSONL). One complete JSON object per line. |
| Record count | 1 618 |
| Top-level shape | Elasticsearch-style document: `_index`, `_type`, `_id`, `_score`, `_source` |
| Working payload | Always under `_source` |
| Line boundaries | Strict newline-delimited; no multi-line records observed. |

Malformed lines were not present in this sample.

## 2. Envelope Fields (always present in this sample)

| Field | Type | Notes |
|-------|------|-------|
| `ip` | string | Target IP (redacted in fixtures). |
| `scanTime` | string | Unix epoch as decimal string **or** ISO-8601 with offset. Both forms appear. Prefer this over `timestamp` for scan time. |
| `timestamp` | string | ISO-8601; appears to be a later merge / processing time. Do **not** replace `scanTime`. |
| `@timestamp` | string | Logstash-style ingestion timestamp. |
| `proto` | string | Declared protocol (`ssh`, `http`, `ftp`, `mongodb`, …). |
| `port` | string | Primary port key (`t22`, `t80`, `t443`, `t21`, `t27017`, …). |
| `appId` | string | Wrapper / scanner identity: `pub-zgrab2` (1 579) or `pub-tgrab` (39). |
| `jid` | string | Job identifier. |
| `path` | string | Original filename path containing appId, pr, port, proto, wip, jid, scanTime. |
| `wip` | string | Always `"local"` in this sample. |
| `nPr` | string | Always `"0"`. |
| `host` | string | Container / worker host id (present on most records). |
| `id` | integer | Numeric document id. |
| `tags` | array | Frequently `["_dateparsefailure"]` (1 581 / 1 618). |

## 3. Port Blocks (`t<number>` / `u<number>`)

- 1 554 records contain exactly one `t*` / `u*` block.
- 60 records contain two blocks.
- 4 records contain three blocks.
- The top-level `port` / `proto` fields indicate the *primary* scan target; additional blocks are secondary (commonly an HTTP probe on port 80 or 443).
- Contracts and extractors **must** iterate over every `t*` / `u*` key whose name matches `^[tu]\d+$`.

## 4. Wrapper Differences

| appId | Count | Characteristics |
|-------|-------|-----------------|
| `pub-zgrab2` | 1 579 | Nested under `tNN.<proto>` with rich `result` objects (SSH `server_id`, HTTP `response`, etc.). |
| `pub-tgrab` | 39 | Used for FTP, MongoDB, Winbox, PPTP, RTSP, DNS, L2TP. Structure is flatter; `result` often contains `banner` or `build_info` directly. |

Structures are **not** identical across wrappers; protocol-specific extractors must be aware of the originating `appId`.

## 5. Supported Protocol Structures (MVP)

### SSH (`pub-zgrab2`, port `t22`)
Primary signal path:  
`_source.t22.ssh.result.server_id.software` → e.g. `"OpenSSH_9.6p1"`  
Secondary: `.comment` (OS hint), `.raw` (full banner), `.version` (SSH protocol version — **not** product version).

Observed software values (top): OpenSSH_8.9p1, OpenSSH_9.6p1, SSHDaemon, ROSSSH, dropbear_…

### HTTP / HTTPS (`pub-zgrab2`, ports `t80` / `t443`)
Primary signal:  
`_source.tNN.http.result.response.headers.server` (or `Server`)  
May contain product + version or only a product name / CDN / WAF string.  
TLS evidence may appear under `result.response.request.tls_log` or certificate fields; treat as corroboration only.  
Redirect chains exist under `redirect_response_chain` on some records (not exhaustively counted).

### FTP (`pub-tgrab`, port `t21`)
Primary signal:  
`_source.t21.ftp.result.banner`  
Typical forms: `"220 … FTP server (MikroTik 6.49.18) ready"`, `"220 (vsFTPd 3.0.5)"`, TP-LINK / D-Link generic banners.

### MongoDB (`pub-tgrab`, port `t27017`)
Primary signal:  
`_source.t27017.mongodb.result.build_info.version` / `versionArray`  
OS hint: `build_info.buildEnvironment.target_os`.

## 6. Data-Quality Observations

- 1 581 / 1 618 records carry `_dateparsefailure` tag → date parsing is unreliable; always prefer the explicit `scanTime` string.
- Many HTTP Server headers are generic (`WAF`, `Webs`, `nginx` without version) → weak evidence.
- FTP banners frequently embed device firmware (MikroTik RouterOS) rather than a pure FTP daemon version.
- Protocol version vs product version confusion is real for SSH (`server_id.version` is protocol).
- Unsupported protocols present: winbox, pptp, dns, l2tp, rtsp (out of MVP scope).
- No records were missing the core envelope fields in this sample.

## 7. Evaluation of `Data/structure.md`

| Claim | Status |
|-------|--------|
| Static envelope fields listed | **Supported** (and expanded by observation). |
| `path` composition | **Supported**. |
| `wip` always local | **Supported** in this sample. |
| SSH `result.server_id.software` primary | **Supported**. |
| FTP banner extraction | **Supported**. |
| HTTP Server header | **Supported** (with noted weakness). |
| MongoDB `build_info.version` | **Supported**. |
| CPE field list & “fill only 3-7” | **Useful design suggestion**; consistent with project constraints. |
| `part` must be assigned by us | **Consistent** with brief. |
| Questions about `pr`/`nPr` | Unresolved; not blocking M1. |
| “443 outputs as http not https” | **Observed** — `proto` stays `"http"` even for `t443`. |

**Precedence:** Observed dataset > project brief constraints > claims in `structure.md`.

## 8. Profiling Reproducibility

```bash
# Count records
wc -l Data/PartOfMe.json

# Basic profile (Python 3 stdlib)
python3 -c '
import json, collections
from pathlib import Path
recs = [json.loads(l) for l in Path("Data/PartOfMe.json").open()]
print(len(recs))
# … further counters as in this document
'
```

No external services or LLMs were used. Raw IPs and geo-meta were not transmitted.
