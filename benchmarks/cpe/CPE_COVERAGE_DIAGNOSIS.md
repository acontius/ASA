# CPE Coverage Diagnosis — 400-Record Pilot Sample

## Method

The diagnosis reuses the two local, non-overlapping Task 22 source samples: 100 records (seed `20261109`) and 300 records (seed `20261110`), for 400 of the 1,617 records. The same files were processed before and after the changes with the online assessment pipeline. Raw scan records, sample files, assessment outputs, credentials, IPs and record IDs are not included here or in Git.

The trace compared M2 identity fields and evidence paths with the exact NVD API query attempts, response counts, returned CPE components, rejected fields, and final status. Ten separate, bounded diagnostic keyword/structured queries were sent to the official NVD CPE API; their results are called out below. The source remains a passive, incomplete inventory.

## Findings

### 1. OpenSSH release suffix did not match NVD's version/update split

There were 126 OpenSSH identities in the sample. M2 correctly extracted versions such as `8.9p1` from SSH server software evidence at `t22.ssh.result.server_id.software`. NVD stores those CPE components as `version=8.9`, `update=p1`. The old exact query asked for version `8.9p1` and returned zero; version-relaxed search returned OpenSSH CPEs, but validation compared only the CPE update against an absent source update and rejected it.

For 115 cases (`8.9p1`: 59, `9.6p1`: 55, `9.2p1`: 1), the returned NVD data contained the matching split CPE. A direct official API query for `cpe:2.3:*:*:openssh:8.9:p1:*:*:*:*:*:*` returned one active record: `cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*`. The same direct query for version `8.2:p1` returned zero; no mapping was added for that version.

The lookup now decomposes only the recognized OpenSSH `pN` release suffix in its temporary CPE query identity. The original M2 identity is unchanged and the decomposition is recorded in provenance. This recovers a verifiable CPE candidate, but does **not** make the result exact when source evidence omits vendor and part.

### 2. Source identities do not establish vendor or CPE part

The shared M2 candidate constructor sets `vendor` and `part` to `null`; the protocol extractors do not independently populate them. Consequently, a unique NVD result generally supplies these identity-defining fields. The established resolver correctly marks such results `review_required` rather than `exact_match`. Before this task, 18 unique active CPEs already had that status. The OpenSSH normalization adds 115 more candidates to this status; it must not enable automatic CVE retrieval.

Representative source identities include `nginx/1.25.3`, `lighttpd/1.4.39`, `RomPager/4.07`, and `mini_httpd/1.19` from HTTP Server headers. NVD returns one compatible active CPE for these examples, but vendor and part were not observed in the source. No production validation rule was relaxed.

### 3. Generic HTTP server labels were extracted as products

Seventeen versioned HTTP identities, `Web/0.9` and `WebServer 1.0`/`1.1`, reached NVD as moderate/strong product candidates but produced no defensible CPE. These are generic server labels, not software product identities. The HTTP extractor now classifies the exact generic tokens `web` and `webserver` as weak; they are not sent to NVD. Their original raw value remains available in local results, but is not committed.

### 4. Source labels that do not identify a dictionary product

The 31 complete `no_match` cases included:

- 12 `Microsoft-HTTPAPI` 2.0 identities: structured product/version lookup returned zero. Diagnostic keyword searches for `Microsoft-HTTPAPI` and `HTTPAPI` also returned zero.
- 10 `Microsoft-IIS` identities: the source label does not match NVD's product component. An official keyword search for `IIS` returned 56 candidates; the directly checked `microsoft:internet_information_server:10.0` CPE was deprecated. No active exact mapping was introduced.
- 8 generic SSH labels (`SSHDaemon` and `ROSSSH`) without a product version; neither structured nor keyword lookup returned a CPE. They were not aliased to OpenSSH.
- 1 `Apache-Coyote 1.1` identity without a compatible returned CPE.

These cases need better source identification or human review; a product-name guess would not be safe.

### 5. Correct rejections and incomplete retrieval

- Two MikroTik candidates returned Checkmk-specific CPEs with concrete `target_sw=checkmk`. They remain rejected as incompatible with the observed device identity.
- Seven exact dictionary entries were deprecated and remain `deprecated_only`.
- One D-Link FTP identity had no structured result; keyword discovery reported 743 results but only 400 were fetched under the configured page cap. It remains `incomplete_lookup`, and that record is marked `partial_error`; it was not converted to `no_match`.
- 102 weak candidates are skipped by policy after the 17 generic HTTP labels were reclassified. The remaining 85 are unchanged and do not trigger NVD requests.

## Before / after

| Measure | Before | After |
|---|---:|---:|
| Source records | 400 | 400 |
| Processed / partial error | 399 / 1 | 399 / 1 |
| `exact_match` | 0 | 0 |
| `review_required` | 18 | 133 |
| `no_match` | 183 | 51 |
| `skipped_weak` | 85 | 102 |
| `deprecated_only` | 7 | 7 |
| `incomplete_lookup` | 1 | 1 |
| CPE API requests | 81 | 72 |
| CVE API requests | 0 | 0 |
| Retrieved CVEs / applicability cases | 0 / 0 | 0 / 0 |

The 115 status changes are `no_match → review_required` after validating NVD's version/update representation. The 17 weak-status increases are the generic HTTP labels no longer treated as software. Nine fewer CPE requests were made. This is a resolution-quality correction, not an accuracy result or evidence of vulnerability coverage.

## Remaining blocker

There are still zero source-supported exact CPEs in this sample. The CPE API has more usable candidates after normalization, but the source records do not establish vendor and part. The online CVE stage correctly requires an exact active versioned CPE, so it made zero CVE requests. To produce applicability Gold cases, provide source evidence or an independently reviewed inventory that establishes those identity components, or select a data source with such evidence. Do not auto-promote the NVD-supplied vendor/part fields.
