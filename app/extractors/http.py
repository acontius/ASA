"""HTTP/HTTPS identification from response Server headers.

A bare product name, CDN, or WAF token without a version is weak evidence.
Certificate fields are not treated as product proof.
"""

from __future__ import annotations

import re

from schemas.models import ExtractionCandidate, NormalizedRecord, PortBlock

from app.extractors.base import block_path, candidate, result_of, split_product_version

EXTRACTOR_ID = "http.server_header.v1"

# Tokens that are not a software product even when present.
_GENERIC = {
    "waf",
    "web",
    "webserver",
    "webs",
    "cloudflare",
    "arvancloud",
    "sotoon cdn",
    "akamai",
    "cdn",
}

_SERVER_RE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9._+-]*?)[/ _](?P<ver>\d+(?:\.\d+)+(?:p\d+)?)"
)


def extract_http(record: NormalizedRecord, block: PortBlock) -> list[ExtractionCandidate]:
    result = result_of(block)
    found: list[ExtractionCandidate] = []
    response = result.get("response")
    if isinstance(response, dict):
        item = _from_headers(
            record,
            block,
            response.get("headers"),
            block_path(block, "result", "response", "headers", "server"),
        )
        if item:
            found.append(item)
    if not any(item["evidence_strength"] != "weak" for item in found):
        chain = result.get("redirect_response_chain")
        if isinstance(chain, list):
            for index, hop in enumerate(chain):
                if not isinstance(hop, dict):
                    continue
                headers = hop.get("headers")
                if headers is None and isinstance(hop.get("response"), dict):
                    headers = hop["response"].get("headers")
                item = _from_headers(
                    record,
                    block,
                    headers,
                    block_path(
                        block, "result", "redirect_response_chain", str(index), "headers", "server"
                    ),
                )
                if item is None:
                    continue
                if item["evidence_strength"] != "weak":
                    found.append(item)
                    break
                if not found:
                    found.append(item)
    return found



def _header_server(headers: object) -> str | None:
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == "server":
            if isinstance(value, list) and value:
                value = value[0]
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _from_headers(
    record: NormalizedRecord,
    block: PortBlock,
    headers: object,
    source_path: str,
) -> ExtractionCandidate | None:
    raw = _header_server(headers)
    if not raw:
        return None
    token = raw.split(" ")[0]
    parsed = split_product_version(token) or _loose(raw)
    if parsed is None:
        strength = "weak"
        product = raw
        version = None
    else:
        product, version = parsed
        if product.lower() in _GENERIC or raw.lower() in _GENERIC:
            strength = "weak"
            version = None
        else:
            strength = "strong" if version.count(".") >= 1 or "p" in version else "moderate"
    if product.lower() in _GENERIC or raw.lower() in _GENERIC:
        strength = "weak"
        version = None
        product = raw
    return candidate(
        record,
        product_name=product,
        version=version,
        raw_value=raw,
        source_path=source_path,
        signal_type="header",
        extractor_id=EXTRACTOR_ID,
        evidence_strength=strength,
        evidence_refs=["headers.server"],
    )


def _loose(raw: str) -> tuple[str, str] | None:
    match = _SERVER_RE.search(raw)
    if not match:
        return None
    return match.group("name"), match.group("ver")
