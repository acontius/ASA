"""Extract CPE-oriented software identities from scan JSONL logs.

Two modes:

* deterministic — use M2 protocol extractors (recommended baseline)
* llm — ask a local llama-server model for product/version/update
* both — run both and write side-by-side fields for comparison

Example::

    python -m app.agent.extract_cpe_cli \\
        --input Data/PartOfMe.json \\
        --output out/agent_cpe.jsonl \\
        --mode deterministic \\
        --limit 50

    python -m app.agent.extract_cpe_cli \\
        --input /tmp/openssh_sample.jsonl \\
        --output out/agent_cpe_llm.jsonl \\
        --mode both \\
        --server-url http://127.0.0.1:9931 \\
        --model-alias llama3.1 \\
        --limit 20
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from app.extractors import EXTRACTORS, extract_candidates
from app.ingestion.normalizer import normalize
from app.ingestion.reader import iter_jsonl_records


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m app.agent.extract_cpe_cli",
        description="Extract CPE-oriented identities from scan JSONL (deterministic and/or local LLM).",
    )
    p.add_argument("--input", required=True, help="Scan JSONL (PartOfMe-style)")
    p.add_argument("--output", required=True, help="JSONL output path (must not exist)")
    p.add_argument(
        "--mode",
        choices=("deterministic", "llm", "both"),
        default="deterministic",
        help="Extraction backend (default: deterministic)",
    )
    p.add_argument("--limit", type=int, default=0, help="Max records to process (0 = all)")
    p.add_argument("--server-url", default="http://127.0.0.1:9931", help="llama-server base URL")
    p.add_argument("--model-alias", default="llama3.1", help="Model alias on llama-server")
    p.add_argument("--timeout", type=float, default=60.0, help="LLM HTTP timeout seconds")
    return p


def _cpe_stub(product: str | None, version: str | None, update: str | None) -> str | None:
    if not product or not str(product).strip():
        return None
    prod = str(product).strip().lower().replace(" ", "_")
    ver = str(version).strip() if version else "*"
    upd = str(update).strip() if update else "*"
    return f"cpe:2.3:a:*:{prod}:{ver}:{upd}:*:*:*:*:*:*"


def _deterministic_identities(document: dict[str, Any], line_number: int) -> list[dict[str, Any]]:
    record = normalize(document, line_number=line_number, byte_offset=0)
    found = extract_candidates(record, EXTRACTORS)
    out: list[dict[str, Any]] = []
    for item in found:
        product = item.get("product_name")
        version = item.get("version")
        update = item.get("update")
        out.append(
            {
                "product": product,
                "version": version,
                "update": update,
                "source_path": item.get("source_path"),
                "evidence_strength": item.get("evidence_strength"),
                "raw_value": item.get("raw_value"),
                "extractor_id": item.get("extractor_id"),
                "cpe_stub": _cpe_stub(
                    product if isinstance(product, str) else None,
                    version if isinstance(version, str) else None,
                    update if isinstance(update, str) else None,
                ),
            }
        )
    return out


def _collect_banners(document: dict[str, Any]) -> list[str]:
    """Best-effort banner/software strings for LLM mode."""
    banners: list[str] = []
    source = document.get("_source")
    if not isinstance(source, dict):
        return banners
    for key, block in source.items():
        if not isinstance(key, str) or not isinstance(block, dict):
            continue
        if not (key.startswith("t") or key.startswith("u")):
            continue
        for proto, payload in block.items():
            if not isinstance(payload, dict):
                continue
            result = payload.get("result")
            if not isinstance(result, dict):
                continue
            if proto == "ssh":
                server_id = result.get("server_id")
                if isinstance(server_id, dict):
                    software = server_id.get("software")
                    if isinstance(software, str) and software.strip():
                        banners.append(software.strip())
            elif proto == "http":
                response = result.get("response")
                if isinstance(response, dict):
                    headers = response.get("headers")
                    if isinstance(headers, dict):
                        for hk, hv in headers.items():
                            if isinstance(hk, str) and hk.lower() == "server" and isinstance(hv, str):
                                banners.append(hv.strip())
            elif proto == "ftp":
                banner = result.get("banner")
                if isinstance(banner, str) and banner.strip():
                    banners.append(banner.strip())
    # dedupe preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for b in banners:
        if b not in seen:
            seen.add(b)
            unique.append(b)
    return unique


_LLM_PROMPT = (
    "Extract software identity from the banner. "
    "Reply with ONLY a single JSON object, no explanation, no markdown. "
    "Keys: product (string), version (string or null), update (string or null). "
    "Banner: {banner}"
)


def _llm_identity(
    banner: str,
    *,
    server_url: str,
    model_alias: str,
    timeout: float,
) -> tuple[dict[str, Any] | None, float, str | None]:
    body = {
        "model": model_alias,
        "messages": [{"role": "user", "content": _LLM_PROMPT.format(banner=banner)}],
        "temperature": 0,
        "max_tokens": 80,
        "stream": False,
    }
    data = json.dumps(body).encode("utf-8")
    url = server_url.rstrip("/") + "/v1/chat/completions"
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "Accept": "application/json"}
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return None, time.perf_counter() - t0, type(exc).__name__
    elapsed = time.perf_counter() - t0
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None, elapsed, "bad_envelope"
    if not isinstance(content, str):
        return None, elapsed, "empty_content"
    start, end = content.find("{"), content.rfind("}")
    if start < 0 or end <= start:
        return None, elapsed, "no_json"
    try:
        parsed = json.loads(content[start : end + 1])
    except json.JSONDecodeError:
        return None, elapsed, "json_decode"
    if not isinstance(parsed, dict):
        return None, elapsed, "not_object"
    product = parsed.get("product")
    version = parsed.get("version")
    update = parsed.get("update")
    return (
        {
            "product": product if isinstance(product, str) else None,
            "version": version if isinstance(version, str) else (None if version is None else str(version)),
            "update": update if isinstance(update, str) else (None if update is None else str(update)),
            "raw_value": banner,
            "cpe_stub": _cpe_stub(
                product if isinstance(product, str) else None,
                version if isinstance(version, str) else None,
                update if isinstance(update, str) else None,
            ),
            "latency_seconds": round(elapsed, 3),
        },
        elapsed,
        None,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    in_path = Path(args.input)
    out_path = Path(args.output)
    if not in_path.is_file():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 2
    if out_path.exists():
        print(f"error: output already exists: {args.output}", file=sys.stderr)
        return 2
    if args.limit < 0:
        print("error: --limit must be >= 0", file=sys.stderr)
        return 2

    stats = {
        "records": 0,
        "errors": 0,
        "deterministic_identities": 0,
        "llm_identities": 0,
        "llm_failures": 0,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("x", encoding="utf-8") as out:
        for item in iter_jsonl_records(str(in_path)):
            if args.limit and stats["records"] >= args.limit:
                break
            if item.document is None:
                if item.error:
                    stats["errors"] += 1
                    row = {
                        "record_id": None,
                        "line_number": item.line_number,
                        "error": item.error,
                        "deterministic": [],
                        "llm": [],
                    }
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
                continue
            stats["records"] += 1
            record_id = None
            source = item.document.get("_source")
            if isinstance(source, dict) and source.get("id") is not None:
                record_id = str(source.get("id"))
            row: dict[str, Any] = {
                "record_id": record_id,
                "line_number": item.line_number,
                "deterministic": [],
                "llm": [],
            }
            if args.mode in ("deterministic", "both"):
                try:
                    idents = _deterministic_identities(item.document, item.line_number)
                    row["deterministic"] = idents
                    stats["deterministic_identities"] += len(idents)
                except Exception as exc:  # keep stream alive
                    stats["errors"] += 1
                    row["deterministic_error"] = type(exc).__name__
            if args.mode in ("llm", "both"):
                for banner in _collect_banners(item.document):
                    ident, _, err = _llm_identity(
                        banner,
                        server_url=args.server_url,
                        model_alias=args.model_alias,
                        timeout=args.timeout,
                    )
                    if ident is not None:
                        row["llm"].append(ident)
                        stats["llm_identities"] += 1
                    else:
                        stats["llm_failures"] += 1
                        row["llm"].append({"raw_value": banner, "error": err})
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            out.flush()

    print(
        " ".join(f"{k}={v}" for k, v in stats.items()),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
