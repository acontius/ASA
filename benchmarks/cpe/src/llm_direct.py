"""Strict local llama.cpp chat-completions client for direct extraction."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
from app.cpe.parser import parse_cpe23

FIELDS = {"product_name", "vendor", "version", "update", "part", "cpe_candidates", "evidence_paths", "abstain", "explanation"}
SYSTEM = '''Extract software identity from the provided raw JSON record. Return one strict JSON object with exactly: product_name, vendor, version, update, part, cpe_candidates, evidence_paths, abstain, explanation. Use null for unknown fields; cpe_candidates must be an empty list because this is extraction-only. Distinguish protocol versions (for example SSH protocol 2.0) from software versions. Do not propose or invent a CPE. Evidence paths must be JSON paths into the input.'''


def validate_output(text: str, allowed_cpes: set[str] | None = None) -> tuple[dict | None, str | None, bool]:
    try:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result: raise ValueError("duplicate JSON key")
                result[key] = value
            return result
        obj = json.loads(text, object_pairs_hook=unique_object)
    except (ValueError, TypeError):
        return None, "invalid_json", False
    if not isinstance(obj, dict) or set(obj) != FIELDS:
        return obj if isinstance(obj, dict) else None, "schema_fields", False
    if not isinstance(obj["cpe_candidates"], list) or not isinstance(obj["evidence_paths"], list) or not isinstance(obj["abstain"], bool) or not isinstance(obj["explanation"], str):
        return obj, "schema_types", False
    for key in ("product_name", "vendor", "version", "update", "part"):
        if obj[key] is not None and not isinstance(obj[key], str): return obj, "schema_types", False
    if any(not isinstance(x, str) for x in obj["cpe_candidates"] + obj["evidence_paths"]): return obj, "schema_types", False
    rejected = []
    for name in obj["cpe_candidates"]:
        try: parse_cpe23(name)
        except (ValueError, TypeError): rejected.append(name)
        else:
            if allowed_cpes is not None and name not in allowed_cpes: rejected.append(name)
    if rejected:
        obj["rejected_cpes"] = rejected
        obj["cpe_candidates"] = []
        obj["abstain"] = True
        return obj, "hallucinated_cpe_rejected", True
    return obj, None, True


def call_local(raw: dict, model: str, server_url: str = "http://127.0.0.1:8080/v1/chat/completions", max_tokens: int = 512, extra_context: str = "") -> dict:
    parsed_url = urlparse(server_url)
    if parsed_url.scheme != "http" or parsed_url.hostname not in {"127.0.0.1", "::1"} or parsed_url.username or parsed_url.password:
        return {"raw_response": "", "parsed": None, "invalid_reason": None, "schema_valid": False, "latency_seconds": 0.0, "ttft_seconds": None, "prompt_tokens": None, "completion_tokens": None, "error": "non_loopback_server_rejected"}
    prompt = SYSTEM + ("\n" + extra_context if extra_context else "") + "\nRAW RECORD:\n" + json.dumps(raw, ensure_ascii=False)
    body = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0, "max_tokens": max_tokens, "stream": True, "stream_options": {"include_usage": True}}
    request = urllib.request.Request(server_url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    start = time.perf_counter(); first = None; pieces = []; usage = {}; error = None
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(request, timeout=300) as response:
            for line in response:
                if not line.startswith(b"data:"): continue
                data = line[5:].strip()
                if data == b"[DONE]": break
                try: event = json.loads(data)
                except ValueError: continue
                if "usage" in event: usage = event["usage"]
                choices = event.get("choices", [])
                if choices:
                    content = choices[0].get("delta", {}).get("content", "")
                    if content:
                        first = first or time.perf_counter(); pieces.append(content)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        error = type(exc).__name__
    latency = time.perf_counter() - start
    text = "".join(pieces)
    parsed, validation_error, valid = validate_output(text)
    return {"raw_response": text, "parsed": parsed, "invalid_reason": validation_error, "schema_valid": valid, "latency_seconds": latency, "ttft_seconds": first-start if first else None, "prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"), "error": error}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
