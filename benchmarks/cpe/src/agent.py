"""Single-round bounded tool-assisted local extraction agent."""
from __future__ import annotations

import json
import time
from benchmarks.cpe.src.cpe_lookup import ReadOnlyCpeLookup
from benchmarks.cpe.src.llm_direct import call_local, validate_output


def run_agent(raw: dict, record_id: str, model: str, lookup: ReadOnlyCpeLookup, server_url: str, max_tokens: int = 512, max_model_calls: int = 2) -> dict:
    agent_start = time.perf_counter()
    # First bounded model call extracts product/version. No tools are executable by the model.
    first = call_local(raw, model, server_url, max_tokens, "First identify product/vendor/version and evidence paths. Set cpe_candidates to [] and abstain=true. Do not output anything except JSON.")
    if not first.get("schema_valid") or not first.get("parsed"):
        first.update({"model_calls": 1, "tool_calls": 0, "agent_total_seconds": time.perf_counter()-agent_start}); return first
    p = first["parsed"]
    candidates = lookup.lookup(p.get("product_name") or "", p.get("version"), p.get("vendor")) if p.get("product_name") else []
    if max_model_calls < 2 or not candidates:
        p["cpe_candidates"] = []
        p["abstain"] = True
        first.update({"parsed": p, "candidate_cpes": [], "model_calls": 1, "tool_calls": 1 if p.get("product_name") else 0, "agent_total_seconds": time.perf_counter()-agent_start}); return first
    prompt_context = "LOCAL DICTIONARY CANDIDATES (select only one or more exact cpe_name values below):\n" + json.dumps(candidates, ensure_ascii=False)
    final = call_local(raw, model, server_url, max_tokens, prompt_context + "\nSelect only returned CPE names. If the evidence does not support one, abstain.")
    allowed = {c["cpe_name"] for c in candidates}
    parsed, invalid, schema = validate_output(final.pop("raw_response", ""), allowed)
    final.update({"parsed": parsed, "invalid_reason": invalid, "schema_valid": schema, "candidate_count": len(candidates), "candidate_cpes": sorted(allowed), "model_calls": 2, "tool_calls": 1, "agent_total_seconds": time.perf_counter()-agent_start})
    return final
