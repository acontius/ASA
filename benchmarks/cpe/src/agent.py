"""Single-round bounded tool-assisted local extraction agent."""
from __future__ import annotations

import json
import time
from benchmarks.cpe.src.cpe_lookup import ReadOnlyCpeLookup
from benchmarks.cpe.src.llm_direct import AGENT_FINAL_SYSTEM, call_local, validate_output


def run_agent(raw: dict, record_id: str, model: str, lookup: ReadOnlyCpeLookup, server_url: str, max_tokens: int = 512, max_model_calls: int = 2) -> dict:
    agent_start = time.perf_counter()
    # First bounded model call extracts product/version. No tools are executable by the model.
    first = call_local(raw, model, server_url, max_tokens, "Extract product/vendor/version/update/part and evidence paths from this record. Set cpe_candidates to []. Set abstain=true only if no usable identity is supported; otherwise set it to false. Do not output anything except the required JSON object.")
    first_parsed, first_error, first_valid = validate_output(first.pop("raw_response", ""), raw_record=raw)
    first.update({"parsed": first_parsed, "invalid_reason": first_error, "schema_valid": first_valid})
    if not first.get("schema_valid") or not first.get("parsed"):
        first.update({"extraction_parsed": first.get("parsed"), "cpe_abstain": True, "model_calls": 1, "tool_calls": 0, "agent_total_seconds": time.perf_counter()-agent_start}); return first
    p = first["parsed"]
    if p.get("abstain"):
        p["cpe_candidates"] = []
        first.update({"parsed": p, "extraction_parsed": p, "cpe_abstain": True, "candidate_cpes": [], "model_calls": 1, "tool_calls": 0, "agent_total_seconds": time.perf_counter()-agent_start})
        return first
    candidates = lookup.lookup(p["product_name"], p.get("version"), p.get("vendor"))
    if max_model_calls < 2 or not candidates:
        p["cpe_candidates"] = []
        first.update({"parsed": p, "extraction_parsed": p, "cpe_abstain": True, "candidate_cpes": [], "model_calls": 1, "tool_calls": 1, "candidate_count": len(candidates), "agent_total_seconds": time.perf_counter()-agent_start}); return first
    prompt_context = "LOCAL DICTIONARY CANDIDATES (select only one or more exact cpe_name values below):\n" + json.dumps(candidates, ensure_ascii=False)
    final = call_local(raw, model, server_url, max_tokens, prompt_context, system_prompt=AGENT_FINAL_SYSTEM)
    allowed = {c["cpe_name"] for c in candidates}
    parsed, invalid, schema = validate_output(final.pop("raw_response", ""), allowed, raw_record=raw)
    cpe_abstain = bool(not parsed or parsed.get("abstain"))
    selected = None
    if parsed:
        # The extraction track belongs to the first call. The second call
        # selects only CPEs, so it cannot revise the scored identity.
        selected = {**parsed, **{key: p.get(key) for key in ("product_name", "vendor", "version", "update", "part", "evidence_paths")},
                    "cpe_candidates": [] if cpe_abstain else parsed["cpe_candidates"], "abstain": p["abstain"]}
    # Aggregate usage across both bounded model calls. Unknown usage stays None
    # instead of implying that the reported total is complete.
    for key in ("prompt_tokens", "completion_tokens"):
        values = (first.get(key), final.get(key))
        final[key] = sum(values) if all(isinstance(value, int) and not isinstance(value, bool) for value in values) else None
    first_latency, final_latency = first.get("latency_seconds"), final.get("latency_seconds")
    final["latency_seconds"] = first_latency + final_latency if isinstance(first_latency, (int, float)) and isinstance(final_latency, (int, float)) else None
    final.update({"first_call_latency_seconds": first_latency, "final_call_latency_seconds": final_latency,
                  "ttft_seconds": first.get("ttft_seconds"), "parsed": selected, "extraction_parsed": p,
                  "cpe_abstain": cpe_abstain, "invalid_reason": invalid,
                  "schema_valid": schema, "candidate_count": len(candidates), "candidate_cpes": sorted(allowed),
                  "model_calls": 2, "tool_calls": 1, "agent_total_seconds": time.perf_counter()-agent_start})
    return final
