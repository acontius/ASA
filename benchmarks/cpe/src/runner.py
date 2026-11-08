"""CLI for preparing a local sample and running benchmark methods."""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
import platform
import resource
import sqlite3
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from benchmarks.cpe.src.dataset import iter_jsonl, load_reviewed_gold, sample
from benchmarks.cpe.src.deterministic import process
from benchmarks.cpe.src.llm_direct import call_local, validate_output
from benchmarks.cpe.src.agent import run_agent
from benchmarks.cpe.src.cpe_lookup import ReadOnlyCpeLookup
from benchmarks.cpe.src.metrics import evaluate
from app.cpe.parser import parse_cpe23
from app.cpe.resolver import resolve_candidate
from benchmarks.cpe.src.identity import compare_cpe_identity

BASE = ROOT / "benchmarks/cpe"

def serialize_result(row: dict) -> str:
    return json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _identity(candidate: dict) -> dict:
    return {field: candidate.get(field) for field in ("product_name", "vendor", "version", "update", "part")}


def cpe_identity_matches(cpe_name: str, identity: dict) -> bool:
    """Backward-compatible boolean wrapper for the shared benchmark comparator."""
    return compare_cpe_identity(cpe_name, identity)["valid"]


def _final_resolution(candidate: dict, resolution: dict, kind: str = "m3") -> dict:
    cpe_name = resolution.get("cpe_name")
    validation = compare_cpe_identity(cpe_name, _identity(candidate)) if cpe_name else {"valid": None, "fields": {}}
    return {
        "candidate_id": candidate.get("candidate_id"),
        "source_path": candidate.get("source_path"),
        "extracted_identity": _identity(candidate),
        "resolution_status": resolution.get("resolution_status"),
        "resolution_basis": resolution.get("resolution_basis"),
        "cpe23": cpe_name,
        "identity_valid": validation["valid"] if cpe_name else None,
        "identity_validation": validation["fields"],
        "resolution_kind": kind,
        "notes": resolution.get("notes"),
        **({"competing": resolution["competing"]} if resolution.get("competing") else {}),
    }


def _single_prediction(candidates: list[dict]) -> dict:
    """Compatibility alias only for singleton extraction; never aggregate candidates."""
    if len(candidates) == 1:
        return {**candidates[0], "cpe_candidates": [], "abstain": bool(candidates[0].get("abstain", False))}
    return {"product_name": None, "vendor": None, "version": None, "update": None, "part": None,
            "cpe_candidates": [], "evidence_paths": [], "abstain": not bool(candidates),
            "explanation": "multiple_extractions_preserved_without_aggregation" if candidates else "no_candidate"}


def _deterministic_contract(candidates: list[dict], resolutions: list[dict]) -> tuple[list[dict], list[dict]]:
    if candidates and not resolutions:
        resolutions = [{"candidate_id": c.get("candidate_id"), "resolution_status": "unavailable", "resolution_basis": "dictionary_unavailable", "notes": "local M3 dictionary was not available"} for c in candidates]
    if len(candidates) != len(resolutions):
        raise ValueError("each M2 candidate must have exactly one M3 resolution")
    extractions = [{**_identity(c), "candidate_id": c.get("candidate_id"), "source_path": c.get("source_path"), "evidence_paths": [c.get("source_path")] if c.get("source_path") else [], "abstain": False} for c in candidates]
    final_resolutions = [_final_resolution(c, r) for c, r in zip(candidates, resolutions, strict=True)]
    return extractions, final_resolutions


def _resolve_direct_identity(parsed: dict | None, record_id: str, db_path: Path) -> tuple[dict | None, dict | None]:
    if not parsed or parsed.get("abstain", False) or not parsed.get("product_name") or not db_path.exists():
        return None, None
    candidate = {
        "candidate_id": record_id,
        "normalized_record_id": record_id,
        "product_name": parsed["product_name"],
        "vendor": parsed.get("vendor"),
        "version": parsed.get("version"),
        "update": parsed.get("update"),
        "part": parsed.get("part"),
        "evidence_strength": "moderate" if parsed.get("evidence_paths") else "weak",
        "source_path": parsed["evidence_paths"][0] if parsed.get("evidence_paths") else None,
    }
    uri = db_path.resolve().as_uri() + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as m3_db:
        m3_db.row_factory = sqlite3.Row
        resolution = resolve_candidate(m3_db, candidate)
    return candidate, resolution


def config(): return json.loads((BASE / "config/benchmark.json").read_text())


def run(method: str, model: str | None = None, server_url: str | None = None):
    cfg = config(); sample_path = ROOT / cfg["sample"]
    if not sample_path.exists(): raise SystemExit("sample missing; run --prepare")
    rows = list(iter_jsonl(sample_path)); db_path = ROOT / cfg["dictionary_db"]
    lookup = ReadOnlyCpeLookup(str(db_path), str(ROOT / cfg["dictionary_chunks"]), cfg["max_tool_calls"])
    db = None
    if method == "deterministic" and db_path.exists():
        db = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        db.row_factory = sqlite3.Row
        meta = db.execute("SELECT schema_version FROM dictionary_metadata WHERE id=1").fetchone()
        if meta is None or meta["schema_version"] != "2.0":
            db.close()
            raise SystemExit("local CPE database is not an M3 schema 2.0 dictionary")
    output = []
    for index, (_, sample_row) in enumerate(rows, 1):
        lookup.calls = 0  # budget is per input record
        recid, raw = sample_row["record_id"], sample_row["raw"]
        base = {"record_id": recid, "method": method, "model": model, "protocol": sample_row.get("protocol"), "timestamp": time.time(), "hardware": hardware()}
        if method == "deterministic":
            started = time.perf_counter()
            try:
                result = process(raw, recid, index, db)
                candidates = result["outcome"]["candidates"]
                extractions, final_resolutions = _deterministic_contract(candidates, result["candidate_resolutions"])
                prediction = _single_prediction(extractions)
                base.update({"prediction": prediction, "extraction_prediction": prediction, "extraction_predictions": extractions, "final_cpe_resolutions": final_resolutions, "dictionary_cpes": [x["cpe23"] for x in final_resolutions if x.get("cpe23")], "evaluation_track": "extraction_only+end_to_end_cpe", "latency_seconds": time.perf_counter()-started, "schema_valid": True, "invalid_json": False, "status": "ok", "outcome": result["outcome"]["outcome"]})
            except Exception as exc: base.update({"prediction": None, "status": "error", "error": type(exc).__name__, "latency_seconds": time.perf_counter()-started})
        elif method == "llm":
            response = call_local(raw, model or "asa-local", server_url or cfg["server_url"], cfg["max_output_tokens"])
            parsed, parse_error, parsed_schema = validate_output(response.pop("raw_response", ""))
            invalid, schema = parse_error, parsed_schema
            resolution = None
            candidate = None
            ignored_model_cpes = []
            if parsed:
                ignored_model_cpes = list(parsed.get("cpe_candidates", []))
                parsed["cpe_candidates"] = []
                response["parsed"] = parsed
            # Shared M3 resolver; direct model output never receives dictionary candidates.
            candidate, resolution = _resolve_direct_identity(parsed, recid, db_path)
            gen_elapsed = max(0.0, response.get("latency_seconds", 0) - (response.get("ttft_seconds") or 0))
            gen_tokens = response.get("completion_tokens")
            extraction_prediction = {k: parsed.get(k) for k in ("product_name", "vendor", "version", "update", "part", "evidence_paths", "abstain", "explanation")} if parsed else None
            final_resolutions = [_final_resolution(candidate, resolution)] if candidate and resolution else []
            base.update(response); base.update({"evaluation_track": "extraction_only+end_to_end_cpe", "ignored_model_cpe_proposals": len(ignored_model_cpes), "extraction_prediction": extraction_prediction, "prediction": extraction_prediction, "extraction_predictions": [extraction_prediction] if extraction_prediction else [], "candidate_resolutions": [resolution] if resolution else [], "final_cpe_resolutions": final_resolutions, "dictionary_cpes": [x["cpe23"] for x in final_resolutions if x.get("cpe23")], "generation_tokens_per_second": gen_tokens/gen_elapsed if isinstance(gen_tokens, int) and gen_elapsed else None, "invalid_json": invalid == "invalid_json", "invalid_reason": invalid, "schema_valid": schema, "status": "error" if response.get("error") else "ok", "model_calls": 1, "tool_calls": 0})
        elif method == "agent":
            response = run_agent(raw, recid, model or "asa-local", lookup, server_url or cfg["server_url"], cfg["max_output_tokens"], cfg["max_model_calls"])
            parsed_agent = response.get("parsed")
            agent_cpes = parsed_agent.get("cpe_candidates", []) if isinstance(parsed_agent, dict) else []
            agent_identity = {k: parsed_agent.get(k) for k in ("product_name", "vendor", "version", "update", "part")} if isinstance(parsed_agent, dict) else {}
            agent_candidate = {"candidate_id": recid, "source_path": (parsed_agent.get("evidence_paths") or [None])[0] if isinstance(parsed_agent, dict) else None, **agent_identity}
            final_resolutions = [_final_resolution(agent_candidate, {"resolution_status": "agent_proposed", "cpe_name": name}) for name in agent_cpes]
            extraction_prediction = {**agent_identity, **{k: parsed_agent.get(k) for k in ("evidence_paths", "abstain", "explanation")}} if isinstance(parsed_agent, dict) else None
            base.update(response); base.update({"evaluation_track": "extraction_only+end_to_end_cpe", "prediction": extraction_prediction, "extraction_prediction": extraction_prediction, "extraction_predictions": [extraction_prediction] if extraction_prediction else [], "final_cpe_resolutions": final_resolutions, "dictionary_cpes": list(response.get("candidate_cpes", [])), "invalid_json": response.get("invalid_reason") == "invalid_json", "status": "error" if response.get("error") else "ok"})
        else: raise SystemExit(f"unknown method: {method}")
        if "dictionary_cpes" not in base: base["dictionary_cpes"] = base.get("candidate_cpes", [])
        output.append(base)
    if db: db.close()
    lookup.close()
    results_dir = BASE / "results"; results_dir.mkdir(exist_ok=True)
    filename = f"{method}-{model or 'none'}.jsonl"
    with (results_dir / filename).open("w", encoding="utf-8") as f:
        for row in output: f.write(serialize_result(row) + "\n")
    return output


def hardware():
    try:
        gpu = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total,memory.used", "--format=csv,noheader"], capture_output=True, text=True, timeout=3)
        gpu_info = gpu.stdout.strip() if gpu.returncode == 0 else None
    except (OSError, subprocess.SubprocessError): gpu_info = None
    return {"machine": platform.machine(), "platform": platform.platform(), "python": platform.python_version(), "gpu": gpu_info}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--method", choices=("deterministic", "llm", "agent"))
    parser.add_argument("--model")
    parser.add_argument("--server-url")
    parser.add_argument("--size", type=int)
    args = parser.parse_args(); cfg = config()
    if args.prepare:
        created = sample(ROOT / cfg["input"], ROOT / cfg["sample"], args.size or cfg["sample_size"], cfg["seed"])
        gold = BASE / "data/gold.jsonl"; gold.touch(exist_ok=True)
        parsed = sum(1 for _ in iter_jsonl(ROOT / cfg["input"]))
        physical = sum(1 for line in (ROOT / cfg["input"]).open(encoding="utf-8") if line.strip())
        protocols = sorted({r["protocol"] for r in created})
        outcomes = sorted({r["m2_outcome_stratum"] for r in created})
        print(json.dumps({"sample_records": len(created), "sample": str(ROOT / cfg["sample"]), "gold_ready": gold.stat().st_size > 0, "malformed_or_multiline_physical_lines_skipped": physical-parsed, "sample_protocols": protocols, "protocols_without_parseable_records": sorted(set(("ssh", "http", "ftp", "mongodb"))-set(protocols)), "m2_outcome_strata": outcomes}, indent=2)); return
    if not args.method: parser.error("choose --prepare or --method")
    run_start = time.perf_counter()
    rows = run(args.method, args.model, args.server_url)
    total_runtime = time.perf_counter() - run_start
    gold_lookup = ReadOnlyCpeLookup(str(ROOT / cfg["dictionary_db"]), str(ROOT / cfg["dictionary_chunks"]))
    gold, gold_errors = load_reviewed_gold(BASE / "data/gold.jsonl", gold_lookup) if (BASE / "data/gold.jsonl").exists() else ({}, [])
    gold_lookup.close()
    summary = evaluate(rows, gold)
    successful_latencies=[r.get("latency_seconds") for r in rows if r.get("status")=="ok" and isinstance(r.get("latency_seconds"),(int,float))]
    summary.update({"gold_label_errors": gold_errors, "method": args.method, "model": args.model or "N/A", "records": len(rows), "total_runtime_seconds": total_runtime, "throughput_records_per_second": len(rows)/total_runtime if total_runtime else None, "latency_mean": statistics.mean(successful_latencies) if successful_latencies else None, "latency_stdev": statistics.pstdev(successful_latencies) if len(successful_latencies)>1 else None, "latency_p50": percentile(successful_latencies, .5), "latency_p95": percentile(successful_latencies, .95), "peak_rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, "model_calls": sum(r.get("model_calls", 0) for r in rows), "tool_calls": sum(r.get("tool_calls", 0) for r in rows), "python": platform.python_version()})
    with (BASE / "results" / f"{args.method}-{args.model or 'none'}.summary.json").open("w") as f: json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


def percentile(values, q):
    values = sorted(v for v in values if isinstance(v, (int, float)))
    return values[min(len(values)-1, round((len(values)-1)*q))] if values else None


if __name__ == "__main__": main()
