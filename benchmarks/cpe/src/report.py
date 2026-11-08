"""Aggregate raw per-record JSONL into CSV and Markdown comparison files."""
from __future__ import annotations
import csv, json
from pathlib import Path
from benchmarks.cpe.src.runner import BASE, percentile
from benchmarks.cpe.src.dataset import iter_jsonl, load_reviewed_gold
from benchmarks.cpe.src.cpe_lookup import ReadOnlyCpeLookup
from benchmarks.cpe.src.metrics import evaluate

FIELDS = ["Method", "Model", "End-to-end Exact CPE Accuracy", "Extraction Product F1", "Extraction Version F1", "Extraction Component F1", "End-to-end Hallucination Rate", "Extraction Coverage", "Extraction Abstentions", "Missing Product", "Missing Vendor", "Missing Version", "Missing Update", "Missing Part", "Latency p50", "Latency p95", "Generation tok/s", "Peak RAM", "Peak VRAM"]

def main():
    cfg=json.loads((BASE/"config/benchmark.json").read_text())
    gold_db=BASE.parents[1]/cfg["dictionary_db"]
    lookup=ReadOnlyCpeLookup(str(gold_db),str(BASE.parents[1]/cfg["dictionary_chunks"]))
    gold, gold_errors=load_reviewed_gold(BASE/"data/gold.jsonl",lookup) if (BASE/"data/gold.jsonl").exists() else ({},[])
    lookup.close()
    summaries=[]
    for path in sorted((BASE/"results").glob("*.jsonl")):
        rows=[r for _,r in iter_jsonl(path)]
        if not rows: continue
        m=evaluate(rows,gold)
        latency=[(r.get("agent_total_seconds") if rows[0].get("method")=="agent" else r.get("latency_seconds")) for r in rows if r.get("status")=="ok"]
        model=rows[0].get("model") or "N/A"
        perf_path=BASE/"results"/(path.stem+".summary.json")
        perf=json.loads(perf_path.read_text()) if perf_path.exists() else {}
        tok=[r.get("generation_tokens_per_second") for r in rows if isinstance(r.get("generation_tokens_per_second"),(int,float))]
        ram=(perf.get("peak_rss_kb")/1024) if rows[0].get("method")=="deterministic" and perf.get("peak_rss_kb") else None
        summaries.append({"Method":rows[0].get("method"),"Model":model,"End-to-end Exact CPE Accuracy":m["evaluation_tracks"]["end_to_end_cpe"]["exact_cpe_accuracy"],"Extraction Product F1":m["product_name_metrics"]["f1"],"Extraction Version F1":m["version_metrics"]["f1"],"Extraction Component F1":m["component_micro"]["f1"],"End-to-end Hallucination Rate":m["hallucinated_cpe_rate"],"Extraction Coverage":m["coverage"],"Latency p50":percentile(latency,.5),"Latency p95":percentile(latency,.95),"Generation tok/s":percentile(tok,.5),"Peak RAM":ram,"Peak VRAM":None,"per_protocol":{p:evaluate([r for r in rows if r.get("protocol")==p],gold) for p in sorted({r.get("protocol") for r in rows})},"performance":{"latency_mean_seconds":perf.get("latency_mean"),"latency_stdev_seconds":perf.get("latency_stdev"),"total_runtime_seconds":perf.get("total_runtime_seconds"),"throughput_records_per_second":perf.get("throughput_records_per_second"),"agent_total_seconds_mean":sum(r.get("agent_total_seconds",0) for r in rows if r.get("agent_total_seconds") is not None)/max(1,sum(r.get("agent_total_seconds") is not None for r in rows)),"agent_model_calls":perf.get("model_calls"),"agent_tool_calls":perf.get("tool_calls"),"peak_process_rss_kb":perf.get("peak_rss_kb")},"failures":[{"record_id":r.get("record_id"),"status":r.get("status"),"error":r.get("error"),"invalid_reason":r.get("invalid_reason")} for r in rows if r.get("status")!="ok" or r.get("invalid_reason")]})
        missing_fields=m["evaluation_tracks"]["extraction_only"]["missing_identity_fields"]
        summaries[-1].update({"Extraction Abstentions":m["evaluation_tracks"]["extraction_only"]["abstentions"],"Missing Product":missing_fields.get("product_name",0),"Missing Vendor":missing_fields.get("vendor",0),"Missing Version":missing_fields.get("version",0),"Missing Update":missing_fields.get("update",0),"Missing Part":missing_fields.get("part",0),"evaluation_tracks":m["evaluation_tracks"]})
    expected=[("deterministic","N/A")]
    expected.extend((method,model) for model in ("llama","qwen","deepseek","falcon","mistral","gemma") for method in ("llm","agent"))
    actual={(r["Method"],r["Model"]):r for r in summaries}
    for method,model in expected:
        actual.setdefault((method,model),{"Method":method,"Model":model,**{k:None for k in FIELDS[2:]},"per_protocol":{},"failures":[]})
    summaries=[actual[key] for key in expected]
    csv_path=BASE/"results/summary.csv"
    with csv_path.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=FIELDS); w.writeheader(); w.writerows([{k:("N/A" if r.get(k) is None else r.get(k)) for k in FIELDS} for r in summaries])
    lines=["# CPE Extraction Benchmark Results", "", "Extraction product/vendor/version/update/part scores use extraction predictions only. End-to-end CPE scores use final CPE 2.3 resolutions/proposals. Gold labels are provisional until independently reviewed. N/A means not measured.", "", "| "+" | ".join(FIELDS)+" |", "|"+"|".join(["---"]*len(FIELDS))+"|"]
    for r in summaries: lines.append("| "+" | ".join("N/A" if r.get(k) is None else str(r.get(k)) for k in FIELDS)+" |")
    lines += ["", "## Per-protocol breakdown", "", "Protocol-level scores require reviewed gold labels; performance-only rows are not substituted for quality scores.", ""]
    for r in summaries:
        if r.get("per_protocol"):
            lines.append(f"### {r['Method']} / {r['Model']}")
            for protocol, metrics in r["per_protocol"].items(): lines.append(f"- {protocol}: scored={metrics['scored_records']}, exact CPE={metrics['exact_cpe_accuracy'] if metrics['exact_cpe_accuracy'] is not None else 'N/A'}, product F1={metrics['product_name_metrics']['f1'] if metrics['product_name_metrics']['f1'] is not None else 'N/A'}")
    lines += ["", "## Failures", ""]
    any_failures=False
    for r in summaries:
        if r.get("failures"):
            any_failures=True; lines.append(f"- {r['Method']} / {r['Model']}: {len(r['failures'])} failed or invalid records; examples: " + ", ".join(f"{x['record_id']} ({x.get('error') or x.get('invalid_reason') or x.get('status')})" for x in r["failures"][:3]))
    if not any_failures: lines.append("- None recorded.")
    (BASE/"results/report.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    (BASE/"results/details.json").write_text(json.dumps({"gold_label_errors":gold_errors,"comparisons":summaries},indent=2),encoding="utf-8")
    print(f"Wrote {csv_path} and results/report.md")

if __name__ == "__main__": main()
