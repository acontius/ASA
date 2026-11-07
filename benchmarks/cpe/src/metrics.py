"""Gold-aware extraction metrics. Unreviewed/excluded rows are not scored."""
from __future__ import annotations


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp/(tp+fp) if tp+fp else None; r = tp/(tp+fn) if tp+fn else None
    return {"precision": p, "recall": r, "f1": 2*p*r/(p+r) if p is not None and r is not None and p+r else None}


def evaluate(rows: list[dict], gold_by_id: dict[str, dict]) -> dict:
    scored = [r for r in rows if r.get("record_id") in gold_by_id and gold_by_id[r["record_id"]].get("scoring_status") in {"reviewed", "ambiguous"}]
    out = {"scored_records": len(scored), "sample_records": len(rows), "coverage": sum(bool((r.get("prediction") or {}).get("product_name")) and not (r.get("prediction") or {}).get("abstain", True) for r in scored)/len(scored) if scored else None}
    components = {field: [0, 0, 0] for field in ("product_name", "vendor", "version", "update", "part")}; exact = 0; hallucinated = 0; invalid = 0; schema_invalid = 0; abstain = 0; false_positive = 0
    for row in scored:
        gold = gold_by_id[row["record_id"]]; pred = row.get("prediction") or {}; invalid += int(row.get("invalid_json", False)); schema_invalid += int(not row.get("schema_valid", True)); abstain += int(bool(pred.get("abstain")))
        target_cpes = set(([gold["expected_cpe23"]] if gold.get("expected_cpe23") else []) + gold.get("acceptable_cpes", [])); proposed = set(pred.get("cpe_candidates", []))
        hallucinated += int(bool(proposed - set(row.get("dictionary_cpes", [])) or pred.get("rejected_cpes")))
        exact += int(bool(target_cpes & proposed)) if target_cpes else int(bool(gold.get("abstain_expected") and pred.get("abstain")))
        expected_any = any(gold.get("expected_"+field) is not None for field in components)
        false_positive += int(bool(pred.get("abstain")) is False and bool(gold.get("abstain_expected")))
        for field, counts in components.items():
            exp = gold.get("expected_"+field); got = pred.get(field)
            if exp is None and field == "update": continue
            if exp is None:
                if field in {"vendor", "version", "update", "part"} and not gold.get("abstain_expected"):
                    continue
                if got is not None: counts[1] += 1
            elif got == exp: counts[0] += 1
            else:
                counts[2] += 1
                if got is not None: counts[1] += 1
    out.update({"exact_cpe_accuracy": exact/len(scored) if scored else None, "hallucinated_cpe_rate": hallucinated/len(scored) if scored else None, "abstention_rate": abstain/len(scored) if scored else None, "false_positive_rate": false_positive/len(scored) if scored else None, "invalid_json_rate": invalid/len(scored) if scored else None, "schema_validity_rate": 1-schema_invalid/len(scored) if scored else None})
    for field, (tp, fp, fn) in components.items(): out[field+"_metrics"] = prf(tp, fp, fn)
    total = [sum(c[i] for c in components.values()) for i in range(3)]; out["component_micro"] = prf(*total)
    macro = [prf(*counts)["f1"] for counts in components.values()]; out["component_macro_f1"] = sum(x for x in macro if x is not None)/len([x for x in macro if x is not None]) if any(x is not None for x in macro) else None
    return out
