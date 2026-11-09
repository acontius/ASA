"""Produce a reproducible report against independent applicability Gold."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.cpe.src.applicability_metrics import evaluate_applicability_gold


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# CVE Applicability Gold Evaluation",
        "",
        "> Applicability correctness on selected asset/CVE cases only. This report does not estimate missed CVEs or retrieval recall. `potentially_affected` is not a confirmed vulnerability.",
        "",
        f"- Pilot report: {'yes' if report['pilot_evaluation'] else 'no'}",
        f"- Eligible reviewed cases: {report['eligible_reviewed_cases']}",
        f"- Prediction coverage: {_percent(report['prediction_coverage'])}",
        f"- Decision coverage (true/false): {_percent(report['decision_coverage'])}",
        f"- Unknown prediction rate: {_percent(report['unknown_prediction_rate'])}",
        f"- Accuracy on definite decisions: {_percent(report['accuracy_on_definite_decisions'])}",
        f"- Macro F1: {_percent(report['macro_f1'])}",
        "",
        "## Confusion matrix",
        "",
        "| Gold \\ Predicted | true | false | unknown | Gold support |",
        "|---|---:|---:|---:|---:|",
    ]
    support = report["class_distribution"]
    for actual in ("true", "false", "unknown"):
        cells = report["confusion_matrix"][actual]
        lines.append(f"| {actual} | {cells['true']} | {cells['false']} | {cells['unknown']} | {support[actual]} |")
    lines.extend(["", "## Per-class metrics", "", "| Class | Precision | Recall | F1 | Support |", "|---|---:|---:|---:|---:|"])
    for label in ("true", "false", "unknown"):
        values = report["per_class"][label]
        lines.append(f"| {label} | {_percent(values['precision'])} | {_percent(values['recall'])} | {_percent(values['f1'])} | {values['support']} |")
    positive = report["security_positive_true"]
    lines.extend([
        "", "## Security-positive (`Gold true`) metrics", "",
        f"- Precision: {_percent(positive['precision'])}",
        f"- Recall: {_percent(positive['recall'])}",
        f"- F1: {_percent(positive['f1'])}",
        f"- Gold true predicted unknown: {positive['gold_true_predicted_unknown']}",
        f"- Gold true predicted false: {positive['gold_true_predicted_false']}",
        f"- Gold true with no prediction: {positive['gold_true_missing_prediction']}",
        "", "## Exclusions and integrity", "",
        f"- Missing predictions: {report['missing_predictions']}",
        f"- Stale source cases: {report['stale_source_cases']}",
        f"- Stale CVE configuration cases: {report['stale_cve_config_cases']}",
        f"- Duplicate prediction cases: {report['duplicate_prediction_cases']}",
        f"- Excluded: `{json.dumps(report['excluded_cases'], sort_keys=True)}`",
        "", "No label is inferred from the ASA prediction. Unreviewed, disputed, insufficient-evidence, out-of-scope and stale cases do not enter primary scoring.", "",
    ])
    return "\n".join(lines)


def _percent(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--source", required=True, help="Original local scan JSONL for source-hash verification")
    parser.add_argument("--predictions", required=True, help="ASA online-assessment-v1 JSONL")
    parser.add_argument("--output", required=True, help="New JSON report path; Markdown is written beside it")
    args = parser.parse_args(argv)
    output = Path(args.output)
    markdown = output.with_suffix(".md")
    if output.exists() or markdown.exists():
        parser.error("report output already exists; choose new JSON/Markdown paths")
    try:
        report = evaluate_applicability_gold(args.gold, args.manifest, args.predictions, args.source)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        with markdown.open("x", encoding="utf-8") as stream:
            stream.write(render_markdown(report))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({"eligible_reviewed_cases": report["eligible_reviewed_cases"],
                      "independent_accuracy_available": report["independent_accuracy_available"],
                      "json_report": str(output), "markdown_report": str(markdown)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
