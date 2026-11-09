"""Command-line entry point for the M2 streaming pipeline.

Example::

    python -m app.cli --input Data/PartOfMe.json --output out/outcomes.jsonl \\
        --checkpoint out/scan.ckpt.json
"""

from __future__ import annotations

import argparse
import sys

from app.ingestion.checkpoint import CheckpointError
from app.pipeline import PipelineError, run_pipeline
from app.vulnerability.nvd.pipeline import OnlineAssessmentError, run_online_assessment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="asa", description="Stream scan JSONL into identification outcomes.")
    subparsers = parser.add_subparsers(dest="command")
    online = subparsers.add_parser("online-assess", help="run authenticated online NVD CPE/CVE assessment")
    online.add_argument("--input", required=True, help="UTF-8 JSONL scan file (or one single-line JSON object)")
    online.add_argument("--output", required=True, help="versioned online assessment JSONL output (must not exist)")
    online.add_argument("--checkpoint", help="sidecar checkpoint path for safe resume")
    online.add_argument("--resume", action="store_true", help="resume from the existing checkpoint and output")
    online.add_argument("--max-api-requests", type=int, default=500,
                        help="shared CPE+CVE HTTP request cap for this run (default: 500)")
    online.add_argument("--max-api-requests-per-identity", type=int, default=5,
                        help="maximum page/retry requests per extracted identity (default: 5)")
    online.add_argument("--timeout-seconds", type=float, default=30.0,
                        help="per-request timeout (default: 30 seconds)")
    # Preserve the legacy M2-only invocation and its output contract.
    parser.add_argument("--input", help="UTF-8 JSONL scan file (legacy M2 mode)")
    parser.add_argument("--output", help="JSONL outcome file (legacy M2 mode)")
    parser.add_argument("--checkpoint", help="JSON sidecar checkpoint path")
    parser.add_argument("--resume", action="store_true", help="Resume from the checkpoint")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "online-assess":
        try:
            stats = run_online_assessment(
                args.input, args.output, args.checkpoint, resume=args.resume,
                max_requests_per_run=args.max_api_requests,
                max_requests_per_identity=args.max_api_requests_per_identity,
                timeout_seconds=args.timeout_seconds,
            )
        except (OnlineAssessmentError, CheckpointError, OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(" ".join(f"{key}={value}" for key, value in stats.items()))
        return 0
    if not args.input or not args.output:
        parser.error("--input and --output are required for the legacy M2 pipeline")
    try:
        stats = run_pipeline(
            args.input,
            args.output,
            args.checkpoint,
            resume=args.resume,
        )
    except (PipelineError, CheckpointError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"processed={stats['processed']} errors={stats['errors']} blank={stats['skipped_blank']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
