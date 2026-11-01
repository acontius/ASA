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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="asa", description="Stream scan JSONL into identification outcomes.")
    parser.add_argument("--input", required=True, help="UTF-8 JSONL scan file")
    parser.add_argument("--output", required=True, help="JSONL file to write outcomes to")
    parser.add_argument("--checkpoint", help="JSON sidecar checkpoint path")
    parser.add_argument("--resume", action="store_true", help="Resume from the checkpoint")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
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
