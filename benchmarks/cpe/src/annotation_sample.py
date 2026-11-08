"""Create a local, reproducible Gold annotation manifest (no labels are generated)."""
from __future__ import annotations

import argparse
import json

from benchmarks.cpe.src.dataset import create_annotation_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Explicit source JSONL path")
    parser.add_argument("--output", default="benchmarks/cpe/results/annotation-manifest.jsonl")
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20261108)
    args = parser.parse_args()
    if args.size < 1 or args.size > 10000:
        parser.error("--size must be between 1 and 10000")
    print(json.dumps(create_annotation_manifest(args.input, args.output, args.size, args.seed), indent=2))


if __name__ == "__main__":
    main()
