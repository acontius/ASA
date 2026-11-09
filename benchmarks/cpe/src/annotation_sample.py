"""Create a local, reproducible Gold annotation manifest (no labels are generated)."""
from __future__ import annotations

import argparse
import json

from benchmarks.cpe.src.dataset import prepare_pilot_sample


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Explicit source JSONL path")
    parser.add_argument("--output", default="benchmarks/cpe/results/pilot-sample.jsonl", help="Ignored JSONL containing raw source records for the UI")
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20261108)
    args = parser.parse_args()
    if args.size < 1 or args.size > 100:
        parser.error("--size must be between 1 and 100")
    try:
        result = prepare_pilot_sample(args.input, args.output, args.size, args.seed)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
