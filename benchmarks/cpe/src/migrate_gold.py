"""Explicitly migrate Gold v1 labels into a new, unreviewed Gold v2 file."""
from __future__ import annotations

import argparse

from benchmarks.cpe.src.gold import migrate_v1_file


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold-v1", required=True, help="Existing unversioned Gold v1 JSONL")
    parser.add_argument("--input", required=True, help="Original source JSONL used to create record hashes")
    parser.add_argument("--output", required=True, help="New destination path; existing files are never overwritten")
    args = parser.parse_args()
    count = migrate_v1_file(args.gold_v1, args.output, args.input)
    print(f"Migrated {count} rows to {args.output}; all migrated records require human review.")


if __name__ == "__main__":
    main()
