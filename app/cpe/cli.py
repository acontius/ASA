"""Offline CPE dictionary import and resolution.

Examples::

    python3.11 -m app.cpe.cli import \\
        --source ./local-data/nvd-cpe-dictionary/ \\
        --db ./out/cpe-dictionary.sqlite

    python3.11 -m app.cpe.cli resolve \\
        --input ./out/outcomes.jsonl \\
        --output ./out/cpe-resolutions.jsonl \\
        --db ./out/cpe-dictionary.sqlite
"""

from __future__ import annotations

import argparse
import sys

from app.cpe.importer import FeedFormatError, import_dictionary
from app.cpe.pipeline import ResolveError, resolve_outcomes
from app.cpe.store import DictionaryError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="asa-cpe", description="Offline CPE dictionary tools")
    sub = parser.add_subparsers(dest="command", required=True)

    importer = sub.add_parser("import", help="Import a local NVD CPE Dictionary 2.0 JSON feed")
    importer.add_argument("--source", required=True, help="JSON file, gzip JSON, or directory of chunks")
    importer.add_argument("--db", required=True, help="SQLite path to create or update")

    resolver = sub.add_parser("resolve", help="Resolve an M2 outcomes JSONL file")
    resolver.add_argument("--input", required=True, help="M2 outcomes JSONL")
    resolver.add_argument("--output", required=True, help="Resolution JSONL to write")
    resolver.add_argument("--db", required=True, help="Imported CPE dictionary SQLite")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "import":
            stats = import_dictionary(args.source, args.db)
            print(
                "files={files} imported={imported} duplicates={duplicates} "
                "deprecated={deprecated} invalid={invalid} skipped={skipped}".format(
                    files=stats.files,
                    imported=stats.imported,
                    duplicates=stats.duplicates,
                    deprecated=stats.deprecated,
                    invalid=stats.invalid,
                    skipped=stats.skipped,
                )
            )
            return 0
        stats = resolve_outcomes(args.input, args.output, args.db)
    except (FeedFormatError, ResolveError, DictionaryError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"records={stats['records']} candidates={stats['candidates']} errors={stats['errors']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
