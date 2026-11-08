from __future__ import annotations

import argparse

from benchmarks.cpe.ui.server import serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Local Gold annotation and CPE benchmark smoke-test UI")
    parser.add_argument("--input", required=True, help="Explicit source JSONL input")
    parser.add_argument("--gold", required=True, help="Gold JSONL output/input path")
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1"], help="Loopback only")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be 0 through 65535")
    serve(args.input, args.gold, args.host, args.port)


if __name__ == "__main__":
    main()
