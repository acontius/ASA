#!/bin/sh
set -eu

case "${1:-help}" in
  scan)
    shift
    exec python -m app.cli "$@"
    ;;
  cpe)
    shift
    exec python -m app.cpe.cli "$@"
    ;;
  test)
    exec python -m unittest discover -s tests -v
    ;;
  help|--help|-h)
    cat <<'USAGE'
ASA — offline scan processing tools

Commands:
  scan <app.cli arguments>       Run the M2 streaming extraction pipeline
  cpe <import|resolve arguments> Run M3 offline CPE dictionary tools
  test                           Run the Python unit test suite (test image only)
  help                           Show this message

Examples:
  docker compose run --rm asa scan --input /data/PartOfMe.json --output /out/outcomes.jsonl --checkpoint /out/scan.ckpt.json
  docker compose run --rm asa cpe import --source /reference/nvd-cpe-dictionary --db /out/cpe-dictionary.sqlite
  docker compose run --rm asa cpe resolve --input /out/outcomes.jsonl --output /out/cpe-resolutions.jsonl --db /out/cpe-dictionary.sqlite

Scan inputs and reference feeds are mounted read-only. Outputs are written to /out.
USAGE
    ;;
  *)
    echo "unknown ASA command: $1 (try 'help')" >&2
    exit 2
    ;;
esac
