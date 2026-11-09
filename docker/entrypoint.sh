#!/bin/sh
set -eu

case "${1:-help}" in
  scan)
    shift
    exec python -m app.cli "$@"
    ;;
  online-assess)
    shift
    exec python -m app.cli online-assess "$@"
    ;;
  cpe)
    shift
    exec python -m app.cpe.cli "$@"
    ;;
  vulnerability)
    shift
    exec python -m app.vulnerability.cli "$@"
    ;;
  test)
    exec python -m unittest discover -s tests -v
    ;;
  help|--help|-h)
    cat <<'USAGE'
ASA — scan processing and online assessment tools

Commands:
  scan <app.cli arguments>       Run the M2 streaming extraction pipeline
  online-assess <arguments>     Run authenticated Online NVD assessment
  cpe <import|resolve arguments> Run M3 offline CPE dictionary tools
  vulnerability <arguments>      Run M4 offline CVE tools
                                 (import-cves, import-cpe-match, assess)
  test                           Run the Python unit test suite (test image only)
  help                           Show this message

Examples:
  docker compose run --rm asa scan --input /data/PartOfMe.json --output /out/outcomes.jsonl --checkpoint /out/scan.ckpt.json
  docker compose run --rm asa cpe import --source /reference/nvd-cpe-dictionary --db /out/cpe-dictionary.sqlite
  docker compose run --rm asa cpe resolve --input /out/outcomes.jsonl --output /out/cpe-resolutions.jsonl --db /out/cpe-dictionary.sqlite
  docker compose run --rm asa vulnerability import-cves --source /reference/nvd-cves --db /out/vulnerability-intelligence.sqlite
  docker compose run --rm asa vulnerability import-cpe-match --source /reference/nvd-cpe-match --db /out/vulnerability-intelligence.sqlite
  docker compose run --rm asa vulnerability assess --input /out/cpe-resolutions.jsonl --output /out/cve-assessments.jsonl --db /out/vulnerability-intelligence.sqlite

Scan inputs and reference feeds are mounted read-only. Outputs are written to /out.
online-assess contacts only the official NVD CPE/CVE APIs and requires NVD_API_KEY.
Other commands retain their existing offline behavior.
USAGE
    ;;
  *)
    echo "unknown ASA command: $1 (try 'help')" >&2
    exit 2
    ;;
esac
