# ASA — Agentic Vulnerability Scanner

Passive assessment pipeline that extracts software/product identification evidence from network scan output, preparing it for later CPE resolution and vulnerability assessment.

**Current milestone:** M3 — Offline CPE dictionary import and conservative resolution.

## Run with Docker (recommended for a repeatable environment)

Requires Docker Engine and Docker Compose v2. The runtime image uses Python 3.11 and the standard library only. It is a CLI container, not a web service.

    docker compose build
    mkdir -p out
    export ASA_UID="$(id -u)"
    export ASA_GID="$(id -g)"

    docker compose run --rm asa scan \
      --input /data/PartOfMe.json \
      --output /out/outcomes.jsonl \
      --checkpoint /out/scan.ckpt.json

The repository's sample input is mounted read-only from Data/; it is not copied into the image. Outputs appear in the host out/ directory. For CPE import/resolution commands, alternate paths, resume, privacy, and troubleshooting, see docs/docker.md.

## Run directly with Python

Requires Python 3.11 (3.10 can import the modules; the test suite is executed on 3.11). No third-party packages.

    python3.11 -m app.cli \
      --input Data/PartOfMe.json \
      --output out/outcomes.jsonl \
      --checkpoint out/scan.ckpt.json

Resume:

    python3.11 -m app.cli --input Data/PartOfMe.json \
      --output out/outcomes.jsonl --checkpoint out/scan.ckpt.json --resume

The CLI refuses to write outcomes onto the input path. Details: docs/m2_implementation.md.

## M3 — resolve candidates to official CPE names

M3 does not change the M2 pipeline. It imports a local NVD CPE Dictionary 2.0 JSON file into SQLite, then resolves an outcomes file offline. It does not download NVD data and it does not send scan output anywhere.

    python3.11 -m app.cpe.cli import \
      --source ./local-data/nvd-cpe-dictionary/ \
      --db ./out/cpe-dictionary.sqlite

    python3.11 -m app.cpe.cli resolve \
      --input ./out/outcomes.jsonl \
      --output ./out/cpe-resolutions.jsonl \
      --db ./out/cpe-dictionary.sqlite

The source may be one .json / .json.gz document or a directory of those files. The feed version must be 2.0. Only a unique active CPE with an exact product and version, plus strong evidence, becomes exact_match. Vendor and part are copied from that entry; they are never guessed. See docs/m3_implementation.md.

## Tests and GitHub CI

    python3.11 -m unittest discover -s tests -v

GitHub Actions runs the full suite on Python 3.11 and builds/runs the Docker test image. It also builds the runtime image and runs a smoke test against the sample JSONL dataset. See .github/workflows/tests.yml and docs/docker.md.

## Layout

    app/                 # M2 pipeline plus app/cpe for offline resolution
    schemas/models.py    # M1 TypedDict contracts
    schemas/cpe.py       # M3 resolution records
    tests/               # M1, M2, and M3 tests
    docs/                # milestone notes and Docker instructions
    Data/PartOfMe.json   # sample JSONL; never included in runtime image

Supported protocols: SSH, HTTP/HTTPS, FTP, MongoDB. Other protocols are reported as unsupported_protocol unless the record also contains a supported port block.

## Privacy

Scan data stays on the local machine. Neither pipeline calls external APIs or LLMs. The CPE resolver reads only the local SQLite dictionary. Fixtures use redacted addresses. The synthetic CPE fixture is not an official NVD download, and dictionary databases are gitignored.

## License

MIT — see LICENSE.
