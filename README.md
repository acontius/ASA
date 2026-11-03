# ASA — Agentic Vulnerability Scanner

Passive assessment pipeline that extracts software/product identification evidence from network scan output, preparing it for later CPE resolution and vulnerability assessment.

**Current milestone:** M4 — Offline CVE intelligence import and conservative applicability assessment.

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

The repository's sample input is mounted read-only from Data/; it is not copied into the image. Outputs appear in the host out/ directory. The same container runs later stages. `cpe` is the M3 dictionary import and resolution command. `vulnerability` is the M4 command (`import-cves`, `import-cpe-match`, `assess`). Neither downloads NVD feeds. For paths, resume, privacy, and troubleshooting, see docs/docker.md.

    docker compose run --rm asa vulnerability --help

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

    app/                 # M2 pipeline, plus app/cpe and app/vulnerability
    schemas/models.py    # M1 TypedDict contracts
    schemas/cpe.py       # M3 resolution records
    schemas/vulnerability.py
    tests/               # M1 through M4 tests
    docs/                # milestone notes and Docker instructions
    Data/PartOfMe.json   # sample JSONL; never included in runtime image

Supported protocols: SSH, HTTP/HTTPS, FTP, MongoDB. Other protocols are reported as unsupported_protocol unless the record also contains a supported port block.

## Privacy

Scan data stays on the local machine. No stage calls NVD, other APIs, or LLMs. Users download public NVD feeds separately and pass local paths. The CPE resolver and the CVE assessor read only local SQLite files. Fixtures use redacted addresses. Synthetic CVE, CPE Match, and CPE dictionary fixtures are not official NVD downloads. Database files and `out/` are gitignored. `potentially_affected` is not a statement that an asset is confirmed vulnerable.

## License

MIT — see LICENSE.
