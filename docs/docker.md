# Running ASA with Docker

ASA is a local Python CLI pipeline, not a web service. The container has no network dependency and does not call NVD or an LLM. Input datasets and reference feeds are mounted read-only; generated files go to the host's out/ directory.

## Requirements

- Docker Engine with Docker Compose v2.
- A local clone of this repository.

The runtime image uses Python 3.11 and the standard library only.

## 1. Build the image

From the repository root:

    docker compose build
    docker run --rm asa:local help

The first build downloads the base Python image. Runtime processing itself does not need network access.

## 2. Run the sample scan

The repository sample is mounted read-only from Data/; it is not copied into the image.

    mkdir -p out
    export ASA_UID="$(id -u)"
    export ASA_GID="$(id -g)"

    docker compose run --rm asa scan \
      --input /data/PartOfMe.json \
      --output /out/outcomes.jsonl \
      --checkpoint /out/scan.ckpt.json

Check the output:

    wc -l out/outcomes.jsonl
    head -n 2 out/outcomes.jsonl

The input is about 14.8 MB and contains 1,618 JSONL records. This is a useful smoke test, not proof of performance on the 4 GB production dataset.

To resume after an interruption:

    docker compose run --rm asa scan \
      --input /data/PartOfMe.json \
      --output /out/outcomes.jsonl \
      --checkpoint /out/scan.ckpt.json \
      --resume

The current M2 checkpoint behavior is at-least-once; a crash between output flush and checkpoint update can repeat one record.

## 3. Run the M3 CPE stage

Place a locally downloaded NVD CPE Dictionary 2.0 JSON file or .json.gz chunks under local-data/nvd-cpe-dictionary/. Do not commit the feed to Git.

    docker compose run --rm asa cpe import \
      --source /reference/nvd-cpe-dictionary/ \
      --db /out/cpe-dictionary.sqlite

    docker compose run --rm asa cpe resolve \
      --input /out/outcomes.jsonl \
      --output /out/cpe-resolutions.jsonl \
      --db /out/cpe-dictionary.sqlite

The CPE stage uses only the local dictionary database. The official NVD feed has not been validated as part of the Docker smoke test; use the project's M3 documentation for current feed support and limitations.

## 4. Run tests

Run the complete suite locally with Python:

    python3.11 -m unittest discover -s tests -v

GitHub Actions builds a separate test image and runs the same test suite inside it. The sample data is bind-mounted into the test container rather than baked into the image.

## Data handling and image contents

- Data/PartOfMe.json is excluded from the Docker build context and image.
- The runtime image contains application code and schemas, not tests, scan data, NVD feeds, or SQLite databases.
- /data and /reference are read-only mounts.
- /out is the writable output mount.
- The container runs as a non-root user by default; Compose uses the current host UID/GID to avoid root-owned output files.
- The container drops Linux capabilities, enables no-new-privileges, and uses a read-only root filesystem.

To use another input directory, set ASA_DATA_DIR. To change reference feed and output directories, set ASA_REFERENCE_DIR and ASA_OUTPUT_DIR.
