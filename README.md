# ASA — Agentic Vulnerability Scanner

Passive assessment pipeline that extracts software/product identification evidence from scan output. It retains the legacy offline M1–M4 commands and adds an explicit authenticated Online NVD assessment command.

**Online target workflow:** deterministic M2 extraction → official NVD CPE API 2.0 → official NVD CVE API 2.0 → conservative applicability evaluation. Legacy offline M3/M4 commands remain available.

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

## Authenticated Online NVD assessment

The explicit production online path requires `NVD_API_KEY` in the process environment or the existing ignored local `.env` file. It uses one shared request scheduler/cap for both official HTTPS endpoints. Input is streamed and the versioned `online-assessment-v1` JSONL output is never overwritten on a fresh run.

```bash
python -m app.cli online-assess \
  --input Data/PartOfMe.json \
  --output out/online-assessment.jsonl \
  --checkpoint out/online-assessment.ckpt.json \
  --max-api-requests 500
```

Resume with the same paths and add `--resume`. Processing is at-least-once: interruption after output flush but before checkpoint update can replay a record. API failures and incomplete pagination stay distinct from a complete empty result.

Docker Compose forwards the host `NVD_API_KEY` environment variable (or an ignored project `.env` value):

```bash
docker compose run --rm asa online-assess \
  --input /data/PartOfMe.json \
  --output /out/online-assessment.jsonl \
  --checkpoint /out/online-assessment.ckpt.json
```

Only extracted identity terms and validated CPEs are sent to NVD, not complete scan records. The online path does not use local SQLite or local NVD feeds. `CVE retrieval != applicability`; `potentially_affected` is not confirmed vulnerable, and `unknown` is not false. See [the output schema](schemas/online_assessment.schema.json) and [online workflow guide](docs/online_assessment.md).

## Opt-in local agent

The deterministic commands above do not call a model. A separate host command can ask the existing read-only agent one question. It talks only to a llama-server that you start on `127.0.0.1`. It does not download a model, store the conversation, or run as a Docker command. See docs/agent_contract.md.

```bash
llama-server \
  --model /absolute/path/to/model.gguf \
  --host 127.0.0.1 \
  --port 8080 \
  --alias asa-local

python3.11 -m app.agent.cli \
  --workspace-root "$PWD" \
  --message "What local results are ready?"
```

Omit `--message` to pass one UTF-8 request on stdin, at most 32768 bytes. A clarification exits after printing that more information is needed; the request is not saved and is not continued.

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

    app/                 # M2 pipeline, app/cpe, app/vulnerability, and app/agent
    schemas/models.py    # M1 TypedDict contracts
    schemas/cpe.py       # M3 resolution records
    schemas/vulnerability.py
    tests/               # pipeline, agent, and CLI tests
    docs/                # milestone notes and Docker instructions
    Data/PartOfMe.json   # sample JSONL; never included in runtime image

Supported protocols: SSH, HTTP/HTTPS, FTP, MongoDB. Other protocols are reported as unsupported_protocol unless the record also contains a supported port block.

## Privacy

Scan data stays on the local machine. Legacy M2, M3, and M4 commands do not call NVD, other APIs, or a model. The explicit `online-assess` command contacts only the official NVD CPE and CVE APIs and requires the API key. The optional agent command calls only the loopback llama-server you started; it has no cloud fallback. Users download public NVD feeds and model files separately for legacy offline commands. Fixtures use redacted addresses. Synthetic CVE, CPE Match, and CPE dictionary fixtures are not official NVD downloads. Database files and `out/` are gitignored. `potentially_affected` is not a statement that an asset is confirmed vulnerable.

## License

MIT — see LICENSE.
