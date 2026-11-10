# Agent path: CPE identities from scan JSONL

## What this is

Batch extraction of software identities (product / version / update) and a
**CPE stub** from PartOfMe-style scan logs.

This is the practical agent-phase path for comparison against pure M2+M3.

The interactive `python -m app.agent.cli` assistant remains read-only ops help
(inspect files, summarize results). CPE extraction from logs uses:

```bash
python -m app.agent.extract_cpe_cli ...
```

## Modes

| Mode | Backend |
|------|---------|
| `deterministic` | M2 extractors (SSH/HTTP/FTP/MongoDB), including OpenSSH `9.6` + `p1` split |
| `llm` | Local `llama-server` chat completions |
| `both` | Side-by-side for benchmark tables |

## Examples

Deterministic (fast, recommended baseline):

```bash
python -m app.agent.extract_cpe_cli \
  --input Data/PartOfMe.json \
  --output out/agent_cpe_det.jsonl \
  --mode deterministic \
  --limit 100
```

LLM only (requires llama-server):

```bash
llama serve --host 127.0.0.1 --port 9931 \
  --model /path/to/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf \
  --alias llama3.1

python -m app.agent.extract_cpe_cli \
  --input /tmp/openssh_sample.jsonl \
  --output out/agent_cpe_llm.jsonl \
  --mode llm \
  --server-url http://127.0.0.1:9931 \
  --model-alias llama3.1 \
  --limit 20
```

Both (comparison):

```bash
python -m app.agent.extract_cpe_cli \
  --input /tmp/openssh_sample.jsonl \
  --output out/agent_cpe_both.jsonl \
  --mode both \
  --server-url http://127.0.0.1:9931 \
  --model-alias llama3.1 \
  --limit 20
```

## Output shape (one JSON object per input record)

```json
{
  "record_id": "...",
  "line_number": 1,
  "deterministic": [
    {
      "product": "OpenSSH",
      "version": "9.6",
      "update": "p1",
      "cpe_stub": "cpe:2.3:a:*:openssh:9.6:p1:*:*:*:*:*:*",
      "source_path": "t22.ssh.result.server_id.software",
      "evidence_strength": "strong",
      "raw_value": "OpenSSH_9.6p1"
    }
  ],
  "llm": []
}
```

`cpe_stub` is a **candidate pattern**, not an NVD-validated CPE.
Validate with `app.cpe.cli resolve` or `app.cli online-assess`.

## Benchmark note (observed)

On OpenSSH portable banners, deterministic correctly splits `9.6p1` →
version=`9.6`, update=`p1`. Llama-3.1 often keeps `9.6p1` inside version and
puts distro revision into update. Use `--mode both` to capture that gap.
