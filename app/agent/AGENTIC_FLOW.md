# Full agentic CPE flow

## Idea

The interactive agent does **not** invent OpenSSH versions. It orchestrates:

1. **Observe** — `inspect_input` / `check_readiness`
2. **Extract** — `extract_identities` (deterministic M2 extractors)
3. **Resolve** — `resolve_cpe_local` (offline dictionary)
4. **Report** — `final_answer` with statuses and `cpe_stub` values

Optional batch path (no decision loop): `python -m app.agent.extract_cpe_cli`.

## Tools

| Tool | Role |
|------|------|
| `inspect_input` | JSONL stats / protocols |
| `check_readiness` | input or SQLite readiness |
| `extract_identities` | M2 identities from scan JSONL |
| `resolve_cpe_local` | offline CPE match |
| `summarize_results` | summarize prior M2/M3/M4 JSONL |
| `list_prior_runs` | placeholder |

## Example

```bash
# llama-server with Instruct model
llama serve --host 127.0.0.1 --port 9931 \
  --model /path/to/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf \
  --alias llama3.1

# copy a small sample under an allowed root (Data or out)
mkdir -p out/samples
grep -i "OpenSSH_9.6p1" Data/PartOfMe.json | head -n 5 > out/samples/openssh5.jsonl

python -m app.agent.cli \
  --workspace-root "$(pwd)" \
  --server-url http://127.0.0.1:9931 \
  --model-alias llama3.1 \
  --max-steps 8 \
  --timeout 60 \
  --message "Extract software identities from out/samples/openssh5.jsonl (max_records 5), resolve OpenSSH against out/cpe-dictionary.sqlite, then summarize CPE resolution statuses."
```

Paths in tool arguments must be **relative** to the workspace and under `Data/`, `out/`, or `local-data/`.
