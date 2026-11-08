# ASA CPE Extraction Benchmark (MVP)

This benchmark is isolated from the production CLI and consumes ASA's existing M2 normalizer/extractors and M3 conservative resolver. It does not change their behavior. Inference uses the installed llama.cpp `llama serve` OpenAI-compatible server on literal loopback only. The model receives local records; no external service is called.

## Data and ground truth

`Data/PartOfMe.json` is read locally as JSONL. `--prepare` writes a reproducible sample stratified by protocol, actual M2 outcome/evidence strength, and version presence to `data/sample.jsonl`; M2 labels are used only for sampling and are never evaluation gold. The sample is intentionally git-ignored because it contains scan records. The gold annotation file is `data/gold.jsonl`, also git-ignored. It starts empty. Accuracy, F1 and related quality scores are therefore N/A until a human independently reviews and validates labels against the local official CPE Dictionary. Do not use deterministic/model outputs as labels.

Gold record fields: `record_id`, `expected_product`, `expected_vendor`, `expected_version`, `expected_update`, `expected_part`, `expected_cpe23`, `acceptable_cpes`, `abstain_expected`, `evidence_paths`, `adjudication_notes`, and `scoring_status` (`unreviewed`, `reviewed`, `ambiguous`, or `excluded`). CPE strings are checked with ASA's CPE 2.3 parser. Keep record identifiers and labels out of model prompts.

All Gold record keys in `gold.schema.json` are required, but identity values may be `null`. A CPE identity requires a concrete `expected_product` when an expected or acceptable CPE is supplied. Vendor, version, update, and part are optional when null; when specified, they must match. A Gold value of `*` is unconstrained. A concrete expected value does not match a wildcard CPE component; `-` matches only the CPE not-applicable value. Product/vendor normalization uses the resolver's case-folding and separator rules; version/update are case-folded and trimmed; part is case-folded and trimmed.

Result JSONL keeps extraction identities in `extraction_prediction(s)` and end-to-end results in `final_cpe_resolutions`. Deterministic rows preserve one resolution per M2 candidate and do not aggregate multi-candidate identities into a single prediction. Direct ignores model-proposed CPEs and sends non-abstaining extracted identity through M3. Agent rows preserve the final CPE proposals. Aggregate reports label extraction metrics and end-to-end CPE metrics separately. Records with more than one candidate may yield false positives against single-identity Gold; the current Gold schema cannot express multiple expected software identities per record.

## Prepare and run

From the repository root:

```bash
python -m benchmarks.cpe.src.runner --prepare
python -m benchmarks.cpe.src.runner --method deterministic
python -m benchmarks.cpe.src.report
```

The deterministic adapter runs M2 against the same sample. If `out/cpe-dictionary.sqlite` is available, it invokes M3's resolver; otherwise extraction still runs and CPE resolution is unavailable (reported as N/A). Import the local dictionary with the existing command before measuring CPE accuracy:

```bash
python -m app.cpe.cli import --source ./local-data/nvd-cpe-dictionary/nvdcpe-2.0-chunks --db ./out/cpe-dictionary.sqlite
```

To use cached Qwen, start a local `llama-server` with the same 4096-token context. This command uses CPU inference (`--n-gpu-layers 0`), because GPU access was unavailable during this MVP run:

```bash
llama serve \
  --model "/home/acontius/.cache/huggingface/hub/models--Qwen--Qwen3-8B-GGUF/snapshots/7c41481f57cb95916b40956ab2f0b139b296d974/Qwen3-8B-Q4_K_M.gguf" \
  --host 127.0.0.1 --port 8080 --alias qwen --ctx-size 4096 --n-gpu-layers 0
```

For GPU inference, choose an offload layer count only after checking available VRAM, then record the actual count. Load one GGUF at a time. Run:

```bash
python -m benchmarks.cpe.src.runner --method llm --model qwen
python -m benchmarks.cpe.src.runner --method agent --model qwen
```

The server must listen on `127.0.0.1:8080` and implement `/v1/chat/completions` streaming. Override only its loopback endpoint with `--server-url`. Each selected model is loaded/unloaded manually, sequentially. The agent makes at most two model calls and one dictionary lookup per record; it cannot execute tools beyond that read-only lookup. Missing servers and request errors are preserved as row failures.

Outputs under `results/`: raw per-record JSONL, per-run summary JSON, aggregate CSV, Markdown table, and detailed protocol/failure JSON. Missing measurements are N/A, never zero. Secondary ROUGE/BLEU/BERTScore and model-server GPU/RSS sampling are not implemented in this MVP; no value is inferred from model size. Deterministic process RSS is recorded. llama-server usage provides token counts when available. Hardware records Python/platform and `nvidia-smi` availability. Runs are single-pass; repeated-run dispersion is not available yet.

## Models and limits

The configured families are Llama 3.1 8B, Qwen3 8B, DeepSeek-R1-Distill-Qwen 7B, Falcon3 7B, Mistral 7B v0.3 and Gemma 2 9B, all intended as Q4_K_M GGUF. The runner does not download model weights. Use `hf download REPOSITORY FILENAME --local-dir benchmarks/cpe/models/MODEL` one model at a time, and record exact file metadata before inference. Model licensing, access and available disk space must be checked first. Never add GGUF or scan input files to Git.

DeepSeek-R1 reasoning may be included in server generation tokens and latency; this MVP cannot reliably separate reasoning tokens from answer tokens. Report that limitation when using the model.

This MVP provides the workflow and annotation/evaluation path, not a completed quality benchmark. No human-reviewed gold labels exist yet. A 30–50 record run without those labels is only a pipeline/performance smoke test.
