"""Local-only annotation store and HTTP API for the CPE benchmark."""
from __future__ import annotations

import json
import mimetypes
import os
import tempfile
import threading
import time
import uuid
import urllib.error
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from benchmarks.cpe.src.dataset import protocol_of, stable_id
from benchmarks.cpe.src.gold import canonical_source_hash, load_gold_annotations, validate_gold_v2
from benchmarks.cpe.src.nvd_api import ENDPOINT as NVD_ENDPOINT, load_api_key

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "benchmarks/cpe"
STATIC = Path(__file__).with_name("static")
MAX_REQUEST_BYTES = 256 * 1024


class ClientError(ValueError):
    status = 400

    def __init__(self, message: str, errors: list[str] | None = None):
        super().__init__(message)
        self.errors = errors or []


class StaleSourceError(ClientError):
    status = 409


def _source_document(row: dict, line_number: int) -> tuple[dict, str]:
    """Accept raw JSONL records and benchmark sample wrappers for the UI."""
    raw = row.get("raw")
    declared_id = row.get("record_id")
    if isinstance(raw, dict) and isinstance(declared_id, str) and declared_id:
        return raw, declared_id
    return row, stable_id(row, line_number)


class SourceIndex:
    """Index JSONL offsets and hashes; raw documents are loaded one at a time."""
    def __init__(self, input_path: str | Path):
        self.path = Path(input_path).resolve(strict=True)
        if not self.path.is_file():
            raise ValueError("input must be a regular JSONL file")
        self.entries: list[dict] = []
        self.by_id: dict[str, dict] = {}
        self.malformed_json_rows = 0
        self.non_object_rows = 0
        self.duplicate_ids = 0
        with self.path.open("rb") as stream:
            line_no = 0
            while True:
                offset = stream.tell()
                line = stream.readline()
                if not line:
                    break
                line_no += 1
                if not line.strip():
                    continue
                try:
                    document = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self.malformed_json_rows += 1
                    continue
                if not isinstance(document, dict):
                    self.non_object_rows += 1
                    continue
                source_document, record_id = _source_document(document, line_no)
                if record_id in self.by_id:
                    self.duplicate_ids += 1
                    continue
                entry = {"record_id": record_id, "source_hash": canonical_source_hash(source_document), "offset": offset, "line": line_no, "protocol": protocol_of(source_document)}
                self.entries.append(entry)
                self.by_id[record_id] = entry

    def get(self, record_id: str) -> tuple[dict, str]:
        entry = self.by_id.get(record_id)
        if entry is None:
            raise KeyError(record_id)
        with self.path.open("rb") as stream:
            stream.seek(entry["offset"])
            try:
                row = json.loads(stream.readline())
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise StaleSourceError("source record is no longer valid JSON") from exc
        if not isinstance(row, dict):
            raise StaleSourceError("source record is no longer an object")
        document, record_id = _source_document(row, entry["line"])
        current_hash = canonical_source_hash(document)
        if current_hash != entry["source_hash"] or record_id != entry["record_id"]:
            raise StaleSourceError("source record changed after the UI indexed it; restart the UI and review the new source")
        return document, current_hash

    def raw_at_entry(self, entry: dict) -> tuple[dict, str]:
        return self.get(entry["record_id"])


class AnnotationStore:
    def __init__(self, gold_path: str | Path, source: SourceIndex):
        self.path = Path(gold_path).resolve()
        if self.path == source.path:
            raise ValueError("Gold output path must not be the source input path")
        self.source = source
        self.lock = threading.RLock()

    def load(self) -> tuple[dict[str, dict], list[dict]]:
        # Structural validation does not require loading every source record.
        # Source hashes/evidence paths are checked lazily for the displayed row
        # and again on save, keeping large JSONL inputs bounded in memory.
        return load_gold_annotations(self.path)

    def get(self, record_id: str) -> dict:
        with self.lock:
            document, source_hash = self.source.get(record_id)
            annotations, errors = load_gold_annotations(self.path)
            annotation = annotations.get(record_id)
            if annotation and annotation.get("schema_version") == "2.0":
                if annotation.get("source_hash") != source_hash:
                    return {"record": None, "stale": True, "errors": ["annotation source_hash is stale; current evidence must be reviewed"]}
                annotation_errors = validate_gold_v2(annotation, document)
                if annotation_errors:
                    errors = [{"record_id": record_id, "errors": annotation_errors}]
            return {"record": annotation, "stale": False, "errors": errors}

    def save(self, record: dict) -> dict:
        if not isinstance(record, dict):
            raise ClientError("annotation body must be a JSON object")
        record_id = record.get("record_id")
        if not isinstance(record_id, str) or not record_id:
            raise ClientError("record_id is required")
        with self.lock:
            document, current_hash = self.source.get(record_id)
            if record.get("source_hash") != current_hash:
                raise StaleSourceError("source hash mismatch; reload the source record before saving")
            errors = validate_gold_v2(record, document)
            if errors:
                raise ClientError("Annotation validation failed", errors)
            if self.path == self.source.path:
                raise ClientError("Gold output cannot overwrite source input")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            existing_lines: list[str] = []
            found = False
            if self.path.exists():
                with self.path.open(encoding="utf-8") as stream:
                    for line_no, line in enumerate(stream, 1):
                        if not line.strip():
                            continue
                        try:
                            old = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise ClientError(f"existing Gold contains invalid JSON at line {line_no}; refusing to overwrite it") from exc
                        if not isinstance(old, dict) or not isinstance(old.get("record_id"), str):
                            raise ClientError(f"existing Gold row {line_no} has no valid record_id")
                        if old["record_id"] == record_id:
                            if found:
                                raise ClientError("existing Gold contains duplicate record IDs; refusing to overwrite it")
                            found = True
                            existing_lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True))
                        else:
                            existing_lines.append(line.rstrip("\r\n"))
            if not found:
                existing_lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True))
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent, prefix=".gold-v2-", delete=False) as stream:
                    temp_path = Path(stream.name)
                    stream.write("\n".join(existing_lines) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp_path, self.path)
            finally:
                if temp_path and temp_path.exists():
                    temp_path.unlink()
            return {"saved": True, "record_id": record_id, "source_hash": current_hash}


class SmokeJobs:
    METHODS = {"deterministic", "llm", "agent", "comparison"}
    MAX_RECORDS = 40

    def __init__(self, source: SourceIndex, annotations: AnnotationStore):
        self.source = source
        self.annotations = annotations
        self.jobs: dict[str, dict] = {}
        self.lock = threading.RLock()
        self.config = json.loads((BASE / "config/benchmark.json").read_text(encoding="utf-8"))
        endpoint = urlsplit(self.config.get("server_url", ""))
        if endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1" or endpoint.username or endpoint.password:
            raise ValueError("configured llama.cpp endpoint must use http://127.0.0.1")

    def model_readiness(self) -> dict:
        """Check local model files and the configured loopback server without fallback."""
        endpoint = urlsplit(self.config["server_url"])
        models_url = f"{endpoint.scheme}://{endpoint.netloc}/v1/models"
        server_models: set[str] = set()
        server_error = None
        try:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            request = urllib.request.Request(models_url, headers={"Accept": "application/json"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(request, timeout=0.5) as response:
                body = json.loads(response.read(1024 * 1024))
            server_models = {item["id"] for item in body.get("data", []) if isinstance(item, dict) and isinstance(item.get("id"), str)}
        except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
            server_error = type(exc).__name__
        server_reachable = server_error is None

        model_tokens = {
            "llama": "llama-3.1-8b", "qwen": "qwen3-8b",
            "deepseek": "deepseek-r1-distill-qwen-7b", "gemma": "gemma-2-9b",
            "mistral": "mistral-7b-instruct-v0.3", "falcon": "falcon3-7b-instruct",
        }
        cache_root = Path.home() / ".cache/huggingface/hub"
        local_model_root = BASE / "models"
        cached_config = self.config.get("cached_models", {})
        results = []
        for alias, model_name in sorted(self.config.get("models", {}).items()):
            candidates: list[Path] = []
            cached = cached_config.get(alias, {})
            if cached.get("cache_path"):
                candidates.append(Path(cached["cache_path"]))
            for configured_path in self.config.get("model_paths", {}).get(alias, []):
                candidates.append(Path(configured_path).expanduser())
            local_alias = local_model_root / alias
            if local_alias.is_dir():
                candidates.extend(local_alias.rglob("*.gguf"))
            token = model_tokens.get(alias, "").casefold()
            if cache_root.is_dir() and token:
                for repo in cache_root.glob("models--*"):
                    if token in repo.name.casefold():
                        candidates.extend((repo / "snapshots").glob("*/*.gguf"))
            weight = next((path for path in dict.fromkeys(candidates) if path.is_file()), None)
            filename = weight.name if weight else cached.get("filename")
            quantization = next((part.split(".", 1)[0] for part in (filename or "").split("-") if part.startswith("Q") and "_" in part), None)
            accepted_models = {alias, model_name}
            if filename:
                accepted_models.add(Path(filename).stem)
            server_model_match = bool(server_models & accepted_models)
            ready = bool(weight and server_reachable and server_model_match)
            reason = None if ready else (
                "local GGUF weights were not found" if not weight else
                "configured loopback model server is not reachable" if not server_reachable else
                "server is reachable but the configured model alias is not loaded"
            )
            results.append({
                "alias": alias, "model": model_name, "configured": True,
                "weights_available": bool(weight), "weight_file": str(weight) if weight else None,
                "quantization": quantization, "server_reachable": server_reachable,
                "server_model_match": server_model_match, "ready": ready, "reason": reason,
            })
        api_key_configured = bool(load_api_key())
        return {"endpoint": self.config["server_url"], "server_reachable": server_reachable,
                "server_models": sorted(server_models), "server_error": server_error, "models": results,
                "nvd_api": {"endpoint": self.config.get("nvd_endpoint", NVD_ENDPOINT),
                            "source": "nvd_api_2.0", "configured": True,
                            "network_status": "checked_on_identity_lookup", "api_key_configured": api_key_configured,
                            "rate_limit_mode": "api_key" if api_key_configured else "public",
                            "min_interval_seconds": self.config.get("nvd_min_interval_seconds") or (0.7 if api_key_configured else 6.1)}}

    def start(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ClientError("smoke-test body must be an object")
        method = payload.get("method")
        count = payload.get("record_count", 5)
        model = payload.get("model")
        if method not in self.METHODS:
            raise ClientError("method must be deterministic, llm, agent, or comparison")
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= self.MAX_RECORDS:
            raise ClientError("record_count must be an integer from 1 through 40")
        aliases = set(self.config.get("models", {}))
        if method in {"llm", "agent", "comparison"}:
            if model not in aliases:
                raise ClientError("model must be a configured local model alias")
            readiness = {item["alias"]: item for item in self.model_readiness()["models"]}
            status = readiness[model]
            if not status["ready"]:
                raise ClientError(f"model '{model}' is not ready: {status['reason']}")
        if method == "deterministic":
            model = None
        selected_entries = self.source.entries[:count]
        if len(selected_entries) < count:
            # A shorter input is valid; report its actual count rather than erroring.
            count = len(selected_entries)
        if not selected_entries:
            raise ClientError("input contains no valid JSON object records")
        job_id = uuid.uuid4().hex
        output_path = BASE / "results" / f"smoke-{job_id}.jsonl"
        methods = ("deterministic", "llm", "agent") if method == "comparison" else (method,)
        output_paths = {
            name: str(output_path) if method != "comparison" else str(BASE / "results" / f"smoke-{job_id}-{name}-{model}.jsonl")
            for name in methods
        }
        job = {"job_id": job_id, "state": "running", "method": method, "methods": list(methods), "model": model, "processed": 0, "total": count * len(methods), "output_path": str(output_path) if method != "comparison" else None, "output_paths": output_paths, "outcomes": {}, "errors": 0, "summary": None, "error": None, "started_at": time.time()}
        with self.lock:
            if any(item["state"] == "running" for item in self.jobs.values()):
                raise ClientError("a smoke test is already running")
            self.jobs[job_id] = job
        thread = threading.Thread(target=self._run, args=(job_id, method, model, selected_entries, output_path), daemon=True)
        thread.start()
        return {key: value for key, value in job.items() if key not in {"summary", "error"}}

    def _run(self, job_id: str, method: str, model: str | None, entries: list[dict], output_path: Path) -> None:
        from benchmarks.cpe.src import runner
        records = []
        source_docs = {}
        for entry in entries:
            try:
                raw, source_hash = self.source.raw_at_entry(entry)
            except Exception:
                continue
            records.append({"record_id": entry["record_id"], "raw": raw, "protocol": entry["protocol"], "source_hash": source_hash})
            source_docs[entry["record_id"]] = raw

        def progress(index: int, total: int, row: dict) -> None:
            with self.lock:
                job = self.jobs[job_id]
                job["processed"] = index
                if row.get("outcome"):
                    job["outcomes"][row["outcome"]] = job["outcomes"].get(row["outcome"], 0) + 1
                job["errors"] += int(row.get("status") != "ok")

        try:
            methods = ("deterministic", "llm", "agent") if method == "comparison" else (method,)
            all_rows = {}
            output_paths = self.jobs[job_id]["output_paths"]
            for method_index, current_method in enumerate(methods):
                def method_progress(index: int, total: int, row: dict, offset=method_index * len(records), current=current_method) -> None:
                    progress(offset + index, len(methods) * len(records), {**row, "outcome": f"{current}:{row.get('outcome')}" if row.get("outcome") else None})
                rows_for_method = runner.run(current_method, model if current_method != "deterministic" else None, self.config.get("server_url"), records=records, output_path=Path(output_paths[current_method]), progress_callback=method_progress)
                all_rows[current_method] = rows_for_method
            gold, gold_errors = load_gold_annotations(self.annotations.path, source_docs)
            status_counts = Counter(gold.get("annotation_status", "legacy") for gold in gold.values())
            method_summaries = {}
            for current_method, rows in all_rows.items():
                summary = runner.evaluate(rows, gold)
                scored = summary.get("scored_records", 0)
                accuracy = summary.get("evaluation_tracks", {}).get("end_to_end_cpe", {}).get("exact_cpe_accuracy")
                accuracy_status = ("scored" if accuracy is not None and scored == len(rows) and not gold_errors else "partial" if accuracy is not None else "unavailable")
                latencies = [row.get("latency_seconds") for row in rows if isinstance(row.get("latency_seconds"), (int, float))]
                method_summaries[current_method] = {
                    "records": len(rows), "errors": sum(row.get("status") != "ok" for row in rows),
                    "outcomes": dict(Counter(row.get("outcome") for row in rows if row.get("outcome"))),
                    "mean_latency_seconds": sum(latencies) / len(latencies) if latencies else None,
                    "model_calls": sum(row.get("model_calls", 0) for row in rows),
                    "tool_calls": sum(row.get("tool_calls", 0) for row in rows),
                    "gold_scored_records": scored, "accuracy_status": accuracy_status,
                    "extraction_identity_f1": summary.get("evaluation_tracks", {}).get("extraction_only", {}).get("identity_metrics", {}).get("f1"),
                    "exact_cpe_accuracy": accuracy, "gold_label_errors": gold_errors,
                    **({
                        "cpe_source": "nvd_api_2.0",
                        "api_key_configured": bool(load_api_key()),
                        "rate_limit_mode": "api_key" if load_api_key() else "public",
                        "api_requests": sum(row.get("api_requests", 0) for row in rows),
                        "resolution_statuses": dict(Counter(
                            resolution.get("resolution_status")
                            for row in rows for resolution in row.get("candidate_resolutions", [])
                            if resolution.get("resolution_status")
                        )),
                        "api_errors": [
                            {"record_id": row.get("record_id"), "error": row.get("error"),
                             "resolutions": [res.get("resolution_status") for res in row.get("candidate_resolutions", [])
                                             if res.get("resolution_status", "").startswith("api_") or res.get("resolution_status") == "incomplete_lookup"]}
                            for row in rows if row.get("cpe_source") == "nvd_api_2.0" and row.get("status") == "error"
                        ],
                    } if current_method == "deterministic" else {}),
                }
            with self.lock:
                job = self.jobs[job_id]
                if method == "comparison":
                    final_summary = {"records_per_method": len(records), "model": model, "methods": method_summaries, "gold_status_counts": dict(status_counts)}
                else:
                    current = method_summaries[method]
                    final_summary = {**current, "records": current["records"], "gold_status_counts": dict(status_counts)}
                job.update({
                    "state": "completed", "processed": len(methods) * len(records), "total": len(methods) * len(records), "summary": final_summary,
                    "finished_at": time.time()})
        except Exception as exc:
            with self.lock:
                self.jobs[job_id].update({"state": "failed", "error": f"{type(exc).__name__}: {str(exc)[:400]}", "finished_at": time.time()})

    def get(self, job_id: str) -> dict:
        if not isinstance(job_id, str) or len(job_id) != 32 or any(c not in "0123456789abcdef" for c in job_id):
            raise ClientError("invalid job_id")
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            return dict(job)


class UIApplication:
    def __init__(self, input_path: str | Path, gold_path: str | Path):
        self.source = SourceIndex(input_path)
        self.annotations = AnnotationStore(gold_path, self.source)
        self.smoke_jobs = SmokeJobs(self.source, self.annotations)

    def list_records(self, query: str, status: str, offset: int, limit: int) -> dict:
        allowed = {"all", "pending", "reviewed", "no_software_identity", "ambiguous", "insufficient_evidence", "out_of_scope", "unreviewed", "stale"}
        if status not in allowed:
            raise ClientError("invalid annotation status filter")
        annotations, errors = self.annotations.load()
        found = []
        query_folded = query.casefold()
        for entry in self.source.entries:
            annotation = annotations.get(entry["record_id"])
            record_status = annotation.get("annotation_status", "unreviewed") if annotation else "pending"
            is_stale = bool(annotation and annotation.get("schema_version") == "2.0" and annotation.get("source_hash") != entry["source_hash"])
            if is_stale:
                record_status = "stale"
            if status not in {"all", "pending"} and status != record_status:
                continue
            if status == "pending" and record_status not in {"pending", "unreviewed"}:
                continue
            if query_folded and query_folded not in entry["record_id"].casefold():
                continue
            found.append({"record_id": entry["record_id"], "protocol": entry["protocol"], "line": entry["line"], "annotation_status": record_status, "identity_count": len(annotation.get("expected_identities", [])) if annotation else 0, "stale": is_stale})
        total = len(found)
        return {"records": found[offset:offset + limit], "total": total, "offset": offset, "limit": limit, "malformed_json_rows": self.source.malformed_json_rows, "non_object_rows": self.source.non_object_rows, "gold_errors": errors}

    def record(self, record_id: str) -> dict:
        try:
            document, source_hash = self.source.get(record_id)
        except KeyError:
            raise
        annotation_result = self.annotations.get(record_id)
        return {"record_id": record_id, "source_hash": source_hash, "protocol": protocol_of(document), "raw": document, **annotation_result}


def make_handler(app: UIApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ASACPEAnnotator/2.0"

        def log_message(self, fmt, *args):
            return

        def _json(self, status: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict:
            raw_length = self.headers.get("Content-Length", "")
            if not raw_length.isdigit():
                raise ClientError("Content-Length is required")
            size = int(raw_length)
            if size > MAX_REQUEST_BYTES:
                error = ClientError("request body exceeds 256 KiB")
                error.status = 413
                raise error
            try:
                value = json.loads(self.rfile.read(size))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ClientError("request body must be valid JSON") from exc
            if not isinstance(value, dict):
                raise ClientError("request body must be an object")
            return value

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                self._static("index.html")
                return
            if parsed.path.startswith("/assets/"):
                name = parsed.path.removeprefix("/assets/")
                if name not in {"app.js", "app.css"}:
                    self._json(404, {"error": "not found"}); return
                self._static(name)
                return
            query = parse_qs(parsed.query, max_num_fields=12)
            try:
                if parsed.path == "/api/records":
                    q = query.get("q", [""])[0]
                    if len(q) > 160:
                        raise ClientError("search query is too long")
                    status = query.get("status", ["pending"])[0]
                    offset = int(query.get("offset", ["0"])[0]); limit = int(query.get("limit", ["30"])[0])
                    if offset < 0 or not 1 <= limit <= 100:
                        raise ClientError("offset must be non-negative and limit must be 1 through 100")
                    self._json(200, app.list_records(q, status, offset, limit)); return
                if parsed.path == "/api/record":
                    record_id = query.get("record_id", [""])[0]
                    if len(record_id) > 160:
                        raise ClientError("record_id is too long")
                    self._json(200, app.record(record_id)); return
                if parsed.path == "/api/smoke/options":
                    self._json(200, {"methods": ["deterministic", "llm", "agent", "comparison"], "model_readiness": app.smoke_jobs.model_readiness(), "default_record_count": 5, "max_record_count": 40}); return
                if parsed.path == "/api/smoke/status":
                    self._json(200, app.smoke_jobs.get(query.get("job_id", [""])[0])); return
                self._json(404, {"error": "not found"})
            except KeyError:
                self._json(404, {"error": "record or job not found"})
            except (ValueError, ClientError) as exc:
                self._json(getattr(exc, "status", 400), {"error": str(exc)[:500]})
            except Exception as exc:
                self._json(500, {"error": f"request failed ({type(exc).__name__})"})

        def do_POST(self):
            parsed = urlsplit(self.path)
            try:
                body = self._body()
                if parsed.path == "/api/annotation":
                    self._json(200, app.annotations.save(body)); return
                if parsed.path == "/api/smoke":
                    self._json(202, app.smoke_jobs.start(body)); return
                self._json(404, {"error": "not found"})
            except ClientError as exc:
                body = {"error": str(exc)[:500]}
                if exc.errors:
                    body["errors"] = exc.errors
                self._json(exc.status, body)
            except KeyError:
                self._json(404, {"error": "record not found"})
            except Exception as exc:
                self._json(500, {"error": f"request failed ({type(exc).__name__})"})

        def _static(self, name: str) -> None:
            path = STATIC / name
            data = path.read_bytes()
            mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") or "javascript" in mime else ""))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(input_path: str | Path, gold_path: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    if host != "127.0.0.1":
        raise ValueError("the annotation UI only binds to 127.0.0.1")
    app = UIApplication(input_path, gold_path)
    server = ThreadingHTTPServer((host, port), make_handler(app))
    server.daemon_threads = True
    print(f"ASA CPE local UI: http://{host}:{server.server_address[1]}/")
    print(f"Input records: {len(app.source.entries)}; malformed JSON rows: {app.source.malformed_json_rows}; non-object rows: {app.source.non_object_rows}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
