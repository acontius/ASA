"""Local-only human annotation UI for independent CVE applicability Gold."""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from benchmarks.cpe.src.applicability_gold import (
    GOLD_SCHEMA, MANIFEST_SCHEMA, canonical_hash, iter_jsonl,
    source_record_id, validate_gold_row, validate_manifest_row,
)

STATIC = Path(__file__).with_name("applicability_static")
MAX_BODY = 64 * 1024


class UiError(ValueError):
    status = 400


class StaleCase(UiError):
    status = 409


def _path_value(document, path: str):
    text = path[1:] if path.startswith("$") else path
    text = text.lstrip(".")
    parts, token, index = [], "", 0
    while index < len(text):
        char = text[index]
        if char == ".":
            if token: parts.append(token); token = ""
            index += 1
        elif char == "[":
            if token: parts.append(token); token = ""
            end = text.find("]", index + 1)
            if end < 0: return False, None
            parts.append(text[index + 1:end].strip("'\"")); index = end + 1
        else:
            token += char; index += 1
    if token: parts.append(token)
    value = document
    try:
        for part in parts:
            if isinstance(value, dict): value = value[part]
            elif isinstance(value, list) and part.isdigit(): value = value[int(part)]
            else: return False, None
        return True, value
    except (KeyError, IndexError, TypeError):
        return False, None


class SourceIndex:
    """Keep offsets and hashes only; fetch one source record on demand."""
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve(strict=True)
        if not self.path.is_file(): raise ValueError("source input must be a regular JSONL file")
        self.entries = {}
        self.malformed = 0
        self.duplicates = 0
        with self.path.open("rb") as stream:
            line_number = 0
            while True:
                offset = stream.tell()
                raw = stream.readline()
                if not raw: break
                line_number += 1
                if not raw.strip(): continue
                try: document = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError): self.malformed += 1; continue
                if not isinstance(document, dict): self.malformed += 1; continue
                record_id = source_record_id(document, line_number)
                if record_id in self.entries: self.duplicates += 1; continue
                self.entries[record_id] = {"offset": offset, "line": line_number, "hash": canonical_hash(document)}

    def get(self, record_id: str) -> tuple[dict, str]:
        entry = self.entries.get(record_id)
        if not entry: raise KeyError(record_id)
        with self.path.open("rb") as stream:
            stream.seek(entry["offset"])
            document = json.loads(stream.readline())
        digest = canonical_hash(document)
        if digest != entry["hash"] or source_record_id(document, entry["line"]) != record_id:
            raise StaleCase("source record changed; regenerate the manifest before annotation")
        return document, digest


class ApplicabilityStore:
    def __init__(self, manifest_path: str | Path, source_path: str | Path, gold_path: str | Path):
        self.manifest_path = Path(manifest_path).resolve(strict=True)
        self.source = SourceIndex(source_path)
        self.gold_path = Path(gold_path).resolve()
        if self.gold_path in {self.manifest_path, self.source.path}:
            raise ValueError("Gold output must differ from source and manifest paths")
        self.lock = threading.RLock()
        self.manifests, self.manifest_errors = {}, []
        for line, row, error in iter_jsonl(self.manifest_path):
            if error: self.manifest_errors.append({"line": line, "error": error}); continue
            errors = validate_manifest_row(row)
            if errors: self.manifest_errors.append({"line": line, "errors": errors}); continue
            if row["case_id"] in self.manifests:
                self.manifest_errors.append({"line": line, "case_id": row["case_id"], "error": "duplicate case_id"}); continue
            self.manifests[row["case_id"]] = row
        self.gold = {}
        self.gold_errors = []
        if self.gold_path.exists():
            for line, row, error in iter_jsonl(self.gold_path):
                if error: self.gold_errors.append({"line": line, "error": error}); continue
                if not isinstance(row, dict): self.gold_errors.append({"line": line, "error": "Gold row must be an object"}); continue
                case_id = row.get("case_id")
                if not isinstance(case_id, str) or case_id in self.gold:
                    self.gold_errors.append({"line": line, "error": "missing or duplicate case_id"}); continue
                errors = validate_gold_row(row, self.manifests.get(case_id))
                if errors: self.gold_errors.append({"line": line, "case_id": case_id, "errors": errors})
                self.gold[case_id] = row

    def list_cases(self, query: str = "", status: str = "all") -> dict:
        if status not in {"all", "pending", "reviewed", "adjudicated", "disputed", "insufficient_evidence", "out_of_scope", "stale"}:
            raise UiError("invalid status filter")
        found = []
        for case_id, manifest in self.manifests.items():
            row = self.gold.get(case_id)
            current = row.get("annotation_status", "unreviewed") if row else "unreviewed"
            source_entry = self.source.entries.get(manifest["source_record_id"])
            stale = not source_entry or source_entry["hash"] != manifest["source_hash"]
            if stale: current = "stale"
            if status == "pending" and current not in {"unreviewed", "disputed"}: continue
            if status not in {"all", "pending"} and current != status: continue
            haystack = f"{case_id} {manifest['source_record_id']} {manifest['cve_snapshot']['cve_id']}".casefold()
            if query and query.casefold() not in haystack: continue
            found.append({"case_id": case_id, "source_record_id": manifest["source_record_id"],
                          "cve_id": manifest["cve_snapshot"]["cve_id"], "status": current, "stale": stale})
        return {"cases": found, "total": len(found), "manifest_errors": self.manifest_errors,
                "gold_errors": self.gold_errors, "source_malformed": self.source.malformed}

    def get_case(self, case_id: str) -> dict:
        manifest = self.manifests.get(case_id)
        if not manifest: raise KeyError(case_id)
        try:
            document, digest = self.source.get(manifest["source_record_id"])
        except (StaleCase, KeyError):
            return {"manifest": manifest, "evidence": [], "gold": self.gold.get(case_id), "stale": True}
        stale = digest != manifest["source_hash"]
        evidence = []
        for path in manifest["asset_snapshot"]["evidence_paths"]:
            found, value = _path_value(document, path)
            encoded = json.dumps(value, ensure_ascii=False, default=str) if found else None
            if encoded is not None and len(encoded) > 2000: encoded = encoded[:2000] + "…"
            evidence.append({"path": path, "found": found, "value": encoded})
        return {"manifest": manifest, "evidence": evidence, "gold": self.gold.get(case_id), "stale": stale}

    def save(self, payload: dict) -> dict:
        if not isinstance(payload, dict): raise UiError("request must be an object")
        allowed = {"case_id", "action", "actor_id", "label", "status", "reason_codes", "notes", "evidence_paths", "identity_ids", "configuration_references"}
        if set(payload) - allowed: raise UiError("unexpected review fields")
        case_id = payload.get("case_id")
        manifest = self.manifests.get(case_id)
        if not manifest: raise UiError("case_id is not in the manifest")
        if self.manifest_errors or self.gold_errors: raise UiError("manifest or existing Gold has errors; repair or regenerate before saving")
        document, current_hash = self.source.get(manifest["source_record_id"])
        if current_hash != manifest["source_hash"]: raise StaleCase("source hash changed; regenerate the manifest before annotation")
        actor = payload.get("actor_id")
        if not isinstance(actor, str) or not actor.strip(): raise UiError("reviewer/adjudicator ID is required")
        action = payload.get("action")
        now = datetime.now(timezone.utc).isoformat()
        current = self.gold.get(case_id)
        if current and (current.get("source_hash") != current_hash or current.get("cve_snapshot", {}).get("configurations_hash") != manifest["cve_snapshot"]["configurations_hash"]):
            raise StaleCase("existing Gold is stale; do not overwrite it with the current source/configuration")
        if current:
            row = json.loads(json.dumps(current))
            history = list(row["annotation_history"])
            history.append({"saved_at": now, "actor_id": actor, "action": action,
                            "expected_applicability": row["expected_applicability"],
                            "annotation_status": row["annotation_status"],
                            "reviews": row["reviews"], "adjudication": row["adjudication"]})
            row["annotation_history"] = history
        else:
            row = {**manifest, "schema_version": GOLD_SCHEMA, "expected_applicability": None,
                   "annotation_status": "unreviewed", "reviews": [], "adjudication": None,
                   "annotation_history": []}
        reviewer_ids = {review["reviewer_id"] for review in row["reviews"]}
        if action in {"review", "non_scored"}:
            label = payload.get("label")
            reasons = payload.get("reason_codes")
            notes = payload.get("notes", "")
            paths = payload.get("evidence_paths", [])
            identities = payload.get("identity_ids", [])
            configs = payload.get("configuration_references", [])
            if actor in reviewer_ids: raise UiError("this reviewer already submitted; use a different reviewer or adjudicate")
            if not isinstance(reasons, list) or not reasons or any(not isinstance(value, str) or not value.strip() for value in reasons):
                raise UiError("provide at least one reason code")
            if not isinstance(notes, str) or len(notes) > 5000: raise UiError("notes must be text up to 5000 characters")
            if not all(isinstance(value, list) and all(isinstance(item, str) for item in value) for value in (paths, identities, configs)):
                raise UiError("evidence and configuration references must be string arrays")
            known_paths = set(manifest["asset_snapshot"]["evidence_paths"])
            known_ids = {item["identity_id"] for item in manifest["asset_snapshot"]["identities"]}
            if set(paths) - known_paths or set(identities) - known_ids: raise UiError("evidence path or identity is not present in this case")
            if not (paths or identities or configs): raise UiError("select supporting evidence or configuration references")
            if action == "review" and label not in {"true", "false", "unknown"}: raise UiError("choose TRUE, FALSE, or UNKNOWN")
            if action == "non_scored" and (payload.get("label") is not None or row["reviews"]):
                raise UiError("insufficient-evidence/out-of-scope decisions must not replace scored reviews")
            row["reviews"].append({"reviewer_id": actor, "reviewed_at": now,
                "expected_applicability": label if action == "review" else None,
                "reason_codes": list(dict.fromkeys(reasons)), "notes": notes,
                "supporting_evidence_paths": list(dict.fromkeys(paths)),
                "supporting_identity_ids": list(dict.fromkeys(identities)),
                "reviewed_configuration_references": list(dict.fromkeys(configs))})
            if action == "non_scored":
                status = payload.get("status")
                if status not in {"insufficient_evidence", "out_of_scope"}: raise UiError("choose insufficient_evidence or out_of_scope")
                row["annotation_status"] = status
                row["expected_applicability"] = None
            else:
                labels = {review["expected_applicability"] for review in row["reviews"]}
                if len(labels) == 1:
                    row["annotation_status"] = "reviewed"
                    row["expected_applicability"] = next(iter(labels))
                else:
                    row["annotation_status"] = "disputed"
                    row["expected_applicability"] = None
            row["adjudication"] = None
        elif action == "adjudicate":
            label, notes = payload.get("label"), payload.get("notes")
            references = payload.get("configuration_references", [])
            if len(row["reviews"]) < 2: raise UiError("adjudication requires at least two independent reviews")
            if actor in reviewer_ids: raise UiError("adjudicator must be independent from the reviewers")
            if label not in {"true", "false", "unknown"}: raise UiError("adjudication must choose TRUE, FALSE, or UNKNOWN")
            if not isinstance(notes, str) or not notes.strip() or len(notes) > 5000: raise UiError("adjudication notes are required and limited to 5000 characters")
            if not isinstance(references, list) or any(not isinstance(item, str) or not item.strip() for item in references):
                raise UiError("configuration references must be an array of non-empty strings")
            row["annotation_status"] = "adjudicated"
            row["expected_applicability"] = label
            row["adjudication"] = {"adjudicator_id": actor, "adjudicated_at": now,
                "expected_applicability": label, "notes": notes,
                "reviewed_configuration_references": list(dict.fromkeys(references))}
        else:
            raise UiError("action must be review, non_scored, or adjudicate")
        errors = validate_gold_row(row, manifest)
        if errors: raise UiError("annotation failed validation: " + "; ".join(errors))
        self._write(row)
        self.gold[case_id] = row
        return {"saved": True, "case_id": case_id, "annotation_status": row["annotation_status"],
                "expected_applicability": row["expected_applicability"], "review_count": len(row["reviews"])}

    def _write(self, replacement: dict) -> None:
        self.gold_path.parent.mkdir(parents=True, exist_ok=True)
        rows = []
        found = False
        if self.gold_path.exists():
            for _, row, error in iter_jsonl(self.gold_path):
                if error or not isinstance(row, dict): raise UiError("existing Gold is malformed; refusing to overwrite")
                if row.get("case_id") == replacement["case_id"]:
                    if found: raise UiError("existing Gold has duplicate case IDs; refusing to overwrite")
                    found = True; rows.append(replacement)
                else: rows.append(row)
        if not found: rows.append(replacement)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.gold_path.parent, prefix=".applicability-gold-", delete=False) as stream:
                temporary = Path(stream.name)
                for row in rows: stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.gold_path)
        finally:
            if temporary and temporary.exists(): temporary.unlink()


def make_handler(app: ApplicabilityStore):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args): return
        def _json(self, status: int, value: dict):
            data = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'")
            self.end_headers(); self.wfile.write(data)
        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/": return self._static("index.html")
            if parsed.path == "/assets/app.js": return self._static("app.js")
            if parsed.path == "/assets/app.css": return self._static("app.css")
            query = parse_qs(parsed.query, max_num_fields=4)
            try:
                if parsed.path == "/api/cases":
                    result = app.list_cases(query.get("q", [""])[0], query.get("status", ["all"])[0])
                    return self._json(200, result)
                if parsed.path == "/api/case":
                    return self._json(200, app.get_case(query.get("case_id", [""])[0]))
                return self._json(404, {"error": "not found"})
            except KeyError: return self._json(404, {"error": "case not found"})
            except UiError as exc: return self._json(exc.status, {"error": str(exc)[:500]})
            except Exception as exc: return self._json(500, {"error": f"request failed ({type(exc).__name__})"})
        def do_POST(self):
            if urlsplit(self.path).path != "/api/review": return self._json(404, {"error": "not found"})
            try:
                length = self.headers.get("Content-Length", "")
                if not length.isdigit(): raise UiError("Content-Length is required")
                if int(length) > MAX_BODY: raise UiError("request body exceeds 64 KiB")
                payload = json.loads(self.rfile.read(int(length)))
                return self._json(200, app.save(payload))
            except UiError as exc: return self._json(exc.status, {"error": str(exc)[:500]})
            except (json.JSONDecodeError, UnicodeDecodeError): return self._json(400, {"error": "request body must be JSON"})
            except Exception as exc: return self._json(500, {"error": f"request failed ({type(exc).__name__})"})
        def _static(self, name: str):
            if name not in {"index.html", "app.js", "app.css"}: return self._json(404, {"error": "not found"})
            data = (STATIC / name).read_bytes(); mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
            self.send_response(200); self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") or "javascript" in mime else ""))
            self.send_header("Content-Length", str(len(data))); self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'")
            self.end_headers(); self.wfile.write(data)
    return Handler


def serve(manifest_path: str, source_path: str, gold_path: str, host: str = "127.0.0.1", port: int = 8766):
    if host != "127.0.0.1": raise ValueError("applicability annotator binds only to 127.0.0.1")
    app = ApplicabilityStore(manifest_path, source_path, gold_path)
    server = ThreadingHTTPServer((host, port), make_handler(app)); server.daemon_threads = True
    print(f"ASA applicability annotator: http://{host}:{server.server_address[1]}/")
    print(f"Cases: {len(app.manifests)}; invalid manifest rows: {len(app.manifest_errors)}; source rows: {len(app.source.entries)}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--gold", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args(argv)
    serve(args.manifest, args.source, args.gold, args.host, args.port)


if __name__ == "__main__": raise SystemExit(main())
