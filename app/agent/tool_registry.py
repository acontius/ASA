"""Explicit, read-only local tool registry for the ASA agent.

All paths are interpreted relative to a trusted workspace supplied by the
application. The model can select only files beneath caller-configured roots.
No handler invokes the ASA pipeline or changes project data.
"""
from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Callable
from urllib.parse import urlsplit

from app.agent.contracts import ALLOWED_TOOL_NAMES, AgentDecision
from schemas.cpe import ResolutionStatus
from schemas.models import OutcomeKind
from schemas.vulnerability import AssessmentStatus, DatasetStatus

DEFAULT_ALLOWED_DATA_ROOTS = ("Data", "out", "local-data")
MAX_RESULT_BYTES = 16 * 1024
_PROTOCOLS = frozenset({"ftp", "http", "https", "ssh", "mongodb"})
_M2_OUTCOMES = frozenset({
    "matched", "ambiguous", "no_match", "insufficient_evidence",
    "processing_error", "unsupported_protocol",
})
_M3_STATUSES = frozenset({
    "exact_match", "review_required", "ambiguous", "product_only",
    "no_match", "deprecated_only", "skipped_weak", "invalid_candidate",
})
_M4_DATASET_STATUSES = frozenset({"assessed", "not_evaluated", "no_match_in_local_feed"})
_M4_ASSESSMENT_STATUSES = frozenset({
    "potentially_affected", "not_evaluated", "context_only", "rejected",
})


class ToolDispatchError(ValueError):
    """Raised when a decision cannot be dispatched safely."""


class ToolInputError(ValueError):
    """Raised for a controlled tool argument or path validation failure."""


@dataclass(frozen=True, slots=True)
class ToolLimits:
    """Hard caller-controlled ceilings; model arguments cannot override them."""

    max_bytes: int = 64 * 1024 * 1024
    max_records: int = 100_000
    max_line_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        for name in ("max_bytes", "max_records", "max_line_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_line_bytes > self.max_bytes:
            raise ValueError("max_line_bytes must not exceed max_bytes")


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Small JSON-compatible result envelope; never carries source records."""

    tool_name: str
    success: bool
    data: dict[str, Any]
    error: str | None = None

    def __post_init__(self) -> None:
        if self.tool_name not in ALLOWED_TOOL_NAMES:
            raise ValueError("tool_name is not allow-listed")
        if not isinstance(self.success, bool) or not isinstance(self.data, dict):
            raise ValueError("invalid tool result fields")
        if self.error is not None and not isinstance(self.error, str):
            raise ValueError("error must be a string or None")
        try:
            encoded = json.dumps(
                {"tool_name": self.tool_name, "success": self.success,
                 "data": self.data, "error": self.error},
                ensure_ascii=True, separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("tool result must contain only JSON-compatible values") from exc
        if len(encoded) > MAX_RESULT_BYTES:
            raise ValueError("tool result exceeds the hard result-size limit")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "data": self.data,
            "error": self.error,
        }


class _SafeWorkspace:
    """Open regular files beneath trusted roots without following symlinks."""

    def __init__(self, workspace_root: str | os.PathLike[str],
                 allowed_data_roots: tuple[str, ...]) -> None:
        root = os.fspath(workspace_root)
        if not os.path.isabs(root):
            raise ValueError("workspace_root must be an absolute trusted path")
        self.root = os.path.realpath(root)
        root_stat = os.stat(self.root, follow_symlinks=False)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ValueError("workspace_root must be a directory")
        if not allowed_data_roots:
            raise ValueError("at least one allowed data root is required")
        roots: list[tuple[str, ...]] = []
        for item in allowed_data_roots:
            parts = self._validate_relative(item)
            if not parts:
                raise ValueError("allowed data roots must not be empty")
            roots.append(parts)
        if len(set(roots)) != len(roots):
            raise ValueError("allowed data roots must be unique")
        self.allowed_roots = tuple(roots)

    @staticmethod
    def _validate_relative(value: str) -> tuple[str, ...]:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ToolInputError("path must be a non-empty relative path")
        if "\\" in value or value.startswith("~"):
            raise ToolInputError("path contains a forbidden separator or home marker")
        parsed_url = urlsplit(value)
        if parsed_url.scheme or parsed_url.netloc or "://" in value:
            raise ToolInputError("URL paths are not allowed")
        path = PurePosixPath(value)
        if path.is_absolute() or value.startswith("/"):
            raise ToolInputError("absolute paths are not allowed")
        parts = path.parts
        if not parts or any(part in ("", ".", "..", "~") for part in parts):
            raise ToolInputError("path traversal is not allowed")
        if any(part.startswith(".") for part in parts):
            raise ToolInputError("hidden paths are not allowed")
        if any(":" in part for part in parts):
            raise ToolInputError("drive-qualified paths are not allowed")
        return tuple(parts)

    def open_regular(self, model_path: str) -> tuple[int, os.stat_result]:
        parts = self._validate_relative(model_path)
        if not any(parts[:len(root)] == root for root in self.allowed_roots):
            raise ToolInputError("path is outside configured data roots")

        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        current_fd = os.open(self.root, directory_flags)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, directory_flags | nofollow, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            file_fd = os.open(
                parts[-1], os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
                dir_fd=current_fd,
            )
        finally:
            os.close(current_fd)

        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(file_fd)
            raise ToolInputError("path must identify a regular file")
        return file_fd, info


class ToolRegistry:
    """Dispatch one typed tool decision to one of four read-only handlers."""

    def __init__(
        self,
        workspace_root: str | os.PathLike[str],
        *,
        allowed_data_roots: tuple[str, ...] = DEFAULT_ALLOWED_DATA_ROOTS,
        limits: ToolLimits | None = None,
    ) -> None:
        self._workspace = _SafeWorkspace(workspace_root, allowed_data_roots)
        self._limits = limits or ToolLimits()
        self._handlers: dict[str, Callable[[dict[str, str]], dict[str, Any]]] = {
            "inspect_input": self._inspect_input,
            "check_readiness": self._check_readiness,
            "list_prior_runs": self._list_prior_runs,
            "summarize_results": self._summarize_results,
        }
        if frozenset(self._handlers) != ALLOWED_TOOL_NAMES:
            raise RuntimeError("registry handlers do not match the contract allow-list")

    def dispatch(self, decision: AgentDecision) -> ToolResult:
        if not isinstance(decision, AgentDecision) or decision.kind != "tool_call":
            raise ToolDispatchError("only AgentDecision(kind='tool_call') can be dispatched")
        call = decision.tool_call
        if call is None:
            raise ToolDispatchError("tool_call decision is missing its ToolCall")
        handler = self._handlers.get(call.name)
        if handler is None:
            return ToolResult(call.name, False, {}, "unknown_tool")
        arguments = dict(call.arguments)
        try:
            self._validate_arguments(call.name, arguments)
            data = handler(arguments)
            return ToolResult(call.name, True, data)
        except (ToolInputError, OSError, sqlite3.Error, UnicodeError, ValueError) as exc:
            return ToolResult(call.name, False, {}, self._safe_error(exc))

    @staticmethod
    def _safe_error(exc: Exception) -> str:
        # Do not echo paths, OS diagnostics, SQL text, or user-controlled values.
        if isinstance(exc, ToolInputError):
            return str(exc)[:160]
        if isinstance(exc, FileNotFoundError):
            return "file_not_found"
        if isinstance(exc, PermissionError):
            return "file_not_readable"
        if isinstance(exc, sqlite3.Error):
            return "sqlite_read_error"
        if isinstance(exc, UnicodeError):
            return "text_encoding_error"
        if isinstance(exc, ValueError):
            return "invalid_input"
        return "local_read_error"

    @staticmethod
    def _validate_arguments(name: str, arguments: dict[str, str]) -> None:
        schemas: dict[str, tuple[set[str], set[str]]] = {
            "inspect_input": ({"input_path"}, {"input_path"}),
            "check_readiness": (
                {"input_path", "cpe_db_path", "vulnerability_db_path"}, set()
            ),
            "list_prior_runs": (set(), set()),
            "summarize_results": ({"results_path"}, {"results_path"}),
        }
        allowed, required = schemas[name]
        keys = set(arguments)
        if keys - allowed:
            raise ToolInputError("unexpected_arguments")
        if required - keys:
            raise ToolInputError("missing_required_arguments")
        if name == "check_readiness" and not keys:
            raise ToolInputError("at_least_one_prerequisite_required")
        if any(not isinstance(value, str) or not value.strip() for value in arguments.values()):
            raise ToolInputError("argument_values_must_be_non_empty_strings")

    def _inspect_input(self, arguments: dict[str, str]) -> dict[str, Any]:
        return self._inspect_jsonl(arguments["input_path"])

    def _inspect_jsonl(self, relative_path: str) -> dict[str, Any]:
        fd, info = self._workspace.open_regular(relative_path)
        try:
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                result = self._scan_jsonl(stream, info.st_size, inspect_protocols=True)
        finally:
            if fd >= 0:
                os.close(fd)
        return result

    def _scan_jsonl(self, stream: Any, file_size: int, *,
                    inspect_protocols: bool) -> dict[str, Any]:
        records = blank = malformed = bytes_read = 0
        protocols: Counter[str] = Counter()
        stopped = oversized = False
        while records + blank + malformed < self._limits.max_records:
            remaining = self._limits.max_bytes - bytes_read
            if remaining <= 0:
                stopped = bytes_read < file_size
                break
            chunk = stream.readline(min(self._limits.max_line_bytes + 1, remaining + 1))
            if not chunk:
                break
            if len(chunk) > remaining:
                bytes_read += remaining
                stopped = True
                break
            bytes_read += len(chunk)
            if len(chunk) > self._limits.max_line_bytes:
                oversized = stopped = True
                break
            stripped = chunk.strip()
            if not stripped:
                blank += 1
                continue
            try:
                document = json.loads(stripped.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                malformed += 1
                continue
            if not isinstance(document, dict):
                malformed += 1
                continue
            records += 1
            if inspect_protocols:
                source = document.get("_source")
                proto = source.get("proto") if isinstance(source, dict) else None
                if not isinstance(proto, str):
                    proto = document.get("declared_proto")
                if isinstance(proto, str):
                    normalized = proto.strip().lower()
                    if normalized in _PROTOCOLS:
                        protocols[normalized] += 1
        if records + blank + malformed >= self._limits.max_records and bytes_read < file_size:
            stopped = True
        if bytes_read >= self._limits.max_bytes and bytes_read < file_size:
            stopped = True
        return {
            "file_size_bytes": file_size,
            "bytes_read": bytes_read,
            "records_inspected": records,
            "blank_lines": blank,
            "malformed_lines": malformed,
            "recognized_protocol_counts": {
                key: protocols.get(key, 0)
                for key in ("ftp", "http", "https", "ssh", "mongodb")
            } if inspect_protocols else {},
            "stopped_at_limit": stopped,
            "oversized_line": oversized,
            "statistics_complete": not stopped and bytes_read == file_size,
        }

    def _check_readiness(self, arguments: dict[str, str]) -> dict[str, Any]:
        checks: dict[str, Any] = {}
        for key, relative_path in arguments.items():
            if key == "input_path":
                try:
                    summary = self._inspect_jsonl(relative_path)
                    checks[key] = {
                        "ready": True,
                        "file_size_bytes": summary["file_size_bytes"],
                        "statistics_complete": summary["statistics_complete"],
                        "malformed_lines": summary["malformed_lines"],
                    }
                except (ToolInputError, OSError) as exc:
                    checks[key] = {"ready": False, "error": self._safe_error(exc)}
            else:
                try:
                    checks[key] = self._check_sqlite_readiness(relative_path)
                except (ToolInputError, OSError, sqlite3.Error) as exc:
                    checks[key] = {"ready": False, "error": self._safe_error(exc)}
        return {"ready": all(item["ready"] for item in checks.values()), "checks": checks}

    def _check_sqlite_readiness(self, relative_path: str) -> dict[str, Any]:
        fd, info = self._workspace.open_regular(relative_path)
        try:
            uri = f"file:/proc/self/fd/{fd}?mode=ro&immutable=1"
            connection = sqlite3.connect(uri, uri=True, timeout=1.0)
            try:
                connection.execute("PRAGMA query_only = ON")
                tables = [
                    row[0] for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "ORDER BY name LIMIT 64"
                    )
                    if isinstance(row[0], str)
                ]
                user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            finally:
                connection.close()
        finally:
            os.close(fd)
        return {
            "ready": True,
            "file_size_bytes": info.st_size,
            "sqlite_read_only": True,
            "user_version": int(user_version),
            "table_names": tables,
            "table_names_truncated": len(tables) == 64,
        }

    @staticmethod
    def _list_prior_runs(arguments: dict[str, str]) -> dict[str, Any]:
        return {
            "available": False,
            "runs": [],
            "reason": "persistent_agent_run_history_not_implemented",
        }

    def _summarize_results(self, arguments: dict[str, str]) -> dict[str, Any]:
        fd, info = self._workspace.open_regular(arguments["results_path"])
        try:
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                return self._summarize_stream(stream, info.st_size)
        finally:
            if fd >= 0:
                os.close(fd)

    def _summarize_stream(self, stream: Any, file_size: int) -> dict[str, Any]:
        records = blank = malformed = bytes_read = 0
        stopped = oversized = False
        result_format: str | None = None
        counts: Counter[str] = Counter()
        dataset_counts: Counter[str] = Counter()
        assessment_counts: Counter[str] = Counter()
        while records + blank + malformed < self._limits.max_records:
            remaining = self._limits.max_bytes - bytes_read
            if remaining <= 0:
                stopped = bytes_read < file_size
                break
            line = stream.readline(min(self._limits.max_line_bytes + 1, remaining + 1))
            if not line:
                break
            if len(line) > remaining:
                bytes_read += remaining
                stopped = True
                break
            bytes_read += len(line)
            if len(line) > self._limits.max_line_bytes:
                oversized = stopped = True
                break
            stripped = line.strip()
            if not stripped:
                blank += 1
                continue
            try:
                item = json.loads(stripped.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                malformed += 1
                continue
            if not isinstance(item, dict):
                malformed += 1
                continue
            detected = self._detect_format(item)
            if detected is None or (result_format is not None and detected != result_format):
                malformed += 1
                continue
            result_format = detected
            records += 1
            if detected == "m2":
                value = item.get("outcome")
                counts[value if value in _M2_OUTCOMES else "unrecognized"] += 1
            elif detected == "m3":
                resolutions = item.get("candidate_resolutions")
                if not isinstance(resolutions, list):
                    malformed += 1
                    records -= 1
                    continue
                for resolution in resolutions:
                    if not isinstance(resolution, dict):
                        malformed += 1
                        continue
                    value = resolution.get("resolution_status")
                    counts[value if value in _M3_STATUSES else "unrecognized"] += 1
            else:
                dataset = item.get("dataset_status")
                dataset_counts[dataset if dataset in _M4_DATASET_STATUSES else "unrecognized"] += 1
                assessments = item.get("cve_assessments")
                if not isinstance(assessments, list):
                    malformed += 1
                    records -= 1
                    continue
                for assessment in assessments:
                    if not isinstance(assessment, dict):
                        malformed += 1
                        continue
                    value = assessment.get("assessment_status")
                    assessment_counts[
                        value if value in _M4_ASSESSMENT_STATUSES else "unrecognized"
                    ] += 1
        if records + blank + malformed >= self._limits.max_records and bytes_read < file_size:
            stopped = True
        if bytes_read >= self._limits.max_bytes and bytes_read < file_size:
            stopped = True
        if result_format is None:
            raise ToolInputError("unrecognized_or_empty_results_file")
        return {
            "format": result_format,
            "records_summarized": records,
            "blank_lines": blank,
            "malformed_records": malformed,
            "counts": dict(sorted(counts.items())),
            "dataset_status_counts": dict(sorted(dataset_counts.items())),
            "assessment_status_counts": dict(sorted(assessment_counts.items())),
            "bytes_read": bytes_read,
            "file_size_bytes": file_size,
            "truncated": stopped,
            "statistics_complete": not stopped and bytes_read == file_size,
            "oversized_line": oversized,
        }

    @staticmethod
    def _detect_format(item: dict[str, Any]) -> str | None:
        if "outcome" in item and "record_id" in item and "candidates" in item:
            return "m2"
        if "candidate_resolutions" in item and "record_id" in item:
            return "m3"
        if "dataset_status" in item and "cve_assessments" in item:
            return "m4"
        return None
