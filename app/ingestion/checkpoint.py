"""JSON sidecar checkpoint.

A checkpoint records the next byte offset that has not yet been durably
handled. It is written only after the corresponding outcome line has been
flushed. Crash between output write and checkpoint update can reprocess one
record (at-least-once). Exactly-once is not claimed.

Schema::

    {"version": 1, "next_offset": <int>, "records_completed": <int>}
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


CHECKPOINT_VERSION = 1


class CheckpointError(ValueError):
    """Raised when a checkpoint file is missing required fields or is invalid."""


@dataclass(frozen=True)
class Checkpoint:
    next_offset: int
    records_completed: int
    version: int = CHECKPOINT_VERSION


def load_checkpoint(path: str, *, input_size: int | None = None) -> Checkpoint:
    file_path = Path(path)
    if not file_path.exists():
        raise CheckpointError(f"checkpoint not found: {path}")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckpointError(f"unreadable checkpoint: {exc}") from exc
    if not isinstance(data, dict):
        raise CheckpointError("checkpoint must be a JSON object")
    if data.get("version") != CHECKPOINT_VERSION:
        raise CheckpointError(f"unsupported checkpoint version: {data.get('version')!r}")
    offset = data.get("next_offset")
    completed = data.get("records_completed", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise CheckpointError(f"next_offset must be a non-negative int, got {offset!r}")
    if not isinstance(completed, int) or isinstance(completed, bool) or completed < 0:
        raise CheckpointError("records_completed must be a non-negative int")
    if input_size is not None and offset > input_size:
        raise CheckpointError(
            f"next_offset {offset} is past input size {input_size}"
        )
    return Checkpoint(next_offset=offset, records_completed=completed)


def save_checkpoint(path: str, checkpoint: Checkpoint) -> None:
    """Atomically replace the sidecar (write temp file in the same directory, then rename)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": CHECKPOINT_VERSION,
        "next_offset": checkpoint.next_offset,
        "records_completed": checkpoint.records_completed,
    }
    fd, tmp_name = tempfile.mkstemp(prefix=".ckpt-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
