"""Incremental UTF-8 JSONL reader.

Offsets are byte positions in the file (the start of each line). Resume by
passing the byte offset stored after the last durably completed record.

An incomplete final line (no trailing newline) is still parsed when it
contains valid JSON. A truncated or invalid final line is reported as a
malformed record rather than aborting the stream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterator


@dataclass(frozen=True)
class JsonlItem:
    """One physical line from a JSONL file."""

    line_number: int
    byte_offset: int
    next_offset: int
    document: dict | None
    error: str | None


def iter_jsonl_records(path: str, start_offset: int = 0) -> Iterator[JsonlItem]:
    """Yield records starting at a byte offset. Never loads the whole file."""
    if start_offset < 0:
        raise ValueError(f"start_offset must be >= 0, got {start_offset}")

    with open(path, "rb") as raw:
        raw.seek(0, 2)
        size = raw.tell()
        if start_offset > size:
            raise ValueError(
                f"start_offset {start_offset} is past end of file ({size} bytes)"
            )
        raw.seek(start_offset)
        line_number = _line_number_at(path, start_offset)
        while True:
            byte_offset = raw.tell()
            blob = raw.readline()
            if blob == b"":
                return
            next_offset = raw.tell()
            line_number += 1
            yield _decode_line(blob, line_number, byte_offset, next_offset)


def _line_number_at(path: str, start_offset: int) -> int:
    """Count newlines before start_offset so resumed line numbers stay correct."""
    if start_offset == 0:
        return 0
    count = 0
    with open(path, "rb") as raw:
        remaining = start_offset
        while remaining:
            chunk = raw.read(min(65536, remaining))
            if not chunk:
                break
            count += chunk.count(b"\n")
            remaining -= len(chunk)
    return count


def _decode_line(blob: bytes, line_number: int, byte_offset: int, next_offset: int) -> JsonlItem:
    stripped = blob.strip()
    if not stripped:
        return JsonlItem(line_number, byte_offset, next_offset, None, None)
    try:
        text = stripped.decode("utf-8")
    except UnicodeDecodeError as exc:
        return JsonlItem(
            line_number, byte_offset, next_offset, None, f"utf-8 decode error: {exc}"
        )
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        return JsonlItem(
            line_number, byte_offset, next_offset, None, f"invalid JSON: {exc.msg}"
        )
    if not isinstance(value, dict):
        return JsonlItem(
            line_number,
            byte_offset,
            next_offset,
            None,
            f"expected JSON object, got {type(value).__name__}",
        )
    return JsonlItem(line_number, byte_offset, next_offset, value, None)
