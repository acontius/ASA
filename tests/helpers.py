"""Shared test helpers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = ROOT / "tests" / "fixtures"


def load_fixture(name: str) -> dict:
    with (FIXTURES / f"fixture_{name}.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def write_jsonl(path: Path, lines: list[str], newline_terminated: bool = True) -> None:
    text = "\n".join(lines)
    if newline_terminated and lines:
        text += "\n"
    path.write_text(text, encoding="utf-8")
