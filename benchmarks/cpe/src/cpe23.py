"""Standards-tolerant CPE 2.3 formatted-string parsing for NVD API rows.

The production parser intentionally supports the escape subset observed in the
local dictionary. This benchmark parser also accepts escaped printable ASCII
punctuation returned by NVD, while retaining strict field-count and wildcard
semantics for deterministic comparison.
"""
from __future__ import annotations

from dataclasses import dataclass

PREFIX = "cpe:2.3:"
FIELDS = ("part", "vendor", "product", "version", "update", "edition", "language",
          "sw_edition", "target_sw", "target_hw", "other")


class Cpe23Error(ValueError):
    pass


@dataclass(frozen=True)
class Cpe23:
    cpe_name: str
    values: dict[str, str]
    classes: dict[str, str]

    @property
    def value_classes(self) -> dict[str, str]:
        return self.classes

    def __getattr__(self, name: str):
        if name in self.values: return self.values[name]
        raise AttributeError(name)

    def is_concrete(self, field: str) -> bool:
        return self.classes[field] == "concrete"


def parse_cpe23(value: str) -> Cpe23:
    if not isinstance(value, str) or not value.startswith(PREFIX):
        raise Cpe23Error("CPE name must start with 'cpe:2.3:'")
    parts = _split(value)
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        raise Cpe23Error("CPE 2.3 formatted name must contain 11 components")
    values, classes = {}, {}
    for field, raw in zip(FIELDS, parts[2:], strict=True):
        decoded, kind = _decode(raw)
        if not decoded: raise Cpe23Error(f"empty {field} component")
        values[field], classes[field] = decoded, kind
    if classes["part"] == "concrete" and values["part"] not in {"a", "o", "h"}:
        raise Cpe23Error("invalid CPE part")
    return Cpe23(value, values, classes)


def _split(value: str) -> list[str]:
    parts, current, i = [], [], len("cpe:2.3:")
    parts.extend(["cpe", "2.3"])
    while i < len(value):
        char = value[i]
        if char == "\\":
            if i + 1 >= len(value): raise Cpe23Error("trailing CPE escape")
            current.extend((char, value[i + 1])); i += 2; continue
        if char == ":":
            parts.append("".join(current)); current = []; i += 1; continue
        current.append(char); i += 1
    parts.append("".join(current))
    return parts


def _decode(raw: str) -> tuple[str, str]:
    if raw == "*": return "*", "any"
    if raw == "-": return "-", "na"
    chars, wildcard, i = [], False, 0
    while i < len(raw):
        char = raw[i]
        if char == "\\":
            if i + 1 >= len(raw): raise Cpe23Error("trailing CPE escape")
            escaped = raw[i + 1]
            if escaped.isalnum(): raise Cpe23Error("invalid CPE escape")
            chars.append(escaped); i += 2; continue
        if char in "*?": wildcard = True
        chars.append(char); i += 1
    return "".join(chars), "wildcard" if wildcard else "concrete"
"""Backward-compatible import shim for the shared application CPE 2.3 parser."""
from app.vulnerability.nvd.cpe23 import *  # noqa: F401,F403
