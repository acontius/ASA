"""CPE 2.3 formatted-string parser.

Splits on unescaped colons (NIST IR 7695). A backslash escapes the next
character. Recognized escapes are ``\\``, ``:``, ``*``, and ``?``. This is
enough to read official dictionary names. It is not a full CPE name binder
(no WFN generation, no matching language).

Value classes:

* ``any`` — the component is exactly ``*``
* ``na`` — the component is exactly ``-``
* ``wildcard`` — any other component that still contains an unescaped ``*`` or ``?``
* ``concrete`` — everything else
"""

from __future__ import annotations

from dataclasses import dataclass

_PREFIX = "cpe:2.3:"
_ATTRS = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
_ESCAPABLE = set("\\:?*")


class CpeParseError(ValueError):
    """The string is not a usable CPE 2.3 formatted name."""


@dataclass(frozen=True)
class ParsedCpe:
    cpe_name: str
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str
    value_classes: dict[str, str]

    def is_concrete(self, field: str) -> bool:
        return self.value_classes[field] == "concrete"


def parse_cpe23(value: str) -> ParsedCpe:
    if not isinstance(value, str) or not value.startswith("cpe:2.3:"):
        raise CpeParseError("CPE name must start with 'cpe:2.3:'")
    fields = _split_unescaped(value)
    if len(fields) != 13:
        raise CpeParseError(f"expected 13 colon-separated fields, got {len(fields)}")
    if fields[0] != "cpe" or fields[1] != "2.3":
        raise CpeParseError("bad CPE prefix")
    decoded: dict[str, str] = {}
    classes: dict[str, str] = {}
    for name, raw in zip(_ATTRS, fields[2:]):
        text, kind = _decode_component(raw, name)
        decoded[name] = text
        classes[name] = kind
    if classes["part"] == "concrete" and decoded["part"] not in {"a", "h", "o"}:
        raise CpeParseError(f"invalid part: {decoded['part']!r}")
    return ParsedCpe(cpe_name=value, value_classes=classes, **decoded)


def _split_unescaped(value: str) -> list[str]:
    fields: list[str] = []
    buf: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\":
            if i + 1 >= len(value):
                raise CpeParseError("trailing escape")
            nxt = value[i + 1]
            if nxt not in _ESCAPABLE:
                raise CpeParseError(f"invalid escape: \\{nxt}")
            buf.append("\\")
            buf.append(nxt)
            i += 2
            continue
        if char == ":":
            fields.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(char)
        i += 1
    fields.append("".join(buf))
    return fields


def _decode_component(raw: str, field: str) -> tuple[str, str]:
    if raw == "":
        raise CpeParseError(f"empty {field} component")
    if raw == "*":
        return "*", "any"
    if raw == "-":
        return "-", "na"
    out: list[str] = []
    wildcard = False
    i = 0
    while i < len(raw):
        if raw[i] == "\\":
            if i + 1 >= len(raw):
                raise CpeParseError("trailing escape")
            nxt = raw[i + 1]
            if nxt not in _ESCAPABLE:
                raise CpeParseError(f"invalid escape: \\{nxt}")
            out.append(nxt)
            i += 2
            continue
        if raw[i] in "*?":
            wildcard = True
        out.append(raw[i])
        i += 1
    if wildcard:
        return "".join(out), "wildcard"
    return "".join(out), "concrete"
