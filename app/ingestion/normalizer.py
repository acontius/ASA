"""Turn an Elasticsearch-style scan document into a NormalizedRecord."""

from __future__ import annotations

from typing import Any

from schemas.models import REQUIRED_SOURCE_KEYS, NormalizedRecord, PortBlock, is_port_key


class NormalizationError(ValueError):
    """Input document cannot be normalized (missing required fields or bad types)."""


def normalize(document: dict[str, Any], *, line_number: int, byte_offset: int) -> NormalizedRecord:
    if not isinstance(document, dict):
        raise NormalizationError("input document must be an object")
    source = document.get("_source")
    if not isinstance(source, dict):
        raise NormalizationError("missing or non-object _source")

    missing = [key for key in sorted(REQUIRED_SOURCE_KEYS) if _blank(source.get(key))]
    if missing:
        raise NormalizationError("missing required fields: " + ", ".join(missing))

    for key in ("ip", "scanTime", "proto", "port", "appId", "path"):
        if not isinstance(source.get(key), str):
            raise NormalizationError(f"field {key} must be a string")

    record_id = _record_id(source, document, line_number)
    scan_time = source["scanTime"]
    merge_time = source.get("timestamp")
    if not isinstance(merge_time, str) or merge_time == scan_time:
        merge_time = None

    blocks = _port_blocks(source)
    jid = source.get("jid")
    host = source.get("host")
    return {
        "record_id": record_id,
        "source_path": f"{source['path']}#L{line_number}@{byte_offset}",
        "ip": source["ip"],
        "scan_time": scan_time,
        "merge_time": merge_time,
        "app_id": source["appId"],
        "declared_proto": source["proto"].lower(),
        "declared_port": source["port"],
        "port_blocks": blocks,
        "provenance": {
            "original_line": line_number,
            "jid": jid if isinstance(jid, str) else None,
            "host": host if isinstance(host, str) else None,
        },
    }


def _blank(value: Any) -> bool:
    return value is None or value == ""


def _record_id(source: dict[str, Any], document: dict[str, Any], line_number: int) -> str:
    for candidate in (source.get("id"), document.get("_id")):
        if isinstance(candidate, (str, int)) and not isinstance(candidate, bool):
            return str(candidate)
    return f"line-{line_number}"


def _port_blocks(source: dict[str, Any]) -> list[PortBlock]:
    blocks: list[PortBlock] = []
    for key in sorted(source):
        if not is_port_key(key):
            continue
        wrapper = source[key]
        if not isinstance(wrapper, dict):
            blocks.append(
                {
                    "port_key": key,
                    "protocol": "unknown",
                    "raw_block": {"_invalid": True, "_type": type(wrapper).__name__},
                    "status": "invalid",
                }
            )
            continue
        protocol, payload = _extract_protocol_payload(wrapper, source.get("proto"))
        status = None
        if isinstance(payload, dict) and isinstance(payload.get("status"), str):
            status = payload["status"]
        block: PortBlock = {
            "port_key": key,
            "protocol": protocol,
            "raw_block": payload if isinstance(payload, dict) else {"_value": payload},
        }
        if status is not None:
            block["status"] = status
        blocks.append(block)
    return blocks


def _extract_protocol_payload(wrapper: dict[str, Any], declared_proto: Any) -> tuple[str, Any]:
    """Find the nested protocol object inside a tNN wrapper.

    pub-zgrab2 and pub-tgrab both nest the scan under a protocol name key
    (ssh, http, ftp, mongodb, ...). Envelope keys on the wrapper are ignored.
    """
    skip = {"pr", "appId", "scanTime", "port_scanned", "port"}
    candidates = [k for k in wrapper if k not in skip and isinstance(wrapper[k], dict)]
    if isinstance(declared_proto, str) and declared_proto in candidates:
        return declared_proto.lower(), wrapper[declared_proto]
    if len(candidates) == 1:
        name = candidates[0]
        return name.lower(), wrapper[name]
    if candidates:
        # Prefer a key that itself contains a result object.
        for name in candidates:
            inner = wrapper[name]
            if isinstance(inner, dict) and "result" in inner:
                return name.lower(), inner
        name = candidates[0]
        return name.lower(), wrapper[name]
    return "unknown", {}
