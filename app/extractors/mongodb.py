"""MongoDB identification from structured build_info.version."""

from __future__ import annotations

from schemas.models import ExtractionCandidate, NormalizedRecord, PortBlock

from app.extractors.base import block_path, candidate, result_of

EXTRACTOR_ID = "mongodb.build_info.v1"


def extract_mongodb(record: NormalizedRecord, block: PortBlock) -> list[ExtractionCandidate]:
    build_info = result_of(block).get("build_info")
    if not isinstance(build_info, dict):
        return []
    version = build_info.get("version")
    if not isinstance(version, str) or not version.strip():
        array = build_info.get("versionArray")
        if isinstance(array, list) and array and all(isinstance(part, int) for part in array[:3]):
            version = ".".join(str(part) for part in array[:3])
        else:
            return []
    version = version.strip()
    refs = ["build_info.version"]
    env = build_info.get("buildEnvironment")
    if isinstance(env, dict) and isinstance(env.get("target_os"), str):
        refs.append(f"target_os={env['target_os']}")
    return [
        candidate(
            record,
            product_name="MongoDB",
            version=version,
            raw_value=version,
            source_path=block_path(block, "result", "build_info", "version"),
            signal_type="build_info",
            extractor_id=EXTRACTOR_ID,
            evidence_strength="strong",
            evidence_refs=refs,
        )
    ]
