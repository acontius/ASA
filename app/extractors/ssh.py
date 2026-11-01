"""SSH identification from server_id.software. Protocol version is not a product version."""

from __future__ import annotations

from schemas.models import ExtractionCandidate, NormalizedRecord, PortBlock

from app.extractors.base import block_path, candidate, result_of, split_product_version

EXTRACTOR_ID = "ssh.server_id.v1"


def extract_ssh(record: NormalizedRecord, block: PortBlock) -> list[ExtractionCandidate]:
    server_id = result_of(block).get("server_id")
    if not isinstance(server_id, dict):
        return []
    software = server_id.get("software")
    if not isinstance(software, str) or not software.strip():
        comment = server_id.get("comment")
        if isinstance(comment, str) and comment.strip():
            return [
                candidate(
                    record,
                    product_name=comment.strip(),
                    raw_value=comment.strip(),
                    source_path=block_path(block, "result", "server_id", "comment"),
                    signal_type="comment",
                    extractor_id=EXTRACTOR_ID,
                    evidence_strength="weak",
                    evidence_refs=["server_id.comment"],
                )
            ]
        return []

    software = software.strip()
    parsed = split_product_version(software)
    refs = ["server_id.software"]
    raw = server_id.get("raw")
    if isinstance(raw, str) and raw.strip():
        refs.append("server_id.raw")
    if parsed:
        product, version = parsed
        return [
            candidate(
                record,
                product_name=product,
                version=version,
                raw_value=software,
                source_path=block_path(block, "result", "server_id", "software"),
                signal_type="banner",
                extractor_id=EXTRACTOR_ID,
                evidence_strength="strong",
                evidence_refs=refs,
            )
        ]
    return [
        candidate(
            record,
            product_name=software,
            raw_value=software,
            source_path=block_path(block, "result", "server_id", "software"),
            signal_type="banner",
            extractor_id=EXTRACTOR_ID,
            evidence_strength="moderate",
            evidence_refs=refs,
        )
    ]
