"""SSH identification from server_id.software. Protocol version is not a product version."""

from __future__ import annotations

import re

from schemas.models import ExtractionCandidate, NormalizedRecord, PortBlock

from app.extractors.base import block_path, candidate, result_of, split_product_version

EXTRACTOR_ID = "ssh.server_id.v1"

# Portable OpenSSH appends pN to the upstream version (9.6p1). NVD stores that
# as version=9.6 and update=p1. The split is not applied to other products.
_OPENSSH_PORTABLE = re.compile(r"^(?P<version>\d+(?:\.\d+)*)p(?P<update>\d+)$", re.IGNORECASE)


def _is_openssh(product: str) -> bool:
    folded = product.casefold().strip()
    return folded.replace("_", "").replace("-", "").replace(" ", "") == "openssh"


def _openssh_release(product: str, version: str) -> tuple[str, str | None]:
    if not _is_openssh(product):
        return version, None
    match = _OPENSSH_PORTABLE.fullmatch(version)
    if not match:
        return version, None
    return match.group("version"), "p" + match.group("update")


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
    comment = server_id.get("comment")
    if isinstance(comment, str) and comment.strip():
        # Distro/package revision (Ubuntu-3ubuntu13.11, Debian-2, …). Kept as
        # evidence only; it is not the OpenSSH update component.
        refs.append("server_id.comment")
    if parsed:
        product, version_token = parsed
        version, update = _openssh_release(product, version_token)
        trailing = ""
        if software.startswith(product) and len(software) > len(product):
            after_name = software[len(product) + 1 :]
            if after_name.startswith(version_token):
                trailing = after_name[len(version_token) :].strip()
        if trailing:
            refs.append(f"package_revision={trailing}")
        return [
            candidate(
                record,
                product_name=product,
                version=version,
                update=update,
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
