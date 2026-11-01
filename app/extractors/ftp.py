"""FTP banner identification.

Device firmware embedded in a banner (for example MikroTik RouterOS) is kept
as a clearly labeled product string and is not rewritten into an FTP daemon
name. Ambiguous banners produce no product/version guess.
"""

from __future__ import annotations

import re

from schemas.models import ExtractionCandidate, NormalizedRecord, PortBlock

from app.extractors.base import block_path, candidate, result_of

EXTRACTOR_ID = "ftp.banner.v1"

_PAREN_PRODUCT = re.compile(
    r"\((?P<name>vsFTPd|ProFTPD|Pure-FTPd|GNU inetutils|FileZilla|MikroTik)\s+(?P<ver>\d+(?:\.\d+)*)\)",
    re.IGNORECASE,
)
_LEADING = re.compile(
    r"^220\s+(?P<name>[\w.-]+)\s+FTP\s+version\s+(?P<ver>\d+(?:\.\d+)*)",
    re.IGNORECASE,
)


def extract_ftp(record: NormalizedRecord, block: PortBlock) -> list[ExtractionCandidate]:
    banner = result_of(block).get("banner")
    if not isinstance(banner, str) or not banner.strip():
        return []
    banner = banner.strip()
    path = block_path(block, "result", "banner")
    paren = _PAREN_PRODUCT.search(banner)
    if paren:
        name = paren.group("name")
        version = paren.group("ver")
        # MikroTik here is the device/firmware, not an FTP daemon version.
        strength = "moderate" if name.lower() == "mikrotik" else "strong"
        product = "MikroTik" if name.lower() == "mikrotik" else name
        return [
            candidate(
                record,
                product_name=product,
                version=version,
                raw_value=banner,
                source_path=path,
                signal_type="banner",
                extractor_id=EXTRACTOR_ID,
                evidence_strength=strength,
                evidence_refs=["banner", "device_firmware" if product == "MikroTik" else "ftp_daemon"],
            )
        ]
    leading = _LEADING.search(banner)
    if leading:
        return [
            candidate(
                record,
                product_name=leading.group("name"),
                version=leading.group("ver"),
                raw_value=banner,
                source_path=path,
                signal_type="banner",
                extractor_id=EXTRACTOR_ID,
                evidence_strength="moderate",
                evidence_refs=["banner"],
            )
        ]
    return [
        candidate(
            record,
            product_name="ftp-banner",
            raw_value=banner,
            source_path=path,
            signal_type="banner",
            extractor_id=EXTRACTOR_ID,
            evidence_strength="weak",
            evidence_refs=["banner"],
        )
    ]
