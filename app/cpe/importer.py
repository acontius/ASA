"""Import NVD CPE Dictionary 2.0 JSON into SQLite.

Each input file is one JSON document (``.json`` or ``.json.gz``). A directory
is read as a set of chunk files, one document at a time. The whole feed is
never concatenated into a single in-memory object.

The on-disk shape follows the NVD CPE API 2.0 / dictionary feed::

    {"format": "NVD_CPE", "version": "2.0", "timestamp": "...",
     "products": [{"cpe": {"cpeName": "...", "cpeNameId": "...",
                           "deprecated": false, "titles": [{"title": "...", "lang": "en"}]}}]}

This module does not download anything.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.cpe.parser import CpeParseError, parse_cpe23
from app.cpe.resolver import product_key, vendor_key, version_key
from app.cpe.store import connect, init_schema


class FeedFormatError(ValueError):
    """The file is not an NVD CPE Dictionary 2.0 document."""


@dataclass
class ImportStats:
    files: int = 0
    imported: int = 0
    duplicates: int = 0
    deprecated: int = 0
    invalid: int = 0
    skipped: int = 0
    source_timestamp: str | None = None
    notes: list[str] = field(default_factory=list)


def import_dictionary(source: str, db_path: str) -> ImportStats:
    """Import ``source`` (file or directory) inside one transaction."""
    paths = _source_files(source)
    if not paths:
        raise FeedFormatError(f"no JSON dictionary files found in {source}")
    db = connect(db_path)
    init_schema(db)
    stats = ImportStats()
    try:
        db.execute("BEGIN IMMEDIATE")
        for path in paths:
            _import_file(path, db, stats)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        db.execute(
            """
            INSERT INTO dictionary_metadata (id, schema_version, source_timestamp, imported_at, source_description)
            VALUES (1, '2.0', ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                schema_version = excluded.schema_version,
                source_timestamp = excluded.source_timestamp,
                imported_at = excluded.imported_at,
                source_description = excluded.source_description
            """,
            (
                stats.source_timestamp,
                now,
                "NVD CPE Dictionary 2.0 JSON (local file; not fetched by this process)",
            ),
        )
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    finally:
        db.close()
    return stats


def _source_files(source: str) -> list[Path]:
    path = Path(source)
    if path.is_file():
        return [path]
    if path.is_dir():
        files = [
            item
            for item in sorted(path.iterdir())
            if item.is_file() and item.name.endswith((".json", ".json.gz"))
        ]
        return files
    raise FeedFormatError(f"source not found: {source}")


def _import_file(path: Path, db, stats: ImportStats) -> None:
    stats.files += 1
    opener = gzip.open if path.name.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        try:
            document = json.load(handle)
        except json.JSONDecodeError as exc:
            raise FeedFormatError(f"{path.name}: invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise FeedFormatError(f"{path.name}: dictionary document must be an object")
    version = document.get("version")
    if version != "2.0":
        raise FeedFormatError(f"{path.name}: unsupported schema version {version!r}; expected '2.0'")
    feed_format = document.get("format")
    if feed_format is not None and feed_format != "NVD_CPE":
        raise FeedFormatError(f"{path.name}: unsupported format {feed_format!r}")
    timestamp = document.get("timestamp")
    if isinstance(timestamp, str):
        stats.source_timestamp = timestamp
    products = document.get("products")
    if not isinstance(products, list):
        raise FeedFormatError(f"{path.name}: missing products array")
    for index, item in enumerate(products):
        _import_product(item, db, stats, f"{path.name}[{index}]")


def _import_product(item, db, stats: ImportStats, where: str) -> None:
    if not isinstance(item, dict) or not isinstance(item.get("cpe"), dict):
        stats.skipped += 1
        return
    body = item["cpe"]
    cpe_name = body.get("cpeName")
    cpe_id = body.get("cpeNameId")
    if not isinstance(cpe_name, str) or not isinstance(cpe_id, str) or not cpe_id:
        stats.skipped += 1
        return
    try:
        parsed = parse_cpe23(cpe_name)
    except CpeParseError:
        stats.invalid += 1
        return
    deprecated = 1 if body.get("deprecated") is True else 0
    if deprecated:
        stats.deprecated += 1
    title = _title(body.get("titles"))
    existing = db.execute(
        "SELECT cpe_name FROM cpe_entries WHERE cpe_name_id = ?", (cpe_id,)
    ).fetchone()
    if existing is not None:
        stats.duplicates += 1
        return
    try:
        db.execute("SAVEPOINT cpe_row")
        db.execute(
            """
            INSERT INTO cpe_entries (
                cpe_name_id, cpe_name, part, vendor, product, version, cpe_update,
                edition, language, sw_edition, target_sw, target_hw, other, title,
                deprecated, product_key, version_key, vendor_key,
                product_concrete, version_concrete
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cpe_id,
                parsed.cpe_name,
                parsed.part,
                parsed.vendor,
                parsed.product,
                parsed.version,
                parsed.update,
                parsed.edition,
                parsed.language,
                parsed.sw_edition,
                parsed.target_sw,
                parsed.target_hw,
                parsed.other,
                title,
                deprecated,
                product_key(parsed.product) if parsed.is_concrete("product") else "",
                version_key(parsed.version) if parsed.is_concrete("version") else "",
                vendor_key(parsed.vendor) if parsed.is_concrete("vendor") else "",
                1 if parsed.is_concrete("product") else 0,
                1 if parsed.is_concrete("version") else 0,
            ),
        )
        db.execute("RELEASE SAVEPOINT cpe_row")
    except sqlite3.IntegrityError:
        db.execute("ROLLBACK TO SAVEPOINT cpe_row")
        stats.duplicates += 1
        return
    stats.imported += 1


def _title(titles) -> str | None:
    if not isinstance(titles, list):
        return None
    fallback = None
    for item in titles:
        if not isinstance(item, dict) or not isinstance(item.get("title"), str):
            continue
        if fallback is None:
            fallback = item["title"]
        if item.get("lang") == "en":
            return item["title"]
    return fallback
