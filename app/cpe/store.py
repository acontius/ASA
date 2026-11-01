"""SQLite dictionary used only for offline resolution."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS dictionary_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version TEXT NOT NULL,
    source_timestamp TEXT,
    imported_at TEXT NOT NULL,
    source_description TEXT
);

CREATE TABLE IF NOT EXISTS cpe_entries (
    cpe_name_id TEXT PRIMARY KEY,
    cpe_name TEXT NOT NULL UNIQUE,
    part TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    cpe_update TEXT NOT NULL,
    edition TEXT NOT NULL,
    language TEXT NOT NULL,
    sw_edition TEXT NOT NULL,
    target_sw TEXT NOT NULL,
    target_hw TEXT NOT NULL,
    other TEXT NOT NULL,
    title TEXT,
    deprecated INTEGER NOT NULL,
    product_key TEXT NOT NULL,
    version_key TEXT NOT NULL,
    vendor_key TEXT NOT NULL,
    product_concrete INTEGER NOT NULL,
    version_concrete INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cpe_product
    ON cpe_entries(product_key, deprecated, version_key);
"""


class DictionaryError(RuntimeError):
    """The local dictionary is missing or not a compatible M3 database."""


def connect(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_schema(db: sqlite3.Connection) -> None:
    db.executescript(SCHEMA)


def require_ready(path: str) -> sqlite3.Connection:
    file_path = Path(path)
    if not file_path.is_file():
        raise DictionaryError(f"dictionary database not found: {path}")
    db = connect(path)
    try:
        row = db.execute(
            "SELECT schema_version, source_timestamp FROM dictionary_metadata WHERE id = 1"
        ).fetchone()
    except sqlite3.Error as exc:
        db.close()
        raise DictionaryError(f"incompatible dictionary database: {exc}") from exc
    if row is None or row["schema_version"] != "2.0":
        db.close()
        raise DictionaryError("dictionary metadata missing or schema_version is not 2.0")
    return db


def metadata(db: sqlite3.Connection) -> dict[str, str | None]:
    row = db.execute(
        "SELECT schema_version, source_timestamp, imported_at, source_description "
        "FROM dictionary_metadata WHERE id = 1"
    ).fetchone()
    if row is None:
        return {}
    return {
        "schema_version": row["schema_version"],
        "source_timestamp": row["source_timestamp"],
        "imported_at": row["imported_at"],
        "source_description": row["source_description"],
    }
