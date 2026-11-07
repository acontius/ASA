"""Read-only lookup over the local M3 SQLite dictionary or local NVD JSON chunks."""
from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path

from app.cpe.parser import parse_cpe23
from app.cpe.resolver import product_key, version_key, vendor_key


class ReadOnlyCpeLookup:
    def __init__(self, db_path: str | None = None, chunks_path: str | None = None, max_calls: int = 1):
        self.db_path, self.chunks_path, self.max_calls, self.calls = db_path, chunks_path, max_calls, 0
        self.db = None
        if db_path and Path(db_path).is_file():
            uri = Path(db_path).resolve().as_uri() + "?mode=ro&immutable=1"
            self.db = sqlite3.connect(uri, uri=True)
            self.db.row_factory = sqlite3.Row

    def lookup(self, product: str, version: str | None = None, vendor: str | None = None, limit: int = 20) -> list[dict]:
        if self.calls >= self.max_calls:
            raise RuntimeError("CPE lookup call limit exceeded")
        self.calls += 1
        pk, vk = product_key(product), version_key(version) if version else None
        rows = []
        if self.db:
            sql = "SELECT cpe_name, cpe_name_id, part, vendor, product, version, cpe_update, deprecated FROM cpe_entries WHERE product_key=? AND deprecated=0 AND product_concrete=1"
            args: list[object] = [pk]
            if version:
                sql += " AND version_key=? AND version_concrete=1"; args.append(vk)
            if vendor:
                sql += " AND vendor_key=?"; args.append(vendor_key(vendor))
            sql += " LIMIT ?"; args.append(limit)
            rows = [dict(r) for r in self.db.execute(sql, args)]
        elif self.chunks_path and Path(self.chunks_path).is_dir():
            for path in sorted(Path(self.chunks_path).glob("*.json")):
                try:
                    with path.open(encoding="utf-8") as f: doc = json.load(f)
                except (OSError, json.JSONDecodeError):
                    continue
                for item in doc.get("products", []):
                    cpe = item.get("cpe", {}) if isinstance(item, dict) else {}
                    name = cpe.get("cpeName")
                    if not name or cpe.get("deprecated") is True: continue
                    try: parsed = parse_cpe23(name)
                    except ValueError: continue
                    if not parsed.is_concrete("product") or product_key(parsed.product) != pk: continue
                    if version and (not parsed.is_concrete("version") or version_key(parsed.version) != vk): continue
                    if vendor and vendor_key(parsed.vendor) != vendor_key(vendor): continue
                    rows.append({"cpe_name": name, "cpe_name_id": cpe.get("cpeNameId"), "part": parsed.part, "vendor": parsed.vendor, "product": parsed.product, "version": parsed.version, "cpe_update": parsed.update, "deprecated": False})
                    if len(rows) >= limit: return rows
        return rows[:limit]

    def contains_cpe(self, cpe_name: str) -> bool:
        """Exact membership check for human gold-label validation."""
        if self.db:
            return self.db.execute("SELECT 1 FROM cpe_entries WHERE cpe_name=? AND deprecated=0 LIMIT 1", (cpe_name,)).fetchone() is not None
        if self.chunks_path and Path(self.chunks_path).is_dir():
            for path in sorted(Path(self.chunks_path).glob("*.json")):
                try:
                    with path.open(encoding="utf-8") as f: doc = json.load(f)
                except (OSError, json.JSONDecodeError): continue
                if any(isinstance(x, dict) and isinstance(x.get("cpe"), dict) and x["cpe"].get("cpeName")==cpe_name and x["cpe"].get("deprecated") is not True for x in doc.get("products", [])): return True
        return False

    def close(self):
        if self.db: self.db.close()
