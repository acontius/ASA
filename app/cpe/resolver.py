"""Conservative match of an M2 candidate against active dictionary rows.

No fuzzy matching, no title search, no alias table, no version ranges.
``vendor`` and ``part`` are copied only from a unique dictionary row.
"""

from __future__ import annotations

import re
import sqlite3
import unicodedata
from typing import Any

_SEPARATORS = re.compile(r"[\s_\-]+")
_IDENTIFYING = {"strong", "moderate"}


def product_key(value: str) -> str:
    """Case-fold and drop spaces, underscores, and hyphens.

    ``OpenSSH``, ``openssh``, and ``open_ssh`` compare equal. Other
    characters are left alone, so this is not a substring or fuzzy match.
    """
    text = unicodedata.normalize("NFKC", value).casefold().strip()
    return _SEPARATORS.sub("", text)


def version_key(value: str) -> str:
    """Trim and case-fold only. Suffixes such as ``p1`` are preserved."""
    return unicodedata.normalize("NFKC", value).casefold().strip()


def vendor_key(value: str) -> str:
    return product_key(value)


def resolve_candidate(db: sqlite3.Connection, candidate: Any) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        return _invalid(None, "candidate is not an object")
    cid = candidate.get("candidate_id")
    if not isinstance(cid, str) or not cid:
        return _invalid(cid if isinstance(cid, str) else None, "missing candidate_id")
    product = candidate.get("product_name")
    if not isinstance(product, str) or not product.strip():
        return _invalid(cid, "missing product_name")
    strength = candidate.get("evidence_strength")
    base = {
        "candidate_id": cid,
        "source_path": candidate.get("source_path") if isinstance(candidate.get("source_path"), str) else None,
        "normalized_record_id": candidate.get("normalized_record_id")
        if isinstance(candidate.get("normalized_record_id"), str)
        else None,
        "evidence_strength": strength if isinstance(strength, str) else None,
    }
    if strength == "weak":
        return {**base, "resolution_status": "skipped_weak", "resolution_basis": "evidence_strength", "notes": "weak evidence is not resolved"}
    if strength not in _IDENTIFYING:
        return _invalid(cid, f"unsupported evidence_strength {strength!r}", base)

    version = candidate.get("version")
    version_missing = not isinstance(version, str) or not version.strip()
    vendor = candidate.get("vendor")
    vendor_constraint = vendor_key(vendor) if isinstance(vendor, str) and vendor.strip() else None
    rows = _lookup(db, product_key(product), vendor_constraint)
    active = [row for row in rows if not row["deprecated"] and row["product_concrete"]]
    deprecated = [row for row in rows if row["deprecated"] and row["product_concrete"]]

    if version_missing:
        if active:
            return {
                **base,
                "resolution_status": "product_only",
                "resolution_basis": "product_without_version",
                "match_count": len(active),
                "notes": "dictionary contains this product but the candidate has no version",
            }
        if deprecated:
            return {
                **base,
                "resolution_status": "deprecated_only",
                "resolution_basis": "deprecated_product",
                "match_count": len(deprecated),
                "notes": "only deprecated dictionary rows match this product",
            }
        return {**base, "resolution_status": "no_match", "resolution_basis": "product", "notes": "no dictionary product"}

    wanted = version_key(version)
    exact_active = [row for row in active if row["version_concrete"] and row["version_key"] == wanted]
    exact_deprecated = [row for row in deprecated if row["version_concrete"] and row["version_key"] == wanted]
    if len(exact_active) == 1:
        row = exact_active[0]
        status = "exact_match" if strength == "strong" else "review_required"
        basis = "exact_product_and_version" if strength == "strong" else "moderate_evidence"
        notes = None if strength == "strong" else "moderate evidence is not auto-resolved"
        return {**base, **_row_fields(row), "resolution_status": status, "resolution_basis": basis, "notes": notes}
    if len(exact_active) > 1:
        return {
            **base,
            "resolution_status": "ambiguous",
            "resolution_basis": "multiple_active_entries",
            "match_count": len(exact_active),
            "competing": [_competition(row) for row in exact_active],
            "notes": "differing fields: " + ", ".join(_differing(exact_active)),
        }
    if exact_deprecated:
        return {
            **base,
            "resolution_status": "deprecated_only",
            "resolution_basis": "deprecated_exact_version",
            "match_count": len(exact_deprecated),
            "competing": [_competition(row) for row in exact_deprecated],
            "notes": "only deprecated entries match this product and version",
        }
    if active or deprecated:
        return {
            **base,
            "resolution_status": "no_match",
            "resolution_basis": "version",
            "notes": "product exists but no active entry has this exact version",
        }
    return {**base, "resolution_status": "no_match", "resolution_basis": "product", "notes": "no dictionary product"}


def _lookup(db: sqlite3.Connection, product: str, vendor: str | None) -> list[sqlite3.Row]:
    if not product:
        return []
    if vendor is None:
        return list(
            db.execute(
                "SELECT * FROM cpe_entries WHERE product_key = ?",
                (product,),
            )
        )
    return list(
        db.execute(
            "SELECT * FROM cpe_entries WHERE product_key = ? AND vendor_key = ?",
            (product, vendor),
        )
    )


def _row_fields(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "cpe_name": row["cpe_name"],
        "cpe_name_id": row["cpe_name_id"],
        "part": row["part"],
        "vendor": row["vendor"],
        "product": row["product"],
        "version": row["version"],
        "title": row["title"],
        "deprecated": bool(row["deprecated"]),
    }


def _competition(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "cpe_name": row["cpe_name"],
        "cpe_name_id": row["cpe_name_id"],
        "part": row["part"],
        "vendor": row["vendor"],
        "product": row["product"],
        "version": row["version"],
        "title": row["title"],
        "deprecated": bool(row["deprecated"]),
    }


def _differing(rows: list[sqlite3.Row]) -> list[str]:
    fields = ("part", "vendor", "product", "version", "cpe_update", "edition", "sw_edition", "target_sw", "target_hw")
    found = []
    for field in fields:
        values = {row[field] for row in rows}
        if len(values) > 1:
            found.append("update" if field == "cpe_update" else field)
    return found or ["cpe_name"]


def _invalid(cid: str | None, notes: str, base: dict | None = None) -> dict[str, Any]:
    body = dict(base or {})
    body.update(
        {
            "candidate_id": cid,
            "resolution_status": "invalid_candidate",
            "resolution_basis": "candidate_shape",
            "notes": notes,
        }
    )
    return body
