"""Resolver tests against the synthetic dictionary fixture."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import FIXTURES

from app.cpe.importer import import_dictionary
from app.cpe.resolver import resolve_candidate
from app.cpe.store import connect


def _db():
    tmp = TemporaryDirectory()
    path = Path(tmp.name) / "dict.sqlite"
    import_dictionary(str(FIXTURES / "cpe_dictionary_sample.json"), str(path))
    return tmp, connect(str(path))


def _cand(**overrides):
    body = {
        "candidate_id": "c1",
        "product_name": "nginx",
        "vendor": None,
        "version": "1.24.0",
        "part": None,
        "source_path": "t80.http.result.response.headers.server",
        "raw_value": "nginx/1.24.0",
        "signal_type": "header",
        "extractor_id": "http.server_header.v1",
        "evidence_strength": "strong",
        "evidence_refs": ["headers.server"],
        "normalized_record_id": "rec-1",
    }
    body.update(overrides)
    return body


class TestResolver(unittest.TestCase):
    def test_exact_strong_match_copies_vendor_and_part(self):
        tmp, db = _db()
        try:
            found = resolve_candidate(db, _cand())
            self.assertEqual(found["resolution_status"], "exact_match")
            self.assertEqual(found["vendor"], "f5")
            self.assertEqual(found["part"], "a")
            self.assertEqual(found["cpe_name_id"], "11111111-1111-1111-1111-111111111111")
            self.assertFalse(found["deprecated"])
            self.assertEqual(found["source_path"], "t80.http.result.response.headers.server")
        finally:
            db.close()
            tmp.cleanup()

    def test_wrong_version_and_unknown_product(self):
        tmp, db = _db()
        try:
            wrong = resolve_candidate(db, _cand(version="1.24.1"))
            self.assertEqual(wrong["resolution_status"], "no_match")
            self.assertNotIn("cpe_name", wrong)
            unknown = resolve_candidate(db, _cand(product_name="not-a-real-product", version="1"))
            self.assertEqual(unknown["resolution_status"], "no_match")
        finally:
            db.close()
            tmp.cleanup()

    def test_missing_version_is_product_only(self):
        tmp, db = _db()
        try:
            found = resolve_candidate(db, _cand(version=None))
            self.assertEqual(found["resolution_status"], "product_only")
            self.assertNotIn("cpe_name", found)
        finally:
            db.close()
            tmp.cleanup()

    def test_ambiguous_vendors_are_not_guessed(self):
        tmp, db = _db()
        try:
            found = resolve_candidate(db, _cand(product_name="shared", version="1.0"))
            self.assertEqual(found["resolution_status"], "ambiguous")
            vendors = {item["vendor"] for item in found["competing"]}
            self.assertEqual(vendors, {"acme", "other"})
            self.assertNotIn("vendor", {k for k, v in found.items() if k == "vendor" and v})
            self.assertIsNone(found.get("vendor"))
        finally:
            db.close()
            tmp.cleanup()

    def test_moderate_is_not_auto_resolved(self):
        tmp, db = _db()
        try:
            found = resolve_candidate(db, _cand(evidence_strength="moderate"))
            self.assertEqual(found["resolution_status"], "review_required")
            self.assertEqual(found["cpe_name_id"], "11111111-1111-1111-1111-111111111111")
        finally:
            db.close()
            tmp.cleanup()

    def test_weak_skipped_and_deprecated_only(self):
        tmp, db = _db()
        try:
            weak = resolve_candidate(db, _cand(evidence_strength="weak"))
            self.assertEqual(weak["resolution_status"], "skipped_weak")
            self.assertNotIn("cpe_name", weak)
            old = resolve_candidate(db, _cand(product_name="oldthing", version="1.0"))
            self.assertEqual(old["resolution_status"], "deprecated_only")
            self.assertNotIn("vendor", old)
        finally:
            db.close()
            tmp.cleanup()

    def test_invalid_candidate_and_no_alias(self):
        tmp, db = _db()
        try:
            bad = resolve_candidate(db, {"evidence_strength": "strong"})
            self.assertEqual(bad["resolution_status"], "invalid_candidate")
            # MikroTik must not be rewritten to another product.
            alias = resolve_candidate(
                db, _cand(product_name="MikroTik", version="6.49.18", evidence_strength="moderate")
            )
            self.assertEqual(alias["resolution_status"], "no_match")
        finally:
            db.close()
            tmp.cleanup()

    def test_supplied_vendor_is_a_constraint(self):
        tmp, db = _db()
        try:
            found = resolve_candidate(db, _cand(product_name="shared", version="1.0", vendor="acme"))
            self.assertEqual(found["resolution_status"], "exact_match")
            self.assertEqual(found["vendor"], "acme")
            missed = resolve_candidate(db, _cand(product_name="nginx", version="1.24.0", vendor="notf5"))
            self.assertEqual(missed["resolution_status"], "no_match")
        finally:
            db.close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
