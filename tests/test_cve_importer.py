"""CVE 2.0 importer tests. Fixtures are synthetic."""

from __future__ import annotations

import gzip
import json
import sqlite3
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import FIXTURES

from app.vulnerability.cve_importer import import_cves
from app.vulnerability.feedio import FeedFormatError


def _cve(cve_id: str, **extra) -> dict:
    body = {
        "id": cve_id,
        "sourceIdentifier": "cve@example.invalid",
        "published": "2026-01-01T00:00:00.000",
        "lastModified": "2026-01-02T00:00:00.000",
        "vulnStatus": extra.pop("vulnStatus", "Analyzed"),
        "descriptions": extra.pop("descriptions", [{"lang": "en", "value": "Synthetic"}]),
        "metrics": extra.pop("metrics", {}),
        "weaknesses": extra.pop("weaknesses", []),
        "references": extra.pop("references", []),
        "configurations": extra.pop("configurations", []),
    }
    body.update(extra)
    return {"format": "NVD_CVE", "version": "2.0", "timestamp": "2026-01-01T00:00:00.000", "vulnerabilities": [{"cve": body}]}


def _write(path: Path, doc: dict) -> None:
    path.write_text(json.dumps(doc), encoding="utf-8")


class TestCveImporter(unittest.TestCase):
    def test_valid_feed_preserves_descriptions_metrics_and_rejected_status(self):
        with TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "intel.sqlite")
            stats = import_cves(str(FIXTURES / "cve_feed_sample.json"), db)
            self.assertEqual(stats.files, 1)
            self.assertEqual(stats.inserted, 7)
            self.assertEqual(stats.rejected, 1)
            self.assertEqual(stats.schema_version, "2.0")
            conn = sqlite3.connect(db)
            row = conn.execute("SELECT * FROM cve_entries WHERE cve_id = 'CVE-2026-9001'").fetchone()
            descriptions = json.loads(row[5])
            metrics = json.loads(row[6])
            self.assertEqual([item["lang"] for item in descriptions], ["en", "es"])
            self.assertEqual(metrics["cvssMetricV2"][0]["cvssData"]["version"], "2.0")
            self.assertEqual(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"], 5.0)
            self.assertEqual(metrics["cvssMetricV31"][0]["cvssData"]["version"], "3.1")
            self.assertEqual(metrics["cvssMetricV31"][0]["source"], "nvd@nist.gov")
            self.assertEqual(metrics["cvssMetricV40"][0]["cvssData"]["version"], "4.0")
            self.assertEqual(metrics["cvssMetricV40"][0]["source"], "cna@example.invalid")
            self.assertEqual(row[1], "cve@example.invalid")
            self.assertEqual(row[2], "2026-02-01T00:00:00.000")
            rejected = conn.execute("SELECT vuln_status FROM cve_entries WHERE cve_id = 'CVE-2026-9004'").fetchone()
            self.assertEqual(rejected[0], "Rejected")
            criteria = conn.execute("SELECT match_criteria_id FROM cve_criteria WHERE cve_id = 'CVE-2026-9005' ORDER BY 1").fetchall()
            self.assertEqual([item[0] for item in criteria], ["CRIT-NGINX", "CRIT-SSH"])
            index = conn.execute("SELECT name FROM sqlite_master WHERE name = 'idx_cve_criteria_mid'").fetchone()
            self.assertIsNotNone(index)
            conn.close()

    def test_missing_descriptions_are_stored_empty(self):
        doc = _cve("CVE-2026-1")
        doc["vulnerabilities"][0]["cve"].pop("descriptions")
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            db = str(Path(tmp) / "intel.sqlite")
            _write(path, doc)
            stats = import_cves(str(path), db)
            self.assertEqual(stats.inserted, 1)
            conn = sqlite3.connect(db)
            raw = conn.execute("SELECT descriptions_json FROM cve_entries").fetchone()[0]
            conn.close()
            self.assertEqual(json.loads(raw), [])

    def test_wrong_schema_version(self):
        doc = _cve("CVE-2026-1")
        doc["version"] = "1.1"
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            _write(path, doc)
            with self.assertRaises(FeedFormatError):
                import_cves(str(path), str(Path(tmp) / "intel.sqlite"))

    def test_missing_vulnerabilities_array(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            path.write_text('{"format":"NVD_CVE","version":"2.0","timestamp":"t"}', encoding="utf-8")
            with self.assertRaises(FeedFormatError):
                import_cves(str(path), str(Path(tmp) / "intel.sqlite"))

    def test_invalid_records_are_skipped(self):
        doc = _cve("CVE-2026-1")
        doc["vulnerabilities"].append({"cve": {"id": "not-a-cve"}})
        doc["vulnerabilities"].append({"nope": True})
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            _write(path, doc)
            stats = import_cves(str(path), str(Path(tmp) / "intel.sqlite"))
            self.assertEqual(stats.inserted, 1)
            self.assertEqual(stats.invalid, 2)

    def test_duplicate_ids_and_reimport_are_idempotent(self):
        doc = _cve("CVE-2026-1")
        doc["vulnerabilities"].append(doc["vulnerabilities"][0])
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            db = str(Path(tmp) / "intel.sqlite")
            _write(path, doc)
            first = import_cves(str(path), db)
            self.assertEqual(first.inserted, 1)
            self.assertEqual(first.updated, 1)
            second = import_cves(str(path), db)
            self.assertEqual(second.inserted, 0)
            self.assertEqual(second.updated, 2)
            conn = sqlite3.connect(db)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0], 1)
            conn.close()

    def test_modified_feed_updates_existing_cve(self):
        with TemporaryDirectory() as tmp:
            first = Path(tmp) / "yearly.json"
            modified = Path(tmp) / "nvdcve-2.0-modified.json"
            db = str(Path(tmp) / "intel.sqlite")
            _write(first, _cve("CVE-2026-1", descriptions=[{"lang": "en", "value": "old"}]))
            changed = _cve(
                "CVE-2026-1",
                descriptions=[{"lang": "en", "value": "new"}],
                lastModified="2026-03-01T00:00:00.000",
            )
            _write(modified, changed)
            import_cves(str(first), db, kind="initial")
            stats = import_cves(str(modified), db)
            self.assertEqual(stats.import_type, "incremental")
            self.assertFalse(stats.incomplete)
            self.assertEqual(stats.updated, 1)
            conn = sqlite3.connect(db)
            row = conn.execute("SELECT descriptions_json, last_modified FROM cve_entries").fetchone()
            self.assertEqual(json.loads(row[0])[0]["value"], "new")
            self.assertEqual(row[1], "2026-03-01T00:00:00.000")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0], 1)
            conn.close()

    def test_incremental_import_into_empty_database_warns(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "modified" / "feed.json"
            path.parent.mkdir()
            _write(path, _cve("CVE-2026-1"))
            stats = import_cves(str(path.parent), str(Path(tmp) / "intel.sqlite"))
            self.assertTrue(stats.incomplete)
            self.assertIn("incomplete", stats.warnings[0])
            conn = sqlite3.connect(str(Path(tmp) / "intel.sqlite"))
            flag = conn.execute("SELECT incomplete_cve_import FROM feed_metadata").fetchone()[0]
            conn.close()
            self.assertEqual(flag, 1)

    def test_invalid_json(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(FeedFormatError):
                import_cves(str(path), str(Path(tmp) / "intel.sqlite"))

    def test_gzip_and_zip_packaging(self):
        doc = _cve("CVE-2026-9")
        with TemporaryDirectory() as tmp:
            gz_path = Path(tmp) / "feed.json.gz"
            with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
                json.dump(doc, handle)
            zip_path = Path(tmp) / "feed.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("chunk-a.json", json.dumps(_cve("CVE-2026-8")))
                archive.writestr("chunk-b.json.gz", gzip.compress(json.dumps(_cve("CVE-2026-7")).encode()))
            db = str(Path(tmp) / "intel.sqlite")
            import_cves(str(gz_path), db)
            import_cves(str(zip_path), db)
            conn = sqlite3.connect(db)
            ids = {row[0] for row in conn.execute("SELECT cve_id FROM cve_entries")}
            conn.close()
            self.assertEqual(ids, {"CVE-2026-9", "CVE-2026-8", "CVE-2026-7"})

    def test_transaction_rollback_keeps_previous_file(self):
        with TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.json"
            bad = Path(tmp) / "bad.json"
            db = str(Path(tmp) / "intel.sqlite")
            _write(good, _cve("CVE-2026-1"))
            bad.write_text(
                '{"format":"NVD_CVE","version":"2.0","timestamp":"t","vulnerabilities":[{"cve":{"id":"CVE-2026-2","descriptions":[],"metrics":{},"weaknesses":[],"references":[],"configurations":[]}},{',
                encoding="utf-8",
            )
            import_cves(str(good), db)
            with self.assertRaises(FeedFormatError):
                import_cves(str(bad), db)
            conn = sqlite3.connect(db)
            ids = [row[0] for row in conn.execute("SELECT cve_id FROM cve_entries")]
            conn.close()
            self.assertEqual(ids, ["CVE-2026-1"])

    def test_meta_checksum_mismatch_does_not_import(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            _write(path, _cve("CVE-2026-1"))
            path.with_suffix(".meta").write_text("sha256:0000\n", encoding="utf-8")
            with self.assertRaises(FeedFormatError):
                import_cves(str(path), str(Path(tmp) / "intel.sqlite"))
            self.assertFalse(Path(tmp, "intel.sqlite").exists() and _count(Path(tmp) / "intel.sqlite"))

    def test_directory_of_chunks_and_large_stream(self):
        with TemporaryDirectory() as tmp:
            folder = Path(tmp) / "yearly"
            folder.mkdir()
            _write(folder / "a.json", _cve("CVE-2026-1"))
            vulnerabilities = []
            for index in range(400):
                vulnerabilities.append(
                    {
                        "cve": {
                            "id": f"CVE-2099-{index:04d}",
                            "vulnStatus": "Awaiting Analysis",
                            "descriptions": [{"lang": "en", "value": "synthetic " + ("x" * 180)}],
                            "metrics": {},
                            "weaknesses": [],
                            "references": [],
                            "configurations": [],
                        }
                    }
                )
            payload = {"format": "NVD_CVE", "version": "2.0", "timestamp": "t", "vulnerabilities": vulnerabilities}
            with gzip.open(folder / "b.json.gz", "wt", encoding="utf-8") as handle:
                json.dump(payload, handle)
            stats = import_cves(str(folder), str(Path(tmp) / "intel.sqlite"), kind="initial")
            self.assertEqual(stats.inserted, 401)
            self.assertFalse(stats.incomplete)


def _count(path: Path) -> int:
    if not path.exists():
        return 0
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    unittest.main()
