"""Protocol extractor tests."""

from __future__ import annotations

import copy
import json
import unittest

from tests.helpers import load_fixture

from app.extractors.ftp import extract_ftp
from app.extractors.http import extract_http
from app.extractors.mongodb import extract_mongodb
from app.extractors.ssh import extract_ssh
from app.ingestion.normalizer import normalize


def _norm(name: str):
    return normalize(load_fixture(name), line_number=1, byte_offset=0)


def _ssh_software(software: str, *, comment: str | None = None, raw: str | None = None):
    doc = load_fixture("ssh")
    server_id = doc["_source"]["t22"]["ssh"]["result"]["server_id"]
    server_id["software"] = software
    if comment is None:
        server_id.pop("comment", None)
    else:
        server_id["comment"] = comment
    if raw is None:
        server_id.pop("raw", None)
    else:
        server_id["raw"] = raw
    record = normalize(doc, line_number=1, byte_offset=0)
    return extract_ssh(record, record["port_blocks"][0])


class TestSSH(unittest.TestCase):
    def test_software_not_protocol_version(self):
        record = _norm("ssh")
        found = extract_ssh(record, record["port_blocks"][0])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["product_name"], "OpenSSH")
        self.assertEqual(found[0]["version"], "9.6")
        self.assertEqual(found[0]["update"], "p1")
        self.assertNotEqual(found[0]["version"], "2.0")
        self.assertNotIn("Ubuntu", found[0]["version"])
        self.assertNotIn("ubuntu", (found[0]["update"] or "").casefold())
        self.assertEqual(found[0]["evidence_strength"], "strong")
        self.assertIsNone(found[0]["vendor"])
        self.assertIsNone(found[0]["part"])
        self.assertEqual(found[0]["raw_value"], "OpenSSH_9.6p1")
        self.assertEqual(found[0]["source_path"], "t22.ssh.result.server_id.software")
        self.assertIn("server_id.software", found[0]["evidence_refs"])
        self.assertIn("server_id.raw", found[0]["evidence_refs"])
        self.assertIn("server_id.comment", found[0]["evidence_refs"])
        self.assertIn('"update": "p1"', json.dumps(found[0]))

    def test_openssh_portable_release_cases(self):
        cases = {
            "OpenSSH_9.6p1": ("OpenSSH", "9.6", "p1"),
            "OpenSSH_9.6p2": ("OpenSSH", "9.6", "p2"),
            "OpenSSH_9.6": ("OpenSSH", "9.6", None),
            "OpenSSH_8.9p1": ("OpenSSH", "8.9", "p1"),
            "openssh_7.4": ("openssh", "7.4", None),
            "OpenSSH_9.6p1 Ubuntu-3ubuntu13.11": ("OpenSSH", "9.6", "p1"),
        }
        for software, expected in cases.items():
            with self.subTest(software=software):
                found = _ssh_software(software)
                self.assertEqual(len(found), 1)
                product, version, update = expected
                self.assertEqual(found[0]["product_name"], product)
                self.assertEqual(found[0]["version"], version)
                self.assertEqual(found[0]["update"], update)

    def test_ubuntu_revision_stays_in_evidence_only(self):
        found = _ssh_software(
            "OpenSSH_9.6p1",
            comment="Ubuntu-3ubuntu13.11",
            raw="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.11",
        )
        self.assertEqual(found[0]["version"], "9.6")
        self.assertEqual(found[0]["update"], "p1")
        self.assertNotIn("Ubuntu", found[0]["version"] or "")
        self.assertNotIn("ubuntu", (found[0]["update"] or "").casefold())
        self.assertIn("server_id.comment", found[0]["evidence_refs"])
        self.assertTrue(
            any(ref.startswith("package_revision=") for ref in found[0]["evidence_refs"])
            or "server_id.comment" in found[0]["evidence_refs"]
        )

    def test_missing_software_uses_comment_as_weak(self):
        doc = load_fixture("ssh")
        doc["_source"]["t22"]["ssh"]["result"]["server_id"].pop("software")
        record = normalize(doc, line_number=1, byte_offset=0)
        found = extract_ssh(record, record["port_blocks"][0])
        self.assertEqual(found[0]["evidence_strength"], "weak")
        self.assertEqual(found[0]["signal_type"], "comment")

    def test_unparsed_software_is_moderate_raw(self):
        doc = load_fixture("ssh")
        doc["_source"]["t22"]["ssh"]["result"]["server_id"]["software"] = "SSHDaemon"
        record = normalize(doc, line_number=1, byte_offset=0)
        found = extract_ssh(record, record["port_blocks"][0])
        self.assertEqual(found[0]["product_name"], "SSHDaemon")
        self.assertIsNone(found[0]["version"])
        self.assertEqual(found[0]["evidence_strength"], "moderate")

    def test_missing_server_id(self):
        doc = load_fixture("ssh")
        doc["_source"]["t22"]["ssh"]["result"] = {}
        record = normalize(doc, line_number=1, byte_offset=0)
        self.assertEqual(extract_ssh(record, record["port_blocks"][0]), [])

    def test_non_openssh_keeps_version_token_intact(self):
        found = _ssh_software("Dropbear_2020.81")
        self.assertEqual(found[0]["product_name"], "Dropbear")
        self.assertEqual(found[0]["version"], "2020.81")
        self.assertIsNone(found[0]["update"])


class TestHTTP(unittest.TestCase):
    def test_versioned_server_header(self):
        record = _norm("http")
        found = extract_http(record, record["port_blocks"][0])
        self.assertEqual(found[0]["product_name"], "nginx")
        self.assertEqual(found[0]["version"], "1.24.0")
        self.assertEqual(found[0]["evidence_strength"], "strong")

    def test_header_case_and_weak_generic(self):
        doc = load_fixture("http")
        doc["_source"]["t80"]["http"]["result"]["response"]["headers"] = {"Server": "WAF"}
        record = normalize(doc, line_number=1, byte_offset=0)
        found = extract_http(record, record["port_blocks"][0])
        self.assertEqual(found[0]["evidence_strength"], "weak")
        self.assertEqual(found[0]["raw_value"], "WAF")

    def test_generic_web_server_tokens_are_not_software_identities(self):
        for value in ("Web/0.9", "WebServer 1.0"):
            with self.subTest(value=value):
                doc = load_fixture("http")
                doc["_source"]["t80"]["http"]["result"]["response"]["headers"] = {"server": value}
                record = normalize(doc, line_number=1, byte_offset=0)
                found = extract_http(record, record["port_blocks"][0])
                self.assertEqual(found[0]["evidence_strength"], "weak")
                self.assertIsNone(found[0]["version"])
                self.assertNotEqual(found[0]["product_name"], "Web")

    def test_redirect_chain_when_final_is_generic(self):
        doc = load_fixture("http")
        doc["_source"]["t80"]["http"]["result"]["response"]["headers"] = {"server": "WAF"}
        doc["_source"]["t80"]["http"]["result"]["redirect_response_chain"] = [
            {"headers": {"Server": "Apache/2.4.52 (Ubuntu)"}}
        ]
        record = normalize(doc, line_number=1, byte_offset=0)
        found = extract_http(record, record["port_blocks"][0])
        products = {item["product_name"] for item in found}
        self.assertIn("Apache", products)

    def test_missing_response(self):
        doc = load_fixture("http")
        doc["_source"]["t80"]["http"]["result"] = {}
        record = normalize(doc, line_number=1, byte_offset=0)
        self.assertEqual(extract_http(record, record["port_blocks"][0]), [])


class TestFTP(unittest.TestCase):
    def test_mikrotik_is_device_not_daemon(self):
        record = _norm("ftp")
        found = extract_ftp(record, record["port_blocks"][0])
        self.assertEqual(found[0]["product_name"], "MikroTik")
        self.assertEqual(found[0]["version"], "6.49.18")
        self.assertIn("device_firmware", found[0]["evidence_refs"])
        self.assertNotEqual(found[0]["product_name"].lower(), "ftp")

    def test_vsftpd_and_ambiguous(self):
        doc = load_fixture("ftp")
        doc["_source"]["t21"]["ftp"]["result"]["banner"] = "220 (vsFTPd 3.0.5)"
        record = normalize(doc, line_number=1, byte_offset=0)
        found = extract_ftp(record, record["port_blocks"][0])
        self.assertEqual(found[0]["product_name"], "vsFTPd")
        self.assertEqual(found[0]["version"], "3.0.5")
        self.assertEqual(found[0]["evidence_strength"], "strong")

        doc2 = load_fixture("ftp")
        doc2["_source"]["t21"]["ftp"]["result"]["banner"] = "220 FTP server (203.0.113.5) ready."
        record2 = normalize(doc2, line_number=1, byte_offset=0)
        weak = extract_ftp(record2, record2["port_blocks"][0])
        self.assertEqual(weak[0]["evidence_strength"], "weak")

    def test_missing_banner(self):
        doc = load_fixture("ftp")
        doc["_source"]["t21"]["ftp"]["result"] = {}
        record = normalize(doc, line_number=1, byte_offset=0)
        self.assertEqual(extract_ftp(record, record["port_blocks"][0]), [])


class TestMongo(unittest.TestCase):
    def test_structured_version_and_os_hint(self):
        record = _norm("mongodb")
        found = extract_mongodb(record, record["port_blocks"][0])
        self.assertEqual(found[0]["product_name"], "MongoDB")
        self.assertEqual(found[0]["version"], "7.0.12")
        self.assertTrue(any(ref.startswith("target_os=") for ref in found[0]["evidence_refs"]))

    def test_missing_build_info(self):
        doc = load_fixture("mongodb")
        doc["_source"]["t27017"]["mongodb"]["result"] = {"is_master": {}}
        record = normalize(doc, line_number=1, byte_offset=0)
        self.assertEqual(extract_mongodb(record, record["port_blocks"][0]), [])

    def test_version_array_fallback(self):
        doc = copy.deepcopy(load_fixture("mongodb"))
        info = doc["_source"]["t27017"]["mongodb"]["result"]["build_info"]
        del info["version"]
        record = normalize(doc, line_number=1, byte_offset=0)
        found = extract_mongodb(record, record["port_blocks"][0])
        self.assertEqual(found[0]["version"], "7.0.12")


if __name__ == "__main__":
    unittest.main()
