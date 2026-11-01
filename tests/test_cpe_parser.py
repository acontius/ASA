"""CPE 2.3 parser tests."""

from __future__ import annotations

import unittest

from app.cpe.parser import CpeParseError, parse_cpe23


class TestCpeParser(unittest.TestCase):
    def test_valid_components(self):
        parsed = parse_cpe23("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
        self.assertEqual(parsed.part, "a")
        self.assertEqual(parsed.vendor, "f5")
        self.assertEqual(parsed.product, "nginx")
        self.assertEqual(parsed.version, "1.24.0")
        self.assertEqual(parsed.value_classes["version"], "concrete")
        self.assertEqual(parsed.value_classes["update"], "any")
        self.assertTrue(parsed.is_concrete("product"))

    def test_escaped_colon_and_backslash(self):
        parsed = parse_cpe23(r"cpe:2.3:a:vendor:prod\:name:1.0:*:*:*:*:*:*:*")
        self.assertEqual(parsed.product, "prod:name")
        parsed_bs = parse_cpe23(r"cpe:2.3:a:vendor:prod\\name:1.0:*:*:*:*:*:*:*")
        self.assertEqual(parsed_bs.product, "prod\\name")

    def test_not_applicable_and_embedded_wildcard(self):
        parsed = parse_cpe23("cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*")
        self.assertEqual(parsed.value_classes["version"], "na")
        wild = parse_cpe23("cpe:2.3:a:vendor:product:1.*:*:*:*:*:*:*:*")
        self.assertEqual(wild.value_classes["version"], "wildcard")
        self.assertFalse(wild.is_concrete("version"))

    def test_rejects_malformed(self):
        with self.assertRaises(CpeParseError):
            parse_cpe23("not-a-cpe")
        with self.assertRaises(CpeParseError):
            parse_cpe23("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*")
        with self.assertRaises(CpeParseError):
            parse_cpe23(r"cpe:2.3:a:vendor:product\:1.0:*:*:*:*:*:*:*")
        with self.assertRaises(CpeParseError):
            parse_cpe23("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*\\")
        with self.assertRaises(CpeParseError):
            parse_cpe23("cpe:2.3:z:vendor:product:1.0:*:*:*:*:*:*:*")


if __name__ == "__main__":
    unittest.main()
