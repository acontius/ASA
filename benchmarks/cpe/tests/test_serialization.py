import unittest
from benchmarks.cpe.src.runner import cpe_identity_matches, parse_cpe23, serialize_result

class SerializationTests(unittest.TestCase):
    def test_runner_imports_cpe_parser_for_prediction_path(self):
        parsed = parse_cpe23("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")
        self.assertEqual(parsed.product, "openssh")

    def test_dictionary_identity_must_match_extraction(self):
        name = "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"
        self.assertTrue(cpe_identity_matches(name, {"product_name": "OpenSSH", "vendor": "openbsd", "version": "9.6p1"}))
        self.assertFalse(cpe_identity_matches(name, {"product_name": "OpenSSH", "vendor": "microsoft", "version": "9.6p1"}))
        self.assertFalse(cpe_identity_matches(name, {"product_name": "OpenSSH", "version": "9.6"}))

    def test_jsonl_serialization_is_stable(self):
        row={"z":1,"unicode":"محلی","a":{"b":2}}
        self.assertEqual(serialize_result(row),serialize_result(row))
        self.assertEqual(serialize_result(row),'{"a":{"b":2},"unicode":"محلی","z":1}')

if __name__=="__main__": unittest.main()
