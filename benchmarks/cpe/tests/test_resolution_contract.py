import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from benchmarks.cpe.src.identity import compare_cpe_identity
from benchmarks.cpe.src.runner import _deterministic_contract, _resolve_direct_identity


class ResolutionContractTests(unittest.TestCase):
    def test_multiple_candidates_keep_candidate_identity_and_associated_cpe(self):
        candidates = [
            {"candidate_id":"a1","source_path":"t21.ftp.banner","product_name":"vsftpd","vendor":"vsftpd","version":"3.0.5","evidence_strength":"strong"},
            {"candidate_id":"a2","source_path":"t80.http.server","product_name":"nginx","vendor":"f5","version":"1.24.0","evidence_strength":"strong"},
        ]
        resolutions = [
            {"candidate_id":"a1","resolution_status":"exact_match","resolution_basis":"exact_product_and_version","cpe_name":"cpe:2.3:a:vsftpd:vsftpd:3.0.5:*:*:*:*:*:*:*"},
            {"candidate_id":"a2","resolution_status":"exact_match","resolution_basis":"exact_product_and_version","cpe_name":"cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"},
        ]
        extractions, final = _deterministic_contract(candidates, resolutions)
        self.assertEqual([x["candidate_id"] for x in extractions], ["a1", "a2"])
        self.assertEqual([x["candidate_id"] for x in final], ["a1", "a2"])
        self.assertEqual([x["extracted_identity"]["product_name"] for x in final], ["vsftpd", "nginx"])
        self.assertEqual([x["identity_valid"] for x in final], [True, True])

    def test_all_resolution_statuses_are_preserved(self):
        candidates = [{"candidate_id":f"c{i}","source_path":f"path{i}","product_name":"x","vendor":None,"version":None} for i in range(3)]
        statuses = ["no_match", "skipped_weak", "ambiguous"]
        resolutions = [{"resolution_status":s,"resolution_basis":"test","cpe_name":None} for s in statuses]
        _, final = _deterministic_contract(candidates, resolutions)
        self.assertEqual([x["resolution_status"] for x in final], statuses)
        self.assertTrue(all(x["cpe23"] is None for x in final))

    def test_candidate_and_resolution_cardinality_must_match(self):
        with self.assertRaises(ValueError):
            _deterministic_contract([{"candidate_id":"x"}], [{}, {}])

    def test_missing_dictionary_is_explicit_per_candidate(self):
        _, final = _deterministic_contract([{"candidate_id":"x","product_name":"x"}], [])
        self.assertEqual(final[0]["resolution_status"], "unavailable")

    def test_direct_abstention_skips_m3(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dictionary.sqlite"
            path.touch()
            with patch("benchmarks.cpe.src.runner.sqlite3.connect") as connect:
                candidate, resolution = _resolve_direct_identity({"product_name":"OpenSSH","abstain":True}, "r", path)
        self.assertIsNone(candidate)
        self.assertIsNone(resolution)
        connect.assert_not_called()

    def test_direct_sqlite_connection_is_explicitly_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dictionary.sqlite"
            path.touch()
            connection = Mock()
            with patch("benchmarks.cpe.src.runner.sqlite3.connect", return_value=connection), patch("benchmarks.cpe.src.runner.resolve_candidate", return_value={"resolution_status":"no_match","resolution_basis":"product"}):
                _resolve_direct_identity({"product_name":"OpenSSH","version":"9.6","abstain":False,"evidence_paths":["t22.ssh.server"]}, "r", path)
        connection.close.assert_called_once()

    def test_gold_and_runtime_share_normalization_and_optional_wildcard_rules(self):
        identity = {"product_name":"Open_SSH", "vendor":"OPENBSD", "version":"9.6P1", "update":"-", "part":"A"}
        cpe = "cpe:2.3:a:openbsd:openssh:9.6p1:-:*:*:*:*:*:*"
        self.assertTrue(compare_cpe_identity(cpe, identity)["valid"])
        optional = "cpe:2.3:a:*:openssh:*:*:*:*:*:*:*:*"
        self.assertTrue(compare_cpe_identity(optional, {"product_name":"OpenSSH", "vendor":None, "version":None, "update":None, "part":"a"})["valid"])
        self.assertFalse(compare_cpe_identity(optional, {"product_name":"OpenSSH", "vendor":"openbsd", "version":"9.6", "part":"a"})["valid"])


if __name__ == "__main__":
    unittest.main()
