import json, tempfile, unittest
from pathlib import Path
from benchmarks.cpe.src.cpe_lookup import ReadOnlyCpeLookup

class LookupTests(unittest.TestCase):
    def test_read_only_chunks_and_limit(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.json"; p.write_text(json.dumps({"version":"2.0","products":[{"cpe":{"cpeName":"cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*","cpeNameId":"x","deprecated":False}}]}))
            tool=ReadOnlyCpeLookup(chunks_path=d,max_calls=1)
            self.assertEqual(len(tool.lookup("OpenSSH","9.6p1")),1)
            with self.assertRaises(RuntimeError): tool.lookup("OpenSSH")

if __name__=="__main__": unittest.main()
