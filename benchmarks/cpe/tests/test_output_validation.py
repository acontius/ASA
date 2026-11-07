import json, unittest
from benchmarks.cpe.src.llm_direct import FIELDS, validate_output

class OutputTests(unittest.TestCase):
    def valid(self): return {"product_name":"OpenSSH","vendor":None,"version":"9.6p1","update":None,"part":None,"cpe_candidates":[],"evidence_paths":["t22.ssh.result.server_id.software"],"abstain":True,"explanation":"evidence"}
    def test_invalid_json(self): self.assertEqual(validate_output("not json")[1],"invalid_json")
    def test_missing_local_server_is_reported(self):
        from benchmarks.cpe.src.llm_direct import call_local
        self.assertEqual(call_local({},"qwen","http://127.0.0.1:1/v1/chat/completions")["error"],"URLError")
    def test_extra_and_missing_fields(self):
        x=self.valid(); x["extra"]=1; self.assertEqual(validate_output(json.dumps(x))[1],"schema_fields")
        x=self.valid(); del x["vendor"]; self.assertEqual(validate_output(json.dumps(x))[1],"schema_fields")
    def test_duplicate_json_key_is_invalid(self):
        self.assertEqual(validate_output('{"product_name":null,"product_name":"x"}')[1],"invalid_json")
    def test_hallucinated_cpe_rejected(self):
        x=self.valid(); x["cpe_candidates"]=["cpe:2.3:a:madeup:thing:1:*:*:*:*:*:*:*"]
        parsed,err,ok=validate_output(json.dumps(x),set())
        self.assertEqual(err,"hallucinated_cpe_rejected"); self.assertTrue(parsed["abstain"]); self.assertEqual(parsed["cpe_candidates"],[]); self.assertTrue(ok)

if __name__=="__main__": unittest.main()
