import json, tempfile, unittest
from pathlib import Path
from benchmarks.cpe.src.dataset import sample, validate_gold

class DatasetTests(unittest.TestCase):
    def test_sampling_is_reproducible_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/"in.jsonl"; out=Path(d)/"out.jsonl"
            docs=[]
            for proto in ("ssh","http","ftp","mongodb"):
                for n in range(3): docs.append({"_id":f"{proto}{n}","_source":{"proto":proto,"path":"/x","ip":"127.0.0.1","scanTime":"1","port":"t22","appId":"x","t22":{proto:{"result":{"server":"x/1.0"}}}}})
            src.write_text("".join(json.dumps(x)+"\n" for x in docs))
            a=sample(src,out,8,7); b=sample(src,out,8,7)
            with out.open() as f: count=len(f.readlines())
            self.assertEqual([x["record_id"] for x in a],[x["record_id"] for x in b]); self.assertEqual(count,8)
    def test_gold_contract(self):
        self.assertIn("missing fields", " ".join(validate_gold({})))
    def test_gold_cpe_must_exist_in_dictionary(self):
        class Dictionary:
            def contains_cpe(self, name): return False
        gold={"record_id":"r","expected_product":"x","expected_vendor":None,"expected_version":"1","expected_update":None,"expected_part":"a","expected_cpe23":"cpe:2.3:a:v:x:1:*:*:*:*:*:*:*","acceptable_cpes":[],"abstain_expected":False,"evidence_paths":["t80.http.result.response"],"adjudication_notes":"reviewed independently","scoring_status":"reviewed"}
        self.assertIn("absent from the local dictionary", " ".join(validate_gold(gold,Dictionary())))
        gold["expected_cpe23"]="cpe:bad"
        self.assertIn("invalid CPE 2.3", " ".join(validate_gold(gold)))

if __name__=="__main__": unittest.main()
