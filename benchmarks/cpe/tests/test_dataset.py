import json, tempfile, unittest
from pathlib import Path
from benchmarks.cpe.src.dataset import prepare_pilot_sample, sample, stable_id, validate_gold
from benchmarks.cpe.src.gold import canonical_source_hash

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

    def test_pilot_sample_contains_raw_records_strata_and_malformed_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"input.jsonl"
            doc={"_id":"pilot-1","_source":{"id":"pilot-1","proto":"ssh","path":"/x","ip":"127.0.0.1","scanTime":"1","port":"t22","appId":"x","t22":{"ssh":{"result":{"server_id":{"software":"OpenSSH_9.6p1"}}}}}}
            source.write_bytes((json.dumps(doc)+"\n[]\n{bad\n").encode()+b"\xff\n")
            first=prepare_pilot_sample(source,root/"first.jsonl",10,31)
            second=prepare_pilot_sample(source,root/"second.jsonl",10,31)
            rows=[json.loads(line) for line in (root/"first.jsonl").read_text().splitlines()]
            self.assertEqual(first["sample_records"],1)
            self.assertEqual(first["malformed_json_rows"],2)
            self.assertEqual(first["non_object_rows"],1)
            self.assertEqual(first["protocol_distribution"],second["protocol_distribution"])
            self.assertEqual(rows[0]["record_id"],stable_id(doc,1))
            self.assertEqual(rows[0]["source_hash"],canonical_source_hash(doc))
            self.assertEqual(rows[0]["raw"],doc)
            self.assertIn("candidate_count_stratum",rows[0])
            self.assertNotIn("prediction",rows[0])
    def test_gold_contract(self):
        self.assertIn("missing fields", " ".join(validate_gold({})))
    def test_gold_cpe_must_exist_in_dictionary(self):
        class Dictionary:
            def contains_cpe(self, name): return False
        gold={"record_id":"r","expected_product":"x","expected_vendor":None,"expected_version":"1","expected_update":None,"expected_part":"a","expected_cpe23":"cpe:2.3:a:v:x:1:*:*:*:*:*:*:*","acceptable_cpes":[],"abstain_expected":False,"evidence_paths":["t80.http.result.response"],"adjudication_notes":"reviewed independently","scoring_status":"reviewed"}
        self.assertIn("absent from the local dictionary", " ".join(validate_gold(gold,Dictionary())))
        gold["expected_cpe23"]="cpe:bad"
        self.assertIn("invalid CPE 2.3", " ".join(validate_gold(gold)))

    def test_gold_cpe_membership_does_not_override_identity_mismatch(self):
        class Dictionary:
            def contains_cpe(self, name): return True
        gold={"record_id":"r","expected_product":"ssh-client","expected_vendor":"openbsd","expected_version":"9.6p1","expected_update":None,"expected_part":"a","expected_cpe23":"cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*","acceptable_cpes":[],"abstain_expected":False,"evidence_paths":[],"adjudication_notes":"reviewed","scoring_status":"reviewed"}
        self.assertIn("CPE product does not match expected identity", " ".join(validate_gold(gold, Dictionary())))

    def test_gold_identity_uses_runtime_normalization(self):
        gold={"record_id":"r","expected_product":"Open_SSH","expected_vendor":"OPENBSD","expected_version":"9.6P1","expected_update":"-","expected_part":"A","expected_cpe23":"cpe:2.3:a:openbsd:openssh:9.6p1:-:*:*:*:*:*:*","acceptable_cpes":[],"abstain_expected":False,"evidence_paths":[],"adjudication_notes":"reviewed","scoring_status":"reviewed"}
        self.assertEqual(validate_gold(gold), [])

    def test_gold_requires_product_to_validate_cpe_identity(self):
        gold={"record_id":"r","expected_product":None,"expected_vendor":None,"expected_version":None,"expected_update":None,"expected_part":None,"expected_cpe23":"cpe:2.3:a:v:x:1:*:*:*:*:*:*:*","acceptable_cpes":[],"abstain_expected":False,"evidence_paths":[],"adjudication_notes":"reviewed","scoring_status":"reviewed"}
        self.assertIn("expected_product is required", " ".join(validate_gold(gold)))

if __name__=="__main__": unittest.main()
