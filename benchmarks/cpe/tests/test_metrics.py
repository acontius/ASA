import unittest
from benchmarks.cpe.src.metrics import prf, evaluate

class MetricsTests(unittest.TestCase):
    def test_prf(self): self.assertEqual(prf(1,1,1),{"precision":.5,"recall":.5,"f1":.5})
    def test_ambiguous_accepts_alternative(self):
        gold={"r":{"scoring_status":"ambiguous","expected_product":"x","expected_cpe23":None,"acceptable_cpes":["cpe:2.3:a:v:x:1:*:*:*:*:*:*:*"],"abstain_expected":False}}
        row={"record_id":"r","prediction":{"product_name":"x","vendor":None,"version":None,"update":None,"part":None,"cpe_candidates":["cpe:2.3:a:v:x:1:*:*:*:*:*:*:*"],"abstain":False},"dictionary_cpes":["cpe:2.3:a:v:x:1:*:*:*:*:*:*:*"]}
        self.assertEqual(evaluate([row],gold)["exact_cpe_accuracy"],1)

    def test_direct_m3_final_resolution_is_exact_cpe_metric_input(self):
        cpe="cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"
        gold={"r":{"scoring_status":"reviewed","expected_product":"OpenSSH","expected_vendor":"openbsd","expected_version":"9.6p1","expected_cpe23":cpe,"acceptable_cpes":[],"abstain_expected":False}}
        row={"record_id":"r","evaluation_track":"extraction_only+end_to_end_cpe","extraction_prediction":{"product_name":"Open_SSH","vendor":"OPENBSD","version":"9.6P1","abstain":False,"cpe_candidates":[]},"prediction":{"product_name":"OpenSSH","cpe_candidates":[]},"final_cpe_resolutions":[{"cpe23":cpe,"identity_valid":True,"resolution_status":"review_required"}],"dictionary_cpes":[cpe]}
        result=evaluate([row],gold)
        self.assertEqual(result["evaluation_tracks"]["end_to_end_cpe"]["exact_cpe_accuracy"],1)
        self.assertEqual(result["evaluation_tracks"]["extraction_only"]["product_name_metrics"]["f1"],1)

    def test_model_proposed_cpe_is_not_used_as_direct_final_result(self):
        cpe="cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"
        gold={"r":{"scoring_status":"reviewed","expected_product":"OpenSSH","expected_cpe23":cpe,"acceptable_cpes":[],"abstain_expected":False}}
        row={"record_id":"r","prediction":{"product_name":"OpenSSH","cpe_candidates":[cpe],"abstain":False},"final_cpe_resolutions":[],"dictionary_cpes":[cpe]}
        self.assertEqual(evaluate([row],gold)["exact_cpe_accuracy"],0)

    def test_explicit_abstention_is_separate_from_missing_prediction(self):
        gold={"a":{"scoring_status":"reviewed","expected_product":None,"abstain_expected":True}}
        abstain={"record_id":"a","prediction":{"abstain":True},"extraction_predictions":[]}
        missing={"record_id":"a","prediction":None,"status":"error"}
        a=evaluate([abstain],gold)["evaluation_tracks"]["extraction_only"]["abstentions"]
        b=evaluate([missing],gold)["evaluation_tracks"]["extraction_only"]["abstentions"]
        self.assertEqual((a,b),(1,0))

if __name__=="__main__": unittest.main()
