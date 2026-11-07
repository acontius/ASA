import unittest
from benchmarks.cpe.src.metrics import prf, evaluate

class MetricsTests(unittest.TestCase):
    def test_prf(self): self.assertEqual(prf(1,1,1),{"precision":.5,"recall":.5,"f1":.5})
    def test_ambiguous_accepts_alternative(self):
        gold={"r":{"scoring_status":"ambiguous","expected_product":"x","expected_cpe23":None,"acceptable_cpes":["cpe:2.3:a:v:x:1:*:*:*:*:*:*:*"],"abstain_expected":False}}
        row={"record_id":"r","prediction":{"product_name":"x","vendor":None,"version":None,"update":None,"part":None,"cpe_candidates":["cpe:2.3:a:v:x:1:*:*:*:*:*:*:*"],"abstain":False},"dictionary_cpes":["cpe:2.3:a:v:x:1:*:*:*:*:*:*:*"]}
        self.assertEqual(evaluate([row],gold)["exact_cpe_accuracy"],1)

if __name__=="__main__": unittest.main()
