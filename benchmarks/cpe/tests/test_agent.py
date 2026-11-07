import unittest
from unittest.mock import patch
from benchmarks.cpe.src.agent import run_agent

class FakeLookup:
    calls=0
    def lookup(self, product, version=None, vendor=None):
        self.calls+=1
        return [{"cpe_name":"cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"}]

class AgentTests(unittest.TestCase):
    def test_one_model_call_budget_abstains_after_lookup(self):
        first={"product_name":"OpenSSH","vendor":None,"version":"9.6p1","update":None,"part":None,"cpe_candidates":[],"evidence_paths":["t22.ssh.result.server_id.software"],"abstain":True,"explanation":"identified"}
        with patch("benchmarks.cpe.src.agent.call_local",return_value={"parsed":first,"schema_valid":True,"latency_seconds":.1}):
            response=run_agent({},"r","qwen",FakeLookup(),"http://127.0.0.1:8080",max_model_calls=1)
        self.assertEqual(response["model_calls"],1); self.assertEqual(response["tool_calls"],1); self.assertTrue(response["parsed"]["abstain"])

if __name__=="__main__": unittest.main()
