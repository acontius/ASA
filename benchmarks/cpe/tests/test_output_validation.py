import json, unittest
from unittest.mock import patch
from benchmarks.cpe.src.llm_direct import AGENT_FINAL_SYSTEM, FIELDS, SYSTEM, call_local, validate_output

class OutputTests(unittest.TestCase):
    def test_direct_prompt_is_extraction_only(self):
        self.assertIn("cpe_candidates must be an empty list", SYSTEM)
        self.assertIn("Do not propose or invent a CPE", SYSTEM)

    def test_agent_prompt_allows_only_dictionary_returned_candidates(self):
        self.assertIn("only exact cpe_name strings from the supplied dictionary results", AGENT_FINAL_SYSTEM)
        self.assertNotIn("cpe_candidates must be an empty list", AGENT_FINAL_SYSTEM)

    def valid(self): return {"product_name":"OpenSSH","vendor":None,"version":"9.6p1","update":None,"part":None,"cpe_candidates":[],"evidence_paths":["t22.ssh.result.server_id.software"],"abstain":True,"explanation":"evidence"}
    def test_invalid_json(self): self.assertEqual(validate_output("not json")[1],"invalid_json")
    def test_missing_local_server_is_reported(self):
        self.assertEqual(call_local({},"qwen","http://127.0.0.1:1/v1/chat/completions")["error"],"URLError")

    def test_qwen_prompt_requests_no_think_for_bounded_structured_extraction(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def __iter__(self):
                yield b'data: {"choices":[{"delta":{"content":"{}"}}]}\n'
                yield b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n'
                yield b'data: [DONE]\n'
        class Opener:
            def open(self,request,timeout):
                self.body=json.loads(request.data)
                return Response()
        opener=Opener()
        with patch("benchmarks.cpe.src.llm_direct.urllib.request.build_opener",return_value=opener):
            call_local({},"qwen")
        self.assertTrue(opener.body["messages"][0]["content"].endswith("/no_think"))

    def test_generation_limit_is_reported_as_truncated_output(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def __iter__(self):
                yield b'data: {"choices":[{"delta":{"content":"{\\\"product_name\\\":\\\"Open"}}]}\n'
                yield b'data: {"choices":[{"delta":{},"finish_reason":"length"}]}\n'
                yield b'data: {"choices":[],"usage":{"prompt_tokens":20,"completion_tokens":512}}\n'
                yield b'data: [DONE]\n'
        class Opener:
            def open(self,request,timeout): return Response()
        with patch("benchmarks.cpe.src.llm_direct.urllib.request.build_opener",return_value=Opener()):
            response=call_local({},"llama")
        self.assertEqual(response["finish_reason"],"length")
        self.assertEqual(response["invalid_reason"],"truncated_output")
        self.assertFalse(response["schema_valid"])
        self.assertEqual(response["completion_tokens"],512)
    def test_extra_and_missing_fields(self):
        x=self.valid(); x["extra"]=1; self.assertEqual(validate_output(json.dumps(x))[1],"schema_fields")
        x=self.valid(); del x["vendor"]; self.assertEqual(validate_output(json.dumps(x))[1],"schema_fields")
    def test_duplicate_json_key_is_invalid(self):
        self.assertEqual(validate_output('{"product_name":null,"product_name":"x"}')[1],"invalid_json")
    def test_hallucinated_cpe_rejected(self):
        x=self.valid(); x["cpe_candidates"]=["cpe:2.3:a:madeup:thing:1:*:*:*:*:*:*:*"]
        parsed,err,ok=validate_output(json.dumps(x),set())
        self.assertEqual(err,"hallucinated_cpe_rejected"); self.assertTrue(parsed["abstain"]); self.assertEqual(parsed["cpe_candidates"],[]); self.assertTrue(ok)

    def test_invalid_part_and_blank_identity_fields_are_rejected(self):
        x=self.valid(); x["part"]="network"; self.assertEqual(validate_output(json.dumps(x))[1],"invalid_part")
        x=self.valid(); x["product_name"]=" "; self.assertEqual(validate_output(json.dumps(x))[1],"invalid_product_name")

    def test_non_abstaining_output_requires_a_concrete_product(self):
        x=self.valid(); x.update(product_name=None,abstain=False)
        self.assertEqual(validate_output(json.dumps(x))[1],"identity_required_unless_abstaining")

    def test_evidence_paths_must_resolve_against_the_raw_record(self):
        x=self.valid(); raw={"_source":{"software":"OpenSSH"}}
        self.assertTrue(validate_output(json.dumps(x),raw_record=raw)[2] is False)
        x["evidence_paths"]=["$. _source.software"]
        # Whitespace is not normalized into a different JSON path.
        self.assertEqual(validate_output(json.dumps(x),raw_record=raw)[1],"evidence_path_not_found")
        x["evidence_paths"]=["_source.software"]
        self.assertTrue(validate_output(json.dumps(x),raw_record=raw)[2])
        x["evidence_paths"]=["$.items[0].name"]
        self.assertTrue(validate_output(json.dumps(x),raw_record={"items":[{"name":"OpenSSH"}]})[2])

if __name__=="__main__": unittest.main()
