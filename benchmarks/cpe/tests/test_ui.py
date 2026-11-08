import json
import tempfile
import time
import unittest
from email.message import Message
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from benchmarks.cpe.src.gold import canonical_source_hash
from benchmarks.cpe.src.dataset import stable_id
from benchmarks.cpe.ui.server import UIApplication, make_handler, serve


def source_record(number):
    return {"_id":str(number),"_source":{"id":number,"proto":"ssh","path":"/x","ip":f"192.0.2.{number}","scanTime":"1","port":"t22","appId":"fixture","t22":{"ssh":{"result":{"server_id":{"software":"OpenSSH_9.6p1"}}}}}}


class UITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.input=self.root/"input.jsonl"
        self.gold=self.root/"gold.jsonl"
        self.documents=[source_record(1),source_record(2)]
        self.source_bytes=("".join(json.dumps(x)+"\n" for x in self.documents)+"{bad\n").encode()
        self.input.write_bytes(self.source_bytes)
        self.app=UIApplication(self.input,self.gold)

    def tearDown(self):
        self.temp.cleanup()

    def request(self,path,method="GET",body=None):
        handler_class=make_handler(self.app)
        handler=object.__new__(handler_class)
        output=BytesIO();response_headers={};status=[]
        handler.path=path;handler.command=method
        handler.headers=Message()
        raw_body=b"" if body is None else json.dumps(body).encode()
        handler.headers["Content-Length"]=str(len(raw_body))
        handler.rfile=BytesIO(raw_body);handler.wfile=output
        handler.send_response=lambda code,*args:status.append(code)
        handler.send_header=lambda key,value:response_headers.__setitem__(key,value)
        handler.end_headers=lambda:None
        (handler.do_POST if method=="POST" else handler.do_GET)()
        data=output.getvalue()
        content_type=response_headers.get("Content-Type","")
        payload=json.loads(data) if "json" in content_type else data.decode()
        return status[0],response_headers,payload

    def annotation(self,document,record_id):
        return {"schema_version":"2.0","record_id":record_id,"source_hash":canonical_source_hash(document),"annotation_status":"reviewed","expected_identities":[{"identity_id":record_id+"-1","expected_product":"OpenSSH","expected_vendor":"OpenBSD","expected_version":"9.6p1","expected_update":None,"expected_part":"a","cpe_mapping_status":"version_unresolved","expected_cpe23":None,"acceptable_cpes":[],"evidence_paths":["_source.t22.ssh.result.server_id.software"],"adjudication_notes":"human review"}],"annotation":{"annotator_id":"tester","reviewed_at":None,"adjudication_status":"pending","reviewer_id":None,"notes":""}}

    def test_read_only_routes_navigation_search_and_invalid_row_count(self):
        status,headers,page=self.request("/")
        self.assertEqual(status,200);self.assertIn("Gold annotation",page);self.assertEqual(headers.get("Content-Security-Policy") is not None,True)
        listing=self.request("/api/records?status=pending&limit=10")[2]
        self.assertEqual(listing["total"],2);self.assertEqual(listing["malformed_json_rows"],1)
        record_id=listing["records"][0]["record_id"]
        record=self.request("/api/record?record_id="+record_id)[2]
        self.assertEqual(record["raw"],self.documents[0] if record_id==stable_id(self.documents[0],1) else self.documents[1])
        found=self.request("/api/records?q="+record_id+"&status=all")[2]
        self.assertEqual(found["total"],1)

    def test_annotation_validation_save_load_preserves_other_records_and_source(self):
        first_id=stable_id(self.documents[0],1);second_id=stable_id(self.documents[1],2)
        self.assertEqual(self.request("/api/annotation","POST",self.annotation(self.documents[0],first_id))[0],200)
        self.assertEqual(self.request("/api/annotation","POST",self.annotation(self.documents[1],second_id))[0],200)
        saved=[json.loads(x) for x in self.gold.read_text().splitlines()]
        self.assertEqual({x["record_id"] for x in saved},{first_id,second_id})
        self.assertEqual(self.input.read_bytes(),self.source_bytes)
        loaded=self.request("/api/record?record_id="+first_id)[2]
        self.assertEqual(loaded["record"]["annotation_status"],"reviewed")
        invalid=self.annotation(self.documents[0],first_id);invalid["expected_identities"][0]["evidence_paths"]=["not.a.source.path"]
        status,_,body=self.request("/api/annotation","POST",invalid)
        self.assertEqual(status,400);self.assertIn("evidence path does not exist",body["error"])

    def test_stale_source_hash_is_rejected_before_save(self):
        record_id=stable_id(self.documents[0],1)
        self.assertEqual(self.request("/api/annotation","POST",self.annotation(self.documents[0],record_id))[0],200)
        changed=source_record(1)
        changed["_source"]["t22"]["ssh"]["result"]["server_id"]["software"]="OpenSSH_9.7p1"
        self.input.write_text(json.dumps(changed)+"\n")
        self.app=UIApplication(self.input,self.gold)
        current=self.request("/api/record?record_id="+record_id)[2]
        self.assertTrue(current["stale"]);self.assertIsNone(current["record"])
        status,_,body=self.request("/api/annotation","POST",self.annotation(self.documents[0],record_id))
        self.assertEqual(status,409);self.assertIn("hash mismatch",body["error"])
        self.assertEqual(len(self.gold.read_text().splitlines()),1)

    def test_smoke_test_constraints_and_status_route(self):
        self.assertEqual(self.request("/api/smoke","POST",{"method":"rag","record_count":1})[0],400)
        self.assertEqual(self.request("/api/smoke","POST",{"method":"deterministic","record_count":41})[0],400)
        self.assertEqual(self.request("/api/smoke","POST",{"method":"llm","record_count":1,"model":"remote"})[0],400)
        status,_,body=self.request("/api/smoke/options")
        self.assertEqual(status,200);self.assertEqual(body["methods"],["deterministic","llm","agent"])

    def test_request_payload_size_is_bounded(self):
        status,_,body=self.request("/api/annotation","POST",{"padding":"x"*(256*1024)})
        self.assertEqual(status,413);self.assertIn("exceeds 256 KiB",body["error"])

    def test_explicit_smoke_start_uses_existing_runner_and_reports_unscored_gold(self):
        import benchmarks.cpe.src.runner as runner
        def fake_run(method,model,server_url,*,records,output_path,progress_callback):
            rows=[]
            for i,row in enumerate(records,1):
                result={"record_id":row["record_id"],"source_hash":row["source_hash"],"status":"ok","outcome":"matched","extraction_predictions":[],"final_cpe_resolutions":[]}
                rows.append(result);progress_callback(i,len(records),result)
            return rows
        with patch.object(runner,"run",side_effect=fake_run):
            status,_,job=self.request("/api/smoke","POST",{"method":"deterministic","record_count":5})
            self.assertEqual(status,202)
            for _ in range(80):
                status,_,current=self.request("/api/smoke/status?job_id="+job["job_id"])
                if current["state"]!="running":break
                time.sleep(.01)
        self.assertEqual(current["state"],"completed")
        self.assertEqual(current["summary"]["records"],2)
        self.assertEqual(current["summary"]["accuracy_status"],"unavailable")
        self.assertTrue(current["output_path"].endswith(".jsonl"))

    def test_ui_only_binds_loopback(self):
        with self.assertRaises(ValueError):UIApplication(self.input,self.input)
        with self.assertRaisesRegex(ValueError,"only binds"):
            serve(self.input,self.gold,host="0.0.0.0",port=0)

    def test_non_loopback_model_endpoint_is_rejected(self):
        with patch("benchmarks.cpe.ui.server.Path.read_text",return_value=json.dumps({"server_url":"https://example.com/api"})):
            with self.assertRaisesRegex(ValueError,"configured llama.cpp endpoint"):
                UIApplication(self.input,self.gold)


if __name__=="__main__":unittest.main()
