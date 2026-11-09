import json
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.error
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

    def build_browser_payload(self, document, record_id, identities):
        node=shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable; browser JavaScript regression cannot execute")
        script=r'''const fs=require("node:fs"),vm=require("node:vm");
const input=JSON.parse(process.argv[1]);
const source=fs.readFileSync(input.script,"utf8");
const match=source.match(/function buildGoldRecord\(\) \{[\s\S]*?\n\}/);
if(!match)throw new Error("buildGoldRecord was not found");
const state={current:{record_id:input.record_id,source_hash:input.source_hash},identities:input.identities};
const values={annotationStatus:{value:"reviewed"},annotatorId:{value:"tester"},adjudicationStatus:{value:"reviewed"},reviewerId:{value:"reviewer"},annotationNotes:{value:"synthetic"}};
const record=vm.runInNewContext(`${match[0]}\nbuildGoldRecord()`,{state,$:id=>values[id],Date});
process.stdout.write(JSON.stringify(record));'''
        payload={"script":str(Path(__file__).parents[1]/"ui/static/app.js"),"record_id":record_id,"source_hash":canonical_source_hash(document),"identities":identities}
        result=subprocess.run([node,"-e",script,json.dumps(payload)],capture_output=True,text=True,check=True)
        return json.loads(result.stdout)

    def test_browser_annotation_payload_saves_and_reloads_single_and_multiple_identities(self):
        document=self.documents[0];record_id=stable_id(document,1)
        identity=self.annotation(document,record_id)["expected_identities"][0]
        single=self.build_browser_payload(document,record_id,[identity])
        self.assertEqual(single["annotation_status"],"reviewed")
        self.assertEqual(self.request("/api/annotation","POST",single)[0],200)
        loaded=self.request("/api/record?record_id="+record_id)[2]["record"]
        self.assertEqual(loaded["annotation_status"],"reviewed")
        self.assertEqual(len(loaded["expected_identities"]),1)

        second={**identity,"identity_id":record_id+"-2","expected_product":"ExampleService"}
        multiple=self.build_browser_payload(document,record_id,[identity,second])
        self.assertEqual(self.request("/api/annotation","POST",multiple)[0],200)
        loaded=self.request("/api/record?record_id="+record_id)[2]["record"]
        self.assertEqual([item["identity_id"] for item in loaded["expected_identities"]],[record_id+"-1",record_id+"-2"])

        invalid={**multiple,"expected_identities":[{**identity,"expected_product":""},second]}
        status,_,error=self.request("/api/annotation","POST",invalid)
        self.assertEqual(status,400);self.assertTrue(any("expected_product" in item for item in error["errors"]))
        loaded=self.request("/api/record?record_id="+record_id)[2]["record"]
        self.assertEqual(len(loaded["expected_identities"]),2)

    def test_cpe_fields_and_evidence_survive_frontend_rerender_validation_save_and_reload(self):
        node=shutil.which("node")
        if not node:self.skipTest("Node.js is unavailable; frontend renderer regression cannot execute")
        document=source_record(77)
        document["_source"]["t80"]={"http":{"result":{"response":{"headers":{"server":"nginx/1.25.3"}}}}}
        self.input.write_text(json.dumps(document)+"\n")
        self.app=UIApplication(self.input,self.gold)
        record_id=stable_id(document,1)
        cpe="cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"
        first={"identity_id":record_id+"-1","expected_product":"OpenSSH","expected_vendor":"OpenBSD","expected_version":"9.6p1","expected_update":None,"expected_part":"a","cpe_mapping_status":"mapped","expected_cpe23":cpe,"acceptable_cpes":[],"evidence_paths":[],"adjudication_notes":""}
        script=r'''const fs=require("node:fs"),vm=require("node:vm");
const input=JSON.parse(process.argv[1]),source=fs.readFileSync(input.script,"utf8");
function fn(name){const start=source.indexOf(`function ${name}(`);const end=source.indexOf("\n}",start);if(start<0||end<0)throw Error(`missing ${name}`);return source.slice(start,end+2);}
class Element{constructor(tag){this.tagName=tag.toUpperCase();this.children=[];this.events={};this.dataset={};this.className="";this.textContent="";this.attributes={};this.classes=new Set();this.classList={add:x=>this.classes.add(x),remove:x=>this.classes.delete(x)};this._value="";Object.defineProperty(this,"value",{get:()=>this._value,set:v=>{v=String(v??"");this._value=this.tagName==="SELECT"&&this.children.length&&!this.children.some(x=>x.value===v)?"":v;}});}
append(...items){this.children.push(...items)} replaceChildren(...items){this.children=items} addEventListener(name,fn){this.events[name]=fn} setAttribute(k,v){this.attributes[k]=v}
walk(){return [this,...this.children.flatMap(x=>x.walk())]}
querySelector(selector){const field=selector.match(/\[data-field="([^"]+)"\]/);if(field){const label=this.walk().find(x=>x.dataset?.field===field[1]);if(!label)return null;if(selector.includes(".field-error"))return label.walk().find(x=>x.className==="field-error")||null;return label;}return null}}
const ids={identityList:new Element("div"),annotationStatus:new Element("select"),annotatorId:new Element("input"),adjudicationStatus:new Element("select"),reviewerId:new Element("input"),annotationNotes:new Element("textarea"),recordStatusError:new Element("small"),validationSummary:new Element("div")};
ids.annotationStatus.value="reviewed";ids.annotatorId.value="annotator";ids.adjudicationStatus.value="reviewed";ids.reviewerId.value="reviewer";ids.annotationNotes.value="synthetic QA";
const documentApi={createElement:tag=>new Element(tag),querySelectorAll(selector){return selector===".field-error"?Object.values(ids).flatMap(x=>x.walk()).filter(x=>x.className==="field-error"):[]},querySelector(selector){const m=selector.match(/data-index="(\d+)"/);return m?ids.identityList.children.find(x=>x.dataset.index===m[1])||null:null;}};
const state={current:{record_id:input.record_id,source_hash:input.source_hash},identities:[structuredClone(input.identity)],selectedIdentity:0};
const code=["makeField","renderIdentities","showValidationErrors","addIdentity","buildGoldRecord"].map(fn).join("\n");
const context={state,document:documentApi,$:id=>ids[id]};vm.runInNewContext(code,context);vm.runInNewContext("renderIdentities()",context);
function field(i,key){const card=ids.identityList.children[i];const label=card.walk().find(x=>x.dataset?.field===key);if(!label)throw Error(`missing field ${key}`);return label.walk().find(x=>["INPUT","SELECT","TEXTAREA"].includes(x.tagName));}
function set(i,key,value,event){const control=field(i,key);control.value=value;control.events[event]?.();return control.value;}
set(0,"cpe_mapping_status","mapped","change");set(0,"expected_cpe23","not-a-cpe","input");
const missingEvidence="expected_identities[0] evidence_paths needs at least one exact path into the raw source record.";
const invalidCpe="expected_identities[0] invalid CPE 2.3: malformed identifier";
vm.runInNewContext(`showValidationErrors(${JSON.stringify([invalidCpe,missingEvidence])})`,context);
const afterValidation={mapping:field(0,"cpe_mapping_status").value,cpe:field(0,"expected_cpe23").value};
const restored=set(0,"expected_cpe23",input.identity.expected_cpe23,"input");const stateAfterRestore=state.identities[0].expected_cpe23;set(0,"evidence_paths","_source.t22.ssh.result.server_id.software","input");
vm.runInNewContext("addIdentity()",context);
const afterAdd={mapping:field(0,"cpe_mapping_status").value,cpe:field(0,"expected_cpe23").value,evidence:field(0,"evidence_paths").value};
set(1,"expected_product","nginx","input");set(1,"expected_version","1.25.3","input");set(1,"cpe_mapping_status","unreviewed","change");set(1,"evidence_paths","_source.t80.http.result.response.headers.server","input");
const record=vm.runInNewContext("buildGoldRecord()",context);
process.stdout.write(JSON.stringify({afterValidation,restored,stateAfterRestore,afterAdd,record}));'''
        args={"script":str(Path(__file__).parents[1]/"ui/static/app.js"),"record_id":record_id,"source_hash":canonical_source_hash(document),"identity":first}
        result=subprocess.run([node,"-e",script,json.dumps(args)],capture_output=True,text=True,check=True)
        state=json.loads(result.stdout)
        self.assertEqual(state["afterValidation"],{"mapping":"mapped","cpe":"not-a-cpe"})
        self.assertEqual(state["afterAdd"],{"mapping":"mapped","cpe":cpe,"evidence":"_source.t22.ssh.result.server_id.software"},state)
        payload=state["record"]
        self.assertEqual([x["cpe_mapping_status"] for x in payload["expected_identities"]],["mapped","unreviewed"])
        self.assertEqual(payload["expected_identities"][0]["expected_cpe23"],cpe)
        status,_,body=self.request("/api/annotation","POST",payload)
        self.assertEqual(status,200,body)
        loaded=self.request("/api/record?record_id="+record_id)[2]["record"]
        first_loaded,second_loaded=loaded["expected_identities"]
        self.assertEqual(first_loaded["cpe_mapping_status"],"mapped");self.assertEqual(first_loaded["expected_cpe23"],cpe)
        self.assertEqual(first_loaded["evidence_paths"],["_source.t22.ssh.result.server_id.software"])
        self.assertEqual(second_loaded["cpe_mapping_status"],"unreviewed");self.assertIsNone(second_loaded["expected_cpe23"])
        self.assertEqual(second_loaded["evidence_paths"],["_source.t80.http.result.response.headers.server"])
        invalid={**payload,"expected_identities":[{**first_loaded,"expected_cpe23":"not-a-cpe"},second_loaded]}
        status,_,errors=self.request("/api/annotation","POST",invalid)
        self.assertEqual(status,400);self.assertTrue(any("invalid CPE 2.3" in x for x in errors["errors"]))
        after_invalid=self.request("/api/record?record_id="+record_id)[2]["record"]["expected_identities"]
        self.assertEqual(after_invalid[0]["expected_cpe23"],cpe);self.assertEqual(len(after_invalid),2)

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

    def test_ui_accepts_pilot_sample_wrappers_and_returns_raw_source(self):
        wrappers=[{"record_id":stable_id(document,index),"source_hash":canonical_source_hash(document),"raw":document,"protocol":"ssh"} for index,document in enumerate(self.documents,1)]
        self.input.write_text("".join(json.dumps(row)+"\n" for row in wrappers))
        self.app=UIApplication(self.input,self.gold)
        record_id=wrappers[0]["record_id"]
        record=self.request("/api/record?record_id="+record_id)[2]
        self.assertEqual(record["record_id"],record_id)
        self.assertEqual(record["raw"],self.documents[0])

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
        self.assertEqual(status,400);self.assertTrue(any("evidence path does not exist" in error for error in body["errors"]))

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
        self.assertEqual(status,200);self.assertEqual(body["methods"],["deterministic","llm","agent","comparison"])

    def test_model_readiness_distinguishes_configured_weights_server_loaded_and_ready(self):
        readiness={"endpoint":"http://127.0.0.1:8080/v1/chat/completions","server_reachable":False,"server_models":[],"server_error":"URLError","models":[{"alias":"qwen","model":"Qwen3-8B","configured":True,"weights_available":True,"weight_file":"/local/Qwen3-8B-Q4_K_M.gguf","quantization":"Q4_K_M","server_reachable":False,"server_model_match":False,"ready":False,"reason":"configured loopback model server is not reachable"}]}
        with patch.object(self.app.smoke_jobs,"model_readiness",return_value=readiness):
            status,_,body=self.request("/api/smoke/options")
            self.assertEqual(status,200)
            model=body["model_readiness"]["models"][0]
            self.assertTrue(model["configured"]);self.assertTrue(model["weights_available"])
            self.assertFalse(model["server_reachable"]);self.assertFalse(model["server_model_match"]);self.assertFalse(model["ready"])
            status,_,error=self.request("/api/smoke","POST",{"method":"llm","record_count":1,"model":"qwen"})
        self.assertEqual(status,400);self.assertIn("not ready",error["error"])

    def test_nvd_api_source_and_key_state_are_visible_without_exposing_key(self):
        class OfflineOpener:
            def open(self, *args, **kwargs): raise urllib.error.URLError("offline")
        with patch("benchmarks.cpe.ui.server.urllib.request.build_opener", return_value=OfflineOpener()):
            readiness=self.app.smoke_jobs.model_readiness()
        nvd=readiness["nvd_api"]
        self.assertEqual(nvd["source"],"nvd_api_2.0")
        self.assertEqual(nvd["endpoint"],"https://services.nvd.nist.gov/rest/json/cpes/2.0")
        self.assertIn(nvd["rate_limit_mode"],{"public","api_key"})
        self.assertIsInstance(nvd["api_key_configured"],bool)
        self.assertNotIn("api_key",nvd)

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

    def test_comparison_runs_all_methods_on_the_same_records_and_separate_outputs(self):
        import benchmarks.cpe.src.runner as runner
        readiness={"models":[{"alias":"qwen","ready":True}]}
        invocations=[]
        def fake_run(method,model,server_url,*,records,output_path,progress_callback):
            invocations.append((method,model,list(records),str(output_path)))
            rows=[]
            for i,row in enumerate(records,1):
                result={"record_id":row["record_id"],"source_hash":row["source_hash"],"status":"ok","outcome":"matched","extraction_predictions":[],"final_cpe_resolutions":[],"latency_seconds":0.01}
                rows.append(result);progress_callback(i,len(records),result)
            return rows
        with patch.object(self.app.smoke_jobs,"model_readiness",return_value=readiness), patch.object(runner,"run",side_effect=fake_run):
            status,_,job=self.request("/api/smoke","POST",{"method":"comparison","record_count":2,"model":"qwen"})
            self.assertEqual(status,202)
            for _ in range(100):
                status,_,current=self.request("/api/smoke/status?job_id="+job["job_id"])
                if current["state"]!="running":break
                time.sleep(.01)
        self.assertEqual(current["state"],"completed")
        self.assertEqual(current["processed"],6)
        self.assertEqual([item[0] for item in invocations],["deterministic","llm","agent"])
        expected_ids=[entry["record_id"] for entry in self.app.source.entries[:2]]
        for method,model,records,path in invocations:
            self.assertEqual([row["record_id"] for row in records],expected_ids)
            self.assertEqual(model,None if method=="deterministic" else "qwen")
            self.assertTrue(path.endswith(f"-{method}-qwen.jsonl"))
        self.assertEqual(len(set(item[3] for item in invocations)),3)
        self.assertEqual(set(current["summary"]["methods"]),{"deterministic","llm","agent"})
        self.assertTrue(all(item["accuracy_status"]=="unavailable" for item in current["summary"]["methods"].values()))

    def test_ui_only_binds_loopback(self):
        with self.assertRaises(ValueError):UIApplication(self.input,self.input)
        with self.assertRaisesRegex(ValueError,"only binds"):
            serve(self.input,self.gold,host="0.0.0.0",port=0)

    def test_non_loopback_model_endpoint_is_rejected(self):
        with patch("benchmarks.cpe.ui.server.Path.read_text",return_value=json.dumps({"server_url":"https://example.com/api"})):
            with self.assertRaisesRegex(ValueError,"configured llama.cpp endpoint"):
                UIApplication(self.input,self.gold)


if __name__=="__main__":unittest.main()
