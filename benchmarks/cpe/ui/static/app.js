"use strict";
const $ = (id) => document.getElementById(id);
const state = { records: [], offset: 0, selected: -1, current: null, identities: [], models: [], jobTimer: null };

async function api(path, options={}) {
  const response = await fetch(path, {cache:"no-store", ...options, headers:{"Content-Type":"application/json", ...(options.headers||{})}});
  const body = await response.json().catch(()=>({error:"Invalid response from local UI"}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}
function message(element, text, kind="") { element.textContent=text||""; element.className=`message ${kind}`; }
function activateTab(name) {
  document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("active",x.dataset.tab===name));
  document.querySelectorAll(".panel").forEach(x=>x.classList.toggle("active",x.id===name));
}
document.querySelectorAll(".tab").forEach(button=>button.addEventListener("click",()=>activateTab(button.dataset.tab)));

async function loadRecords(reset=true) {
  if (reset) state.offset=0;
  const q=$("recordSearch").value.trim();
  const status=$("statusFilter").value;
  const data=await api(`/api/records?q=${encodeURIComponent(q)}&status=${encodeURIComponent(status)}&offset=${state.offset}&limit=30`);
  state.records=data.records; state.selected=-1;
  const list=$("recordList"); list.replaceChildren();
  if (!state.records.length) { const empty=document.createElement("div"); empty.className="empty"; empty.textContent="No records match this filter."; list.append(empty); }
  state.records.forEach((record,index)=>{
    const button=document.createElement("button"); button.className="record-item"; button.type="button";
    const title=document.createElement("strong"); title.textContent=record.record_id;
    const sub=document.createElement("span"); sub.className="sub"; sub.textContent=`${record.protocol} · ${record.annotation_status}${record.stale?" · STALE":""}`;
    button.append(title,sub); button.addEventListener("click",()=>selectRecord(index)); list.append(button);
  });
  $("recordCounter").textContent=`${data.total} match(es) · page ${state.offset+1}–${state.offset+state.records.length}`;
  $("sourceStatus").textContent=`${data.malformed_json_rows} malformed JSON row(s) skipped · ${data.non_object_rows} non-object row(s) skipped`;
  if (state.records.length) await selectRecord(0);
}

async function selectRecord(index) {
  if (index<0 || index>=state.records.length) return;
  try {
    state.selected=index;
    const entry=state.records[index];
    document.querySelectorAll(".record-item").forEach((x,i)=>x.classList.toggle("selected",i===index));
    const data=await api(`/api/record?record_id=${encodeURIComponent(entry.record_id)}`);
    state.current=data;
    $("currentRecord").textContent=`${data.record_id} · ${data.protocol} · ${entry.annotation_status}${data.stale?" · STALE SOURCE":""}`;
    $("rawRecord").textContent=JSON.stringify(data.raw,null,2);
    $("pathValue").value="";
    const annotations=data.record;
    const v2=annotations && annotations.schema_version==="2.0" ? annotations : null;
    state.identities=v2 ? v2.expected_identities.map(x=>structuredClone(x)) : [];
    renderIdentities();
    $("annotationStatus").value=v2?.annotation_status || (annotations?"unreviewed":"unreviewed");
    $("annotatorId").value=v2?.annotation?.annotator_id || "";
    $("adjudicationStatus").value=v2?.annotation?.adjudication_status || "pending";
    $("reviewerId").value=v2?.annotation?.reviewer_id || "";
    $("annotationNotes").value=v2?.annotation?.notes || "";
    const warning=data.stale ? "Gold source hash differs. The old identity was not prefilled; review the current record before saving a replacement." : (data.errors?.length ? `Existing Gold validation errors: ${data.errors.map(x=>(x.errors||[]).join("; ")).join(" · ")}` : annotations?"Existing v1 label shown for reference. Saving replaces this record with an explicit v2 annotation.":"");
    message($("recordMessage"),warning,data.stale?"error":"");
    $("saveAnnotation").disabled=false;
  } catch (error) { message($("recordMessage"),error.message,"error"); }
}

function addIdentity(identity={}) {
  const index=state.identities.length;
  state.identities.push({
    identity_id:identity.identity_id || `${state.current?.record_id||"record"}-${index+1}`,
    expected_product:identity.expected_product||"", expected_vendor:identity.expected_vendor??null,
    expected_version:identity.expected_version??null, expected_update:identity.expected_update??null,
    expected_part:identity.expected_part??null, cpe_mapping_status:identity.cpe_mapping_status||"unreviewed",
    expected_cpe23:identity.expected_cpe23??null, acceptable_cpes:identity.acceptable_cpes||[],
    evidence_paths:identity.evidence_paths||[], adjudication_notes:identity.adjudication_notes||""
  });
  renderIdentities();
}
function makeField(labelText,value,attrs={}) {
  const label=document.createElement("label"); label.textContent=labelText;
  let input;
  if (attrs.options) {
    input=document.createElement("select"); attrs.options.forEach(option=>{const item=document.createElement("option");item.value=option.value;item.textContent=option.label;input.append(item);});
  } else if (attrs.multiline) { input=document.createElement("textarea"); input.rows=attrs.rows||2; }
  else { input=document.createElement("input"); input.type=attrs.type||"text"; }
  input.value=value ?? ""; if(attrs.maxLength)input.maxLength=attrs.maxLength;
  label.append(input); return {label,input};
}
function renderIdentities() {
  const parent=$("identityList"); parent.replaceChildren();
  state.identities.forEach((identity,index)=>{
    const card=document.createElement("fieldset"); card.className="identity-card"; card.dataset.index=String(index);
    const heading=document.createElement("div"); heading.className="identity-title";
    const title=document.createElement("strong"); title.textContent=`Identity ${index+1} · ${identity.identity_id}`;
    const remove=document.createElement("button"); remove.type="button"; remove.className="danger"; remove.textContent="Remove identity"; remove.addEventListener("click",()=>{state.identities.splice(index,1);renderIdentities();});
    heading.append(title,remove); card.append(heading);
    const grid=document.createElement("div"); grid.className="identity-grid";
    const fields=[
      ["Identity ID","identity_id"], ["Product *","expected_product"], ["Vendor","expected_vendor"], ["Version","expected_version"], ["Update","expected_update"], ["CPE part","expected_part"]
    ];
    fields.forEach(([label,key])=>{const {label:node,input}=makeField(label,identity[key],{maxLength:500});grid.append(node);input.addEventListener("input",()=>{identity[key]=input.value;title.textContent=`Identity ${index+1} · ${identity.identity_id}`;});});
    const mapping=makeField("CPE mapping status","cpe_mapping_status",{options:["mapped","not_in_dictionary","ambiguous","version_unresolved","unreviewed"].map(x=>({value:x,label:x}))});
    mapping.input.addEventListener("change",()=>identity.cpe_mapping_status=mapping.input.value); grid.append(mapping.label);
    const cpe=makeField("Expected CPE 2.3","expected_cpe23",{maxLength:300}); cpe.input.addEventListener("input",()=>identity.expected_cpe23=cpe.input.value||null);grid.append(cpe.label);
    const alternatives=makeField("Acceptable CPEs (one per line)",(identity.acceptable_cpes||[]).join("\n"),{multiline:true,rows:2}); alternatives.label.className="wide"; alternatives.input.addEventListener("input",()=>identity.acceptable_cpes=alternatives.input.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean));grid.append(alternatives.label);
    const evidence=makeField("Evidence paths (one per line)",(identity.evidence_paths||[]).join("\n"),{multiline:true,rows:2}); evidence.label.className="wide"; evidence.input.addEventListener("input",()=>identity.evidence_paths=evidence.input.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean));grid.append(evidence.label);
    const notes=makeField("Identity / adjudication notes",identity.adjudication_notes,{multiline:true,rows:2}); notes.label.className="wide"; notes.input.addEventListener("input",()=>identity.adjudication_notes=notes.input.value);grid.append(notes.label);
    card.append(grid); parent.append(card);
  });
}

function buildGoldRecord() {
  if (!state.current) throw new Error("Select a source record first.");
  const annotationStatus=$("annotationStatus").value;
  const identities=state.identities.map(x=>({...x,
    expected_vendor:x.expected_vendor||null,expected_version:x.expected_version||null,expected_update:x.expected_update||null,expected_part:x.expected_part||null,
    expected_cpe23:x.expected_cpe23||null,acceptable_cpes:[...(x.acceptable_cpes||[])],evidence_paths:[...(x.evidence_paths||[])]
  }));
  const now=new Date().toISOString();
  return {schema_version:"2.0",record_id:state.current.record_id,source_hash:state.current.source_hash,annotation_status,expected_identities:identities,annotation:{annotator_id:$("annotatorId").value.trim(),reviewed_at:annotationStatus==="unreviewed"?null:now,adjudication_status:$("adjudicationStatus").value,reviewer_id:$("reviewerId").value.trim()||null,notes:$("annotationNotes").value}};
}

$("annotationForm").addEventListener("submit",async event=>{
  event.preventDefault();
  try {
    const record=buildGoldRecord();
    const errors=[];
    if(record.annotation_status==="reviewed"&&!record.expected_identities.length)errors.push("Reviewed records need at least one identity; use No software identity for a confirmed negative.");
    record.expected_identities.forEach((identity,index)=>{if(!identity.expected_product.trim())errors.push(`Identity ${index+1}: product is required.`);if(!identity.evidence_paths.length)errors.push(`Identity ${index+1}: add at least one evidence path.`);});
    if(record.annotation_status==="no_software_identity"&&record.expected_identities.length)errors.push("No software identity requires an empty identity list.");
    if(errors.length)throw new Error(errors.join(" "));
    await api("/api/annotation",{method:"POST",body:JSON.stringify(record)});
    message($("saveMessage"),"Gold v2 annotation saved.","success");
    await loadRecords(false);
    const idx=state.records.findIndex(x=>x.record_id===record.record_id);if(idx>=0)await selectRecord(idx);
  } catch(error) { $("saveMessage").textContent=error.message;$("saveMessage").className="error"; }
});

$("addIdentity").addEventListener("click",()=>addIdentity());
$("statusFilter").addEventListener("change",()=>loadRecords(true).catch(e=>message($("recordMessage"),e.message,"error")));
$("searchButton").addEventListener("click",()=>loadRecords(true).catch(e=>message($("recordMessage"),e.message,"error")));
$("recordSearch").addEventListener("keydown",event=>{if(event.key==="Enter"){event.preventDefault();$("searchButton").click();}});
$("previousButton").addEventListener("click",async()=>{if(state.selected>0)await selectRecord(state.selected-1);else if(state.offset>0){state.offset=Math.max(0,state.offset-30);await loadRecords(false);await selectRecord(state.records.length-1);}});
$("nextButton").addEventListener("click",async()=>{if(state.selected+1<state.records.length)await selectRecord(state.selected+1);else{state.offset+=30;await loadRecords(false);if(state.records.length)await selectRecord(0);}});
$("copyPath").addEventListener("click",async()=>{try{await navigator.clipboard.writeText($("pathValue").value);message($("recordMessage"),"Path copied.","success");}catch{message($("recordMessage"),"Clipboard is unavailable; select and copy the path manually.","");}});
$("addPathToIdentity").addEventListener("click",()=>{const path=$("pathValue").value.trim();if(!path){message($("recordMessage"),"Enter a path first.","error");return;}if(!state.identities.length)addIdentity();const target=state.identities[0];if(!target.evidence_paths.includes(path))target.evidence_paths.push(path);renderIdentities();});

async function loadSmokeOptions(){
  const options=await api("/api/smoke/options");state.models=options.models;
  options.models.forEach(model=>{const option=document.createElement("option");option.value=model;option.textContent=model;$("smokeModel").append(option);});
  updateSmokeModel();
}
function updateSmokeModel(){$("smokeModel").disabled=$("smokeMethod").value==="deterministic";}
$("smokeMethod").addEventListener("change",updateSmokeModel);
$("smokeForm").addEventListener("submit",async event=>{
  event.preventDefault();clearInterval(state.jobTimer);message($("smokeMessage"),"");
  try{
    const result=await api("/api/smoke",{method:"POST",body:JSON.stringify({method:$("smokeMethod").value,record_count:Number($("smokeCount").value),model:$("smokeModel").value||null})});
    $("smokeProgress").classList.remove("hidden");$("jobOutput").textContent=result.output_path;pollJob(result.job_id);
  }catch(error){message($("smokeMessage"),error.message,"error");}
});
async function pollJob(jobId){
  try{
    const job=await api(`/api/smoke/status?job_id=${encodeURIComponent(jobId)}`);
    $("jobState").textContent=job.state;$("jobCount").textContent=`${job.processed}/${job.total}`;$("jobProgress").max=job.total||1;$("jobProgress").value=job.processed;
    $("jobOutput").textContent=job.output_path;
    $("jobSummary").textContent=job.summary?JSON.stringify(job.summary,null,2):(job.error||"Waiting for results…");
    if(job.state==="running")state.jobTimer=setTimeout(()=>pollJob(jobId),700);else state.jobTimer=null;
  }catch(error){message($("smokeMessage"),error.message,"error");}
}

Promise.all([loadRecords(),loadSmokeOptions()]).catch(error=>message($("recordMessage"),error.message,"error"));
