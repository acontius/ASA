"use strict";
const $ = (id) => document.getElementById(id);
const state = { records: [], offset: 0, selected: -1, selectedIdentity: null, current: null, identities: [], models: [], jobTimer: null };

async function api(path, options={}) {
  const response = await fetch(path, {cache:"no-store", ...options, headers:{"Content-Type":"application/json", ...(options.headers||{})}});
  const body = await response.json().catch(()=>({error:"Invalid response from local UI"}));
  if (!response.ok) {
    const error=new Error(body.errors?.join(" · ") || body.error || `Request failed (${response.status})`);
    error.details=body.errors||[];
    throw error;
  }
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
    state.selectedIdentity=null;
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
  state.selectedIdentity=index;
  renderIdentities();
}
function makeField(labelText,value,attrs={}) {
  const label=document.createElement("label");
  if(attrs.field)label.dataset.field=attrs.field;
  const title=document.createElement("span");title.textContent=labelText;label.append(title);
  let input;
  if (attrs.options) {
    input=document.createElement("select"); attrs.options.forEach(option=>{const item=document.createElement("option");item.value=option.value;item.textContent=option.label;input.append(item);});
  } else if (attrs.multiline) { input=document.createElement("textarea"); input.rows=attrs.rows||2; }
  else { input=document.createElement("input"); input.type=attrs.type||"text"; }
  input.value=value ?? ""; if(attrs.maxLength)input.maxLength=attrs.maxLength;
  if(attrs.help){const help=document.createElement("small");help.className="field-help";help.textContent=attrs.help;label.append(help);}
  const error=document.createElement("small");error.className="field-error";error.setAttribute("aria-live","polite");label.append(error);
  label.append(input); return {label,input};
}
function renderIdentities() {
  const parent=$("identityList"); parent.replaceChildren();
  state.identities.forEach((identity,index)=>{
    const card=document.createElement("fieldset"); card.className=`identity-card${state.selectedIdentity===index?" selected-identity":""}`; card.dataset.index=String(index);
    card.addEventListener("click",event=>{if(event.target.closest("input,select,textarea,button"))return;state.selectedIdentity=index;renderIdentities();});
    const heading=document.createElement("div"); heading.className="identity-title";
    const title=document.createElement("strong"); title.textContent=`Identity ${index+1} · ${identity.identity_id}`;
    const actions=document.createElement("div");actions.className="identity-actions";
    const select=document.createElement("button");select.type="button";select.textContent=state.selectedIdentity===index?"Selected for evidence":"Select for evidence";select.addEventListener("click",event=>{event.stopPropagation();state.selectedIdentity=index;renderIdentities();});
    const remove=document.createElement("button"); remove.type="button"; remove.className="danger"; remove.textContent="Remove identity"; remove.addEventListener("click",event=>{event.stopPropagation();state.identities.splice(index,1);state.selectedIdentity=state.identities.length?Math.min(index,state.identities.length-1):null;renderIdentities();});
    actions.append(select,remove);heading.append(title,actions);card.append(heading);
    const grid=document.createElement("div"); grid.className="identity-grid";
    const fields=[
      ["Identity ID","identity_id","Stable ID for this identity."],
      ["Product *","expected_product","Software product identified from source evidence."],
      ["Vendor","expected_vendor","Manufacturer or organization only when reliable evidence supports it."],
      ["Version","expected_version","Only a version explicitly supported by evidence; do not infer precision from an incomplete banner."],
      ["Update","expected_update","Explicit product update or release identifier, when available."],
      ["Part","expected_part","CPE part: a = application, o = operating system, h = hardware. Choose only when supported; no default is assigned."]
    ];
    fields.forEach(([label,key,help])=>{
      const partOptions=key==="expected_part"?[{value:"",label:"Unknown / not set"},{value:"a",label:"a — application"},{value:"o",label:"o — operating system"},{value:"h",label:"h — hardware"},{value:"*",label:"* — CPE wildcard"},{value:"-",label:"- — not applicable"}]:null;
      const {label:node,input}=makeField(label,identity[key],{field:key,help,maxLength:500,options:partOptions});grid.append(node);
      input.addEventListener("input",()=>{identity[key]=key==="expected_part"&&!input.value?null:input.value;title.textContent=`Identity ${index+1} · ${identity.identity_id}`;});
      input.addEventListener("change",()=>{identity[key]=key==="expected_part"&&!input.value?null:input.value;});
    });
    const mappingOptions=[{value:"unreviewed",label:"unreviewed — save extraction; CPE not adjudicated"},...["mapped","not_in_dictionary","ambiguous","version_unresolved"].map(x=>({value:x,label:x}))];
    const mapping=makeField("CPE mapping status",identity.cpe_mapping_status||"unreviewed",{field:"cpe_mapping_status",help:"unreviewed means this identity can be saved and scored for extraction while CPE mapping waits for adjudication. mapped = independently established; not_in_dictionary = identity known but absent from the dictionary; ambiguous = multiple plausible mappings; version_unresolved = product known but version cannot be mapped. This is identity-level, not record-level.",options:mappingOptions});
    mapping.input.addEventListener("change",()=>identity.cpe_mapping_status=mapping.input.value); grid.append(mapping.label);
    const cpe=makeField("Expected CPE 2.3",identity.expected_cpe23,{field:"expected_cpe23",help:"Independently validated expected CPE; enter it only when mapping is established.",maxLength:300}); cpe.input.addEventListener("input",()=>identity.expected_cpe23=cpe.input.value||null);grid.append(cpe.label);
    const alternatives=makeField("Acceptable CPE alternatives (one per line)",(identity.acceptable_cpes||[]).join("\n"),{field:"acceptable_cpes",help:"Only genuinely acceptable alternatives validated by human review.",multiline:true,rows:2}); alternatives.label.className="wide"; alternatives.input.addEventListener("input",()=>identity.acceptable_cpes=alternatives.input.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean));grid.append(alternatives.label);
    const evidence=makeField("Evidence paths (one per line)",(identity.evidence_paths||[]).join("\n"),{field:"evidence_paths",help:"Exact JSON paths to source fields supporting this identity.",multiline:true,rows:2}); evidence.label.className="wide"; evidence.input.addEventListener("input",()=>identity.evidence_paths=evidence.input.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean));grid.append(evidence.label);
    const notes=makeField("Adjudication notes",identity.adjudication_notes,{field:"adjudication_notes",help:"Explain ambiguity, evidence interpretation, or special CPE mapping decisions.",multiline:true,rows:2}); notes.label.className="wide"; notes.input.addEventListener("input",()=>identity.adjudication_notes=notes.input.value);grid.append(notes.label);
    card.append(grid); parent.append(card);
  });
}

function showValidationErrors(errors,fallback="") {
  document.querySelectorAll(".field-error").forEach(node=>node.textContent="");
  $("recordStatusError").textContent="";
  const summary=$("validationSummary");summary.replaceChildren();
  const items=Array.isArray(errors)&&errors.length?errors:(fallback?[fallback]:[]);
  if(!items.length){summary.classList.add("hidden");return;}
  summary.classList.remove("hidden");
  const heading=document.createElement("strong");heading.textContent="Please correct these fields:";summary.append(heading);
  const list=document.createElement("ul");
  items.forEach(error=>{
    const item=document.createElement("li");item.textContent=error;list.append(item);
    const match=error.match(/expected_identities\[(\d+)\]/);
    if(match){
      const card=document.querySelector(`.identity-card[data-index="${match[1]}"]`);
      const fields=["identity_id","expected_product","expected_vendor","expected_version","expected_update","expected_part","cpe_mapping_status","expected_cpe23","acceptable_cpes","evidence_paths","adjudication_notes"];
      const key=fields.find(field=>error.includes(field))||(error.toLowerCase().includes("evidence path")?"evidence_paths":error.includes("CPE")?"expected_cpe23":null);
      const target=key&&card?.querySelector(`[data-field="${key}"] .field-error`);
      if(target)target.textContent=error.replace(/^expected_identities\[\d+\]\s*/,"");
    } else if(error.startsWith("annotation.")) {
      const key=error.match(/^annotation\.([a-z_]+)/)?.[1];
      const target=key&&document.querySelector(`[data-field="${key}"] .field-error`);
      if(target)target.textContent=error;
    } else if(error.includes("annotation_status")||error.includes("no_software_identity")||error.includes("Reviewed records")) {
      const target=$("recordStatusError");if(target)target.textContent=error;
    }
  });
  summary.append(list);
}

function buildGoldRecord() {
  if (!state.current) throw new Error("Select a source record first.");
  const annotationStatus=$("annotationStatus").value;
  const identities=state.identities.map(x=>({...x,
    expected_product:(x.expected_product||"").trim(),expected_vendor:(x.expected_vendor||"").trim()||null,expected_version:(x.expected_version||"").trim()||null,expected_update:(x.expected_update||"").trim()||null,expected_part:(x.expected_part||"").trim()||null,
    expected_cpe23:(x.expected_cpe23||"").trim()||null,acceptable_cpes:[...(x.acceptable_cpes||[])],evidence_paths:[...(x.evidence_paths||[])]
  }));
  const now=new Date().toISOString();
  return {schema_version:"2.0",record_id:state.current.record_id,source_hash:state.current.source_hash,annotation_status:annotationStatus,expected_identities:identities,annotation:{annotator_id:$("annotatorId").value.trim(),reviewed_at:annotationStatus==="unreviewed"?null:now,adjudication_status:$("adjudicationStatus").value,reviewer_id:$("reviewerId").value.trim()||null,notes:$("annotationNotes").value}};
}

$("annotationForm").addEventListener("submit",async event=>{
  event.preventDefault();
  try {
    showValidationErrors([]);
    const record=buildGoldRecord();
    const errors=[];
    if(record.annotation_status==="reviewed"&&!record.expected_identities.length)errors.push("Reviewed records need at least one identity; use No software identity for a confirmed negative.");
    record.expected_identities.forEach((identity,index)=>{if(!identity.expected_product)errors.push(`expected_identities[${index}] expected_product is required.`);if(!identity.evidence_paths.length)errors.push(`expected_identities[${index}] evidence_paths needs at least one exact path into the raw source record.`);});
    if(record.annotation_status==="no_software_identity"&&record.expected_identities.length)errors.push("No software identity requires an empty identity list.");
    if(errors.length){const error=new Error(errors.join(" · "));error.validationErrors=errors;throw error;}
    await api("/api/annotation",{method:"POST",body:JSON.stringify(record)});
    message($("saveMessage"),"Gold v2 annotation saved.","success");
    await loadRecords(false);
    const idx=state.records.findIndex(x=>x.record_id===record.record_id);if(idx>=0)await selectRecord(idx);
  } catch(error) { showValidationErrors(error.validationErrors||error.details||[],error.message);$("saveMessage").textContent=error.message;$("saveMessage").className="error"; }
});

$("addIdentity").addEventListener("click",()=>addIdentity());
$("statusFilter").addEventListener("change",()=>loadRecords(true).catch(e=>message($("recordMessage"),e.message,"error")));
$("searchButton").addEventListener("click",()=>loadRecords(true).catch(e=>message($("recordMessage"),e.message,"error")));
$("recordSearch").addEventListener("keydown",event=>{if(event.key==="Enter"){event.preventDefault();$("searchButton").click();}});
$("previousButton").addEventListener("click",async()=>{if(state.selected>0)await selectRecord(state.selected-1);else if(state.offset>0){state.offset=Math.max(0,state.offset-30);await loadRecords(false);await selectRecord(state.records.length-1);}});
$("nextButton").addEventListener("click",async()=>{if(state.selected+1<state.records.length)await selectRecord(state.selected+1);else{state.offset+=30;await loadRecords(false);if(state.records.length)await selectRecord(0);}});
$("copyPath").addEventListener("click",async()=>{try{await navigator.clipboard.writeText($("pathValue").value);message($("recordMessage"),"Path copied.","success");}catch{message($("recordMessage"),"Clipboard is unavailable; select and copy the path manually.","");}});
$("addPathToIdentity").addEventListener("click",()=>{const path=$("pathValue").value.trim();if(!path){message($("recordMessage"),"Enter a path first.","error");return;}if(!state.identities.length)addIdentity();const selected=state.selectedIdentity??0;const target=state.identities[selected]||state.identities[0];if(!target.evidence_paths.includes(path))target.evidence_paths.push(path);renderIdentities();});

async function loadSmokeOptions(){
  const options=await api("/api/smoke/options");state.models=options.model_readiness.models;
  state.models.forEach(model=>{const option=document.createElement("option");option.value=model.alias;option.disabled=!model.ready;const serverState=!model.server_reachable?"server unavailable":model.server_model_match?"model loaded":"model not loaded";option.textContent=`${model.alias} — ${model.weights_available?"weights available":"weights missing"}; ${serverState}; ${model.ready?"ready":model.reason}`;$("smokeModel").append(option);});
  const ready=state.models.filter(model=>model.ready).length,weights=state.models.filter(model=>model.weights_available).length,loaded=state.models.filter(model=>model.server_model_match).length;
  $("smokeModelStatus").textContent=`Configured endpoint: ${options.model_readiness.endpoint} · Server ${options.model_readiness.server_reachable?`reachable (${options.model_readiness.server_models.join(", ")||"no model IDs reported"})`:`unavailable (${options.model_readiness.server_error})`} · GGUF weights ${weights}/${state.models.length}; model loaded ${loaded}/${state.models.length}; ready ${ready}/${state.models.length}. Unavailable models are disabled.`;
  const nvd=options.model_readiness.nvd_api||{endpoint:"https://services.nvd.nist.gov/rest/json/cpes/2.0",api_key_configured:false,min_interval_seconds:6.1};
  $("nvdApiStatus").textContent=`Deterministic CPE source: NVD CPE API 2.0 · ${nvd.endpoint} · API key ${nvd.api_key_configured?"configured":"not configured (public rate limit)"} · pacing ${nvd.min_interval_seconds}s/request · API connectivity is exercised when an eligible extracted identity is looked up.`;
  updateSmokeModel();
}
function updateSmokeModel(){$("smokeModel").disabled=$("smokeMethod").value==="deterministic"||!state.models.some(model=>model.ready);}
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
    $("jobOutput").textContent=job.output_paths?Object.values(job.output_paths).join("\n"):job.output_path;
    $("jobSummary").textContent=job.summary?JSON.stringify(job.summary,null,2):(job.error||"Waiting for results…");
    if(job.state==="running")state.jobTimer=setTimeout(()=>pollJob(jobId),700);else state.jobTimer=null;
  }catch(error){message($("smokeMessage"),error.message,"error");}
}

Promise.all([loadRecords(),loadSmokeOptions()]).catch(error=>message($("recordMessage"),error.message,"error"));
