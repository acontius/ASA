"use strict";
const $ = (id) => document.getElementById(id);
const state = {cases: [], selected: null, current: null};
async function api(path, options={}) {
  const response = await fetch(path, {cache:"no-store", ...options, headers:{"Content-Type":"application/json", ...(options.headers||{})}});
  const value = await response.json().catch(()=>({error:"Invalid local response"}));
  if (!response.ok) throw new Error(value.error || `Request failed (${response.status})`);
  return value;
}
function el(tag, text, className="") {
  const node=document.createElement(tag); node.textContent=text??""; if(className) node.className=className; return node;
}
function showMessage(text, error=false) { $("message").textContent=text||""; $("message").className=error?"error":"muted"; }
async function loadCases() {
  const result=await api(`/api/cases?q=${encodeURIComponent($("search").value.trim())}&status=${encodeURIComponent($("filter").value)}`);
  state.cases=result.cases; $("integrity").textContent=`${result.total} cases · ${result.source_malformed} malformed source rows · ${result.manifest_errors.length} manifest errors · ${result.gold_errors.length} Gold errors`;
  const list=$("caseList"); list.replaceChildren();
  if(!state.cases.length) list.append(el("p","No cases match."));
  for(const item of state.cases) {
    const button=el("button",`${item.cve_id}\n${item.source_record_id}\n${item.status}`,"case"); button.type="button";
    if(item.case_id===state.selected) button.classList.add("selected");
    if(item.stale) button.classList.add("stale");
    button.addEventListener("click",()=>loadCase(item.case_id)); list.append(button);
  }
}
function renderMeta(manifest) {
  const cve=manifest.cve_snapshot; const meta=$("cveMeta"); meta.replaceChildren();
  meta.append(el("p",`${cve.cve_id} · published ${cve.published||"unknown"} · modified ${cve.last_modified||"unknown"}`));
  for(const description of cve.descriptions||[]) if(description?.lang==="en") meta.append(el("p",description.value));
  meta.append(el("pre",JSON.stringify(cve.metrics||{},null,2)));
  $("configurations").textContent=cve.configurations_present?JSON.stringify(cve.configurations,null,2):"NVD response has no configurations field.";
}
function renderChoices(current) {
  const evidence=$("evidenceChoices"); evidence.replaceChildren();
  for(const row of current.evidence) {
    const label=document.createElement("label"); label.className="choice";
    const checkbox=document.createElement("input"); checkbox.type="checkbox"; checkbox.value=row.path; checkbox.dataset.kind="evidence";
    label.append(checkbox,el("span",`${row.path}\n${row.found?row.value:"[path not found in current scan record]"}`)); evidence.append(label);
  }
  const identities=$("identityChoices"); identities.replaceChildren();
  for(const row of current.manifest.asset_snapshot.identities) {
    const label=document.createElement("label"); label.className="choice";
    const checkbox=document.createElement("input"); checkbox.type="checkbox"; checkbox.value=row.identity_id; checkbox.dataset.kind="identity";
    label.append(checkbox,el("span",`${row.identity_id} · ${row.resolution_status} · ${row.cpe23||"no CPE"}`)); identities.append(label);
  }
}
async function loadCase(caseId) {
  try {
    const current=await api(`/api/case?case_id=${encodeURIComponent(caseId)}`); state.selected=caseId; state.current=current;
    const m=current.manifest; $("title").textContent=`${m.cve_snapshot.cve_id} · asset ${m.source_record_id}`;
    $("stale").classList.toggle("hidden",!current.stale);
    $("stale").textContent=current.stale?"Source hash changed. Regenerate the manifest before annotating this case.":"";
    $("evidence").replaceChildren();
    if(!current.evidence.length) $("evidence").append(el("p","No evidence paths were linked to this case."));
    for(const row of current.evidence) $("evidence").append(el("pre",`${row.path}\n${row.found?row.value:"[not found]"}`));
    $("identities").textContent=JSON.stringify(m.asset_snapshot.identities,null,2); renderMeta(m); renderChoices(current);
    $("priorReviews").textContent=current.gold?JSON.stringify({status:current.gold.annotation_status,label:current.gold.expected_applicability,reviews:current.gold.reviews,adjudication:current.gold.adjudication,history_count:current.gold.annotation_history.length},null,2):"No reviews yet.";
    $("save").disabled=current.stale || !m.cve_snapshot.configurations_hash;
    showMessage(""); await loadCases();
  } catch(error) { showMessage(error.message,true); }
}
$("action").addEventListener("change",()=>{
  const action=$("action").value;
  $("nonScoredWrap").classList.toggle("hidden",action!=="non_scored");
  $("label").disabled=action==="non_scored";
});
$("form").addEventListener("submit",async event=>{
  event.preventDefault(); if(!state.current) return;
  const action=$("action").value;
  const selected=[...document.querySelectorAll("input[data-kind]:checked")];
  const payload={case_id:state.selected,action,actor_id:$("actor").value.trim(),
    label:action==="non_scored"?null:$("label").value,
    status:action==="non_scored"?$("nonScored").value:undefined,
    reason_codes:$("reasons").value.split(",").map(x=>x.trim()).filter(Boolean),
    notes:$("notes").value,
    evidence_paths:selected.filter(x=>x.dataset.kind==="evidence").map(x=>x.value),
    identity_ids:selected.filter(x=>x.dataset.kind==="identity").map(x=>x.value),
    configuration_references:$("configRefs").value.split("\n").map(x=>x.trim()).filter(Boolean)};
  if(payload.status===undefined) delete payload.status;
  try { const result=await api("/api/review",{method:"POST",body:JSON.stringify(payload)}); showMessage(`Saved: ${result.annotation_status} (${result.expected_applicability??"no truth label"}).`); await loadCase(state.selected); }
  catch(error) { showMessage(error.message,true); }
});
$("search").addEventListener("input",()=>loadCases().catch(error=>showMessage(error.message,true)));
$("filter").addEventListener("change",()=>loadCases().catch(error=>showMessage(error.message,true)));
loadCases().catch(error=>{ $("integrity").textContent=error.message; });
