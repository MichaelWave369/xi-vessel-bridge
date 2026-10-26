"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const fs=require("node:fs");
const core=require("../roadmap/charter-core.js");
const roadmap=JSON.parse(fs.readFileSync("roadmap/bridge-roadmap.json","utf8"));
function source(){
 const known={
  fixture:{
   schema:"PhiXi.R18SyntheticFixture.v1",
   payload_b64:"UEhJLVhJIFIxOCBTWU5USEVUSUMgRElHRVNUIEZJWFRVUkUgdjEKTk8gUFJJVkFURSBEQVRBOyBOTyBBVVRIT1JJVFk7IE5PIFJFTU9URSBSSUdIVFMuCg==",
   size_bytes:88,sha256:core.FIXTURE_SHA,origin:"PHI369-local-synthetic-fixture",
   intended_use:"digest-only offline operator rehearsal",
   classification:"synthetic_public",authority:"none",live_xi_connected:false
  },
  preflight:{
   schema:"PhiXi.R18PilotDraft.v1",status:"draft_no_approval",transport:"unconfigured",
   endpoint_reference:null,native_schema_sha256:null,xi_peer_pin:null,phi_peer_pin:null,
   phi_operator_approval:false,xi_operator_approval:false,transport_security_verified:false,
   provenance_verified:false,durable_receipts_verified:false,independent_revocation_verified:false,
   data_classification:"synthetic_public",scope:"digest_only",live_xi_connected:false,authority:"none"
  },roadmap
 };
 if(fs.existsSync("dist/handoff/synthetic-fixture.json")){
  known.fixture=JSON.parse(fs.readFileSync("dist/handoff/synthetic-fixture.json","utf8"));
  known.preflight=JSON.parse(fs.readFileSync("dist/handoff/pilot-preflight-draft.json","utf8"));
 }
 return JSON.parse(JSON.stringify(known));
}
test("R18 original R18 source artifacts qualify without promoting permissions",()=>{
 const inspected=core.validateSources(source());
 assert.equal(inspected.fixture.sha256,core.FIXTURE_SHA);
 assert.equal(inspected.fixture.size_bytes,88);
 assert.equal(inspected.roadmap.missing,16);
 assert.equal(inspected.preflight.status,"draft_no_approval");
});
test("both variant charters contain only public 88-byte read-only proposal",()=>{
 for(const variant of core.VARIANTS){
  const doc=core.charter(source(),variant);
  assert.deepEqual(core.validateCharter(doc),doc);
  assert.equal(doc.approved_operations,0);
  assert.equal(doc.independently_verified_external_gates,0);
  assert.equal(doc.evidence_gates_missing,16);
  assert.equal(doc.operation.name,"artifact.sha256");
  assert.equal(doc.operation.max_payload_bytes,88);
  assert.equal(doc.operation.peer_data_included,false);
  assert.equal(doc.operation.dry_run_only,true);
  assert.equal(doc.transport.endpoint,null);
  assert.equal(doc.transport.encrypted_authenticated,false);
  assert.equal(doc.identities.xi_public_key_pin,null);
  assert.equal(doc.identities.phi_public_key_pin,null);
  assert.deepEqual(Object.values(doc.approvals),[false,false,false]);
  assert.equal(doc.live_xi_connected,false);
  assert.equal(doc.real_two_physical_hosts_tested,false);
  assert.equal(doc.authority,"none");
  assert.equal(doc.r17_external_pilot,"BLOCKED");
  assert.equal(doc.r18_real_two_host_pilot,"NOT_RUN");
 }
});
test("scope variants only change suggested questions, never permissions",()=>{
 const minimal=core.charter(source(),"single_digest_only");
 const full=core.charter(source(),"digest_and_candidate_negative_controls");
 assert.equal(minimal.proposed_negative_controls.length,0);
 assert.equal(full.proposed_negative_controls.length,13);
 assert.equal(minimal.approved_operations,full.approved_operations);
 assert.equal(minimal.authority,full.authority);
 assert.deepEqual(minimal.approvals,full.approvals);
 assert.deepEqual(minimal.transport,full.transport);
 assert.throws(()=>core.charter(source(),"remote_repo_write"),/scope/);
});
test("altered R18 fixture byte content, digest, classification, or secret rejected",()=>{
 const tests=[
  f=>{f.fixture.payload_b64="QUJD";},
  f=>{f.fixture.sha256="0".repeat(64);},
  f=>{f.fixture.size_bytes=4096;},
  f=>{f.fixture.classification="private_data";},
  f=>{f.fixture.live_xi_connected=true;},
  f=>{f.fixture.peer_private_key="secret";}
 ];
 for(const edit of tests){const f=source();edit(f);assert.throws(()=>core.validateSources(f),/fixture|synthetic/i);}
});
test("modified preflight grants, pins, and remote transport refused",()=>{
 const tests=[
  f=>{f.preflight.phi_operator_approval=true;},
  f=>{f.preflight.xi_operator_approval=true;},
  f=>{f.preflight.phi_peer_pin="self-claimed";},
  f=>{f.preflight.xi_peer_pin="self-claimed";},
  f=>{f.preflight.endpoint_reference="https://xi.example";},
  f=>{f.preflight.transport="live";},
  f=>{f.preflight.data_classification="private";},
  f=>{f.preflight.native_schema_sha256="0".repeat(64);},
  f=>{f.preflight.authority="admin";}
 ];
 for(const edit of tests){const f=source();edit(f);assert.throws(()=>core.validateSources(f),/preflight|approval/i);}
});
test("roadmap drift, duplicate or promoted gates rejected",()=>{
 for(const edit of [
  f=>{f.roadmap.gates[0].state="verified";},
  f=>{f.roadmap.gates.splice(0,1);},
  f=>{f.roadmap.gates[1].id=f.roadmap.gates[0].id;},
  f=>{f.roadmap.milestones.find(x=>x.id==="R17").state="complete";},
  f=>{f.roadmap.live_xi_connected=true;}
 ]){
  const f=source();edit(f);assert.throws(()=>core.validateSources(f),/roadmap|gate|clearance/i);
 }
});
test("export safety validation catches injected approvals, endpoints and privileges",()=>{
 const transforms=[
  x=>{x.approvals.xi_operator=true;},
  x=>{x.approvals.phi_operator=true;},
  x=>{x.transport.endpoint="https://private.example";},
  x=>{x.transport.status="READY";},
  x=>{x.identities.xi_public_key_pin="forge-key";},
  x=>{x.operation.name="shell.exec";},
  x=>{x.operation.read_only=false;},
  x=>{x.operation.source_fixture_sha256="0".repeat(64);},
  x=>{x.approved_operations=1;},
  x=>{x.live_xi_connected=true;},
  x=>{x.evidence_gates_missing=0;},
  x=>{x.exfiltrate="url";}
 ];
 for(const change of transforms){
  const x=core.charter(source(),"single_digest_only");
  change(x);assert.throws(()=>core.validateCharter(x),/Charter|Identity|Transport|Approvals|Operation|prerequisite|stage/i);
 }
});
test("copy text discloses no secret and never presents the plan as approved",()=>{
 const doc=core.charter(source(),"digest_and_candidate_negative_controls");
 const text=core.textForRoom(doc);
 assert.match(text,/UNAPPROVED/);
 assert.match(text,/Xi ⇄ Φ369/);
 assert.match(text,/88-byte/);
 assert.match(text,/TWO distinct human/);
 assert.match(text,/R18 real two-host pilot NOT RUN/);
 assert.match(text,/NOT an approval or permission grant/);
 assert.doesNotMatch(text,/Bearer [\w.-]+|BEGIN RSA PRIVATE KEY/);
});
test("UI reads only fixed same-origin public source JSON and exports on human click",()=>{
 const html=fs.readFileSync("roadmap/charter.html","utf8");
 const script=fs.readFileSync("roadmap/charter.js","utf8");
 assert.match(html,/Synthetic Pilot Charter Studio/);
 assert.match(html,/connect-src 'self'/);
 for(const file of ["synthetic-fixture.json","pilot-preflight-draft.json","bridge-roadmap.json"])
   assert.ok(script.includes(file),file);
 assert.match(script,/addEventListener\("click"/);
 assert.match(script,/textContent/);
 assert.match(script,/navigator\.clipboard\.writeText/);
 assert.doesNotMatch(script,/\bWebSocket\b|\bXMLHttpRequest\b|\bsendBeacon\b|\blocalStorage\b|\bsessionStorage\b|\binnerHTML\b|\bnavigator\.credentials\b/);
 assert.doesNotMatch(html,/<form\b|<iframe\b|type="password"/);
});
