"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs");
const lab=require("../roadmap/fault-core.js");

test("exactly fourteen fixed scenarios, no dynamic request target",()=>{
 assert.equal(lab.CASES.length,14);
 assert.equal(new Set(lab.CASES.map(s=>s.id)).size,14);
 assert.ok(Object.isFrozen(lab.CASES));
 for(const sc of lab.CASES)assert.ok(Object.isFrozen(sc));
 assert.throws(()=>lab.runScenario("https://xi.example/steal"),/Unknown fixed/);
 assert.throws(()=>lab.runScenario({id:"baseline"}),/Unknown fixed/);
});
test("all deterministic scenarios match their declared fail-closed outcome",()=>{
 const runs=lab.runAll();
 assert.equal(runs.length,14);
 assert.ok(runs.every(x=>x.pass===true));
 assert.deepEqual(runs.map(x=>x.scenario_id),lab.CASES.map(x=>x.id));
 assert.ok(runs.every(x=>x.authority==="none"&&x.live_xi_connected===false));
 assert.ok(runs.every(x=>x.physical_hosts===1&&x.independent_xi_evidence===0));
 assert.ok(runs.every(x=>x.abstract_signature_only===true));
 assert.deepEqual(runs,lab.runAll());
});
test("baseline is one synthetic commit and accepted receipt",()=>{
 const v=lab.runScenario("baseline");
 assert.equal(v.observed,"ACCEPTED");assert.equal(v.receiver_commits,1);
 assert.equal(v.requester_confirmed,true);assert.equal(v.duplicate_retry_refused,false);
});
test("invalid auth, recipient, time, session, policy and control reject before committing",()=>{
 for(const id of ["wrong-peer","wrong-recipient","signature-tamper","expired",
 "wrong-session","scope-escalation","receiver-deny","paused","revoked","duplicate","restart-replay"]){
  const v=lab.runScenario(id);
  assert.equal(v.observed,"REFUSED",id);
  assert.equal(v.receiver_commits,0,id);
  assert.equal(v.requester_confirmed,false,id);
  assert.ok(v.trace.some(s=>s.decision==="DENIED"),id);
 }
});
test("restart preserves abstract durable consumed ID",()=>{
 const v=lab.runScenario("restart-replay");
 assert.equal(v.denial_reason,"DURABLE_REPLAY_DENIED");
 assert.ok(v.trace.some(x=>x.stage==="restart" && x.decision==="LEDGER_RESTORED"));
});
test("receipt tamper cannot be confirmed, even after receiver consumes ID",()=>{
 const v=lab.runScenario("receipt-tamper");
 assert.equal(v.observed,"RESULT_REFUSED");assert.equal(v.receiver_commits,1);
 assert.equal(v.requester_confirmed,false);
 assert.ok(v.trace.some(x=>x.house==="PHI-SIM"&&x.decision==="DENIED"));
});
test("lost reply blocks replay without claiming guaranteed delivery",()=>{
 const v=lab.runScenario("lost-reply");
 assert.equal(v.observed,"RETRY_REFUSED");
 assert.equal(v.receiver_commits,1);
 assert.equal(v.requester_confirmed,false);
 assert.equal(v.duplicate_retry_refused,true);
 assert.ok(v.trace.some(x=>x.decision==="DROPPED"));
});
test("export contains no hidden raw envelope, keys, timestamps or Xi authority",()=>{
 const report=lab.exportReview(lab.runAll());
 assert.equal(report.schema,lab.REPORT_SCHEMA);
 assert.equal(report.scenarios_passed,14);
 assert.equal(report.physical_hosts,1);
 assert.equal(report.independent_xi_evidence,0);
 assert.equal(report.external_gates_promoted,0);
 assert.equal(report.live_xi_connected,false);
 assert.equal(report.authority,"none");
 assert.equal(report.r18_real_two_host_pilot,"NOT_RUN");
 assert.equal(report.r17_external_pilot,"BLOCKED");
 const raw=JSON.stringify(report);
 assert.doesNotMatch(raw,/private_key|signatureShapeValid|expectedRecipient|created|expires|session_id|proof_sha256|bearer|grant_admin|payload_b64/);
});
test("report export refuses unknown, forged, and duplicate outcomes",()=>{
 assert.throws(()=>lab.exportReview([]),/No valid/);
 assert.throws(()=>lab.exportReview([lab.runScenario("baseline"),lab.runScenario("baseline")]),/Duplicate/);
 let changed={...lab.runScenario("baseline"),authority:"admin"};
 assert.throws(()=>lab.exportReview([changed]),/Unrecognized/);
 changed={...lab.runScenario("baseline"),pass:false};
 assert.throws(()=>lab.exportReview([changed]),/Unrecognized/);
});
test("public UI enforces no Xi network, no dynamic HTML or credentials",()=>{
 const html=fs.readFileSync("roadmap/fault.html","utf8");
 const client=fs.readFileSync("roadmap/fault.js","utf8");
 const core=fs.readFileSync("roadmap/fault-core.js","utf8");
 for(const s of ["connect-src 'none'","script-src 'self'","src=\"./fault-core.js\"","src=\"./fault.js\"","Run all 14 cases","LIVE_XI_CONNECTED=false"])
  assert.ok(html.includes(s),s);
 assert.doesNotMatch(html,/<form\b|<iframe\b|onerror=|onload=/);
 assert.doesNotMatch(client+core,/\bfetch\(|\bWebSocket\b|\bXMLHttpRequest\b|\bsendBeacon\b|\bpostMessage\b|\blocalStorage\b|\bsessionStorage\b|\binnerHTML\b|\bFunction\(/);
 assert.match(client,/textContent/);
 assert.match(client,/createObjectURL/);
});
