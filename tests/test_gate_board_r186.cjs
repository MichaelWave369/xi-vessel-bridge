"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs");
const core=require("../roadmap/gates-core.js");
const fixture=JSON.parse(fs.readFileSync("roadmap/bridge-roadmap.json","utf8"));
const copy=()=>JSON.parse(JSON.stringify(fixture));
test("source-qualified board covers exactly sixteen outstanding external gates",()=>{
 const b=core.review(fixture);
 assert.equal(b.remaining_external_gates,16);
 assert.equal(b.verified_external_gates,0);
 assert.equal(b.classification,"PHI_PROPOSED_DISCUSSION_ORDER_ONLY");
 assert.equal(b.live_xi_connected,false);
 assert.equal(b.authority,"none");
 assert.equal(b.groups.length,4);
 assert.deepEqual(b.groups.flatMap(g=>g.gates.map(x=>x.id)),core.IDS);
 assert.ok(b.groups.flatMap(g=>g.gates).every(x=>x.state==="OUTSTANDING_SOURCE_GATE"));
});
test("no gate promotion, false live state, missing/unknown gate or extra keys",()=>{
 const changes=[
  x=>{x.live_xi_connected=true;},
  x=>{x.status="ready";},
  x=>{x.gates[0].state="verified";},
  x=>{x.gates[0].authority="admin";},
  x=>{x.gates=x.gates.slice(1);},
  x=>{x.gates[1].id=x.gates[0].id;},
  x=>{x.gates[0].owner="Xi approved";},
  x=>{x.milestones.find(m=>m.id==="R18").state="complete";}
 ];
 for(const mutate of changes){const x=copy();mutate(x);assert.throws(()=>core.review(x),/source|roadmap|readiness|Unreviewed|map/,JSON.stringify(x).slice(0,50));}
});
test("selecting the agenda cannot change source or grant consent",()=>{
 const before=JSON.stringify(fixture);
 const b=core.review(fixture);
 const doc=core.agenda(b,["native_contract","identity","two_operator_approval"]);
 assert.equal(JSON.stringify(fixture),before);
 assert.equal(doc.schema,core.SCHEMA);
 assert.equal(doc.authority,"none");
 assert.equal(doc.approved_operations,0);
 assert.equal(doc.externally_verified_gates,0);
 assert.equal(doc.external_gates_remaining,16);
 assert.equal(doc.r17_external_pilot,"BLOCKED");
 assert.equal(doc.r18_real_two_host_pilot,"NOT_RUN");
 assert.deepEqual(doc.topics.map(t=>t.id),["native_contract","identity","two_operator_approval"]);
 assert.ok(doc.topics.every(x=>x.status==="DISCUSSION_ONLY_NOT_APPROVED"));
});
test("agenda rejects unknown, repeated, forged or empty topics",()=>{
 const b=core.review(fixture);
 for(const arr of [[],["unknown"],["identity","identity"],new Array(17).fill("identity")]){
  assert.throws(()=>core.agenda(b,arr),/Choose|repeated|Unverified/);
 }
 assert.throws(()=>core.agenda({...b,authority:"Xi"},["identity"]),/Unverified/);
});
test("copied message is public human discussion, never an approval",()=>{
 const b=core.review(fixture);
 const msg=core.agendaText(core.agenda(b,["identity","consent"]));
 assert.match(msg,/NOT APPROVAL/);
 assert.match(msg,/both humans/);
 assert.match(msg,/NOT RUN/);
 assert.match(msg,/All 16 external evidence gates remain outstanding/);
 assert.doesNotMatch(msg,/BEGIN RSA PRIVATE KEY|Bearer /);
 assert.throws(()=>core.agendaText({schema:core.SCHEMA,authority:"admin"}),/unapproved/);
});
test("UI has no external Xi calls, saves no user data and only exports public agenda",()=>{
 const html=fs.readFileSync("roadmap/gates.html","utf8");
 const js=fs.readFileSync("roadmap/gates.js","utf8");
 assert.match(html,/connect-src 'self'/);
 assert.match(html,/source roadmap gates/);
 assert.match(html,/id="copy"/);
 assert.match(html,/id="export"/);
 assert.match(js,/fetch\("\.\/bridge-roadmap\.json"/);
 assert.match(js,/navigator\.clipboard\.writeText/);
 assert.match(js,/textContent/);
 assert.doesNotMatch(js,/localStorage|sessionStorage|XMLHttpRequest|WebSocket|sendBeacon|innerHTML|credentials|fetch\("\/\/|fetch\("https/);
 assert.doesNotMatch(html,/<iframe\b|<form\b/);
});
