"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs");
const core=require("../roadmap/fault-core.js");
function good(){
 const commits=new Set(["baseline","duplicate","restart-replay","receipt-tamper","lost-reply"]);
 const conf=new Set(["baseline","duplicate","receipt-tamper"]);
 return {
  schema:core.WORKER_SCHEMA,
  classification:"LOCAL_TWO_PROCESS_CRYPTOGRAPHIC_FIXTURE_ONLY",
  status:"LOCAL_R18_4_GAUNTLET_PASS",case_count:14,passed_count:14,
  cases:core.CASES.map(s=>({
    scenario_id:s.id,expected:s.expected,observed:s.expected,
    pass:true,receiver_commits:commits.has(s.id)?1:0,
    requester_confirmed:conf.has(s.id),
    replay_refused_after_restart:s.id==="restart-replay",
    local_worker_processes:2,physical_hosts:1,real_ed25519_fixture:true,
    network_transport:false,live_xi_connected:false,authority:"none"
  })),
  physical_hosts:1,distinct_worker_processes_per_case:2,
  real_ed25519_fixture:true,actual_xi_peer_authenticated:false,
  remote_transport:false,independent_xi_receipts:0,external_gates_promoted:0,
  r17_external_pilot:"BLOCKED",r18_real_two_host_pilot:"NOT_RUN",
  live_xi_connected:false,authority:"none",
  qualification:"Executed signed local Python worker fixtures. Not a real Xi peer, network pilot, operator grant or independent security audit."
 };
}
test("real worker report shape is accepted as UNAUTHENTICATED imported evidence",()=>{
 const result=core.validateWorkerReport(good());
 assert.equal(result.shape,"R18_4_LOCAL_WORKER_REPORT_SHAPE_VALID_ONLY");
 assert.equal(result.classification,"IMPORTED_UNAUTHENTICATED_LOCAL_WORKER_SUMMARY");
 assert.equal(result.case_count,14);
 assert.equal(result.physical_hosts,1);
 assert.equal(result.external_gates_promoted,0);
 assert.equal(result.independent_xi_receipts,0);
});
test("false signed peer and live pilot promotion rejected",()=>{
 for(const [key,val] of [["actual_xi_peer_authenticated",true],["remote_transport",true],
  ["physical_hosts",2],["external_gates_promoted",1],["authority","admin"],
  ["live_xi_connected",true],["r17_external_pilot","READY"],["r18_real_two_host_pilot","PASS"],
  ["classification","VERIFIED_EXTERNAL_PEER"],["distinct_worker_processes_per_case",3],
  ["case_count",13]]){
  const x=good();x[key]=val;
  assert.throws(()=>core.validateWorkerReport(x),/refused/,key);
 }
});
test("case-level forged claims, fake passes and signer fields rejected",()=>{
 for(const [key,val] of [["observed","ACCEPTED"],["pass",false],
  ["physical_hosts",2],["receiver_commits",6],["requester_confirmed",true],
  ["real_ed25519_fixture",false],["authority","Xi"],["network_transport",true]]){
  const x=good();x.cases[4][key]=val;
  assert.throws(()=>core.validateWorkerReport(x),/Unrecognized/,key);
 }
 const x=good(); x.cases[0].signature="fake signed receipt";
 assert.throws(()=>core.validateWorkerReport(x),/Unrecognized/);
});
test("missing and reordered cases rejected",()=>{
 const x=good();x.cases=x.cases.slice(1);
 assert.throws(()=>core.validateWorkerReport(x),/refused/);
 const y=good();[y.cases[0],y.cases[1]]=[y.cases[1],y.cases[0]];
 assert.throws(()=>core.validateWorkerReport(y),/Unrecognized/);
});
test("browser UI imports only user-selected local bytes, reports untrusted status",()=>{
 const html=fs.readFileSync("roadmap/fault.html","utf8");
 const js=fs.readFileSync("roadmap/fault.js","utf8");
 assert.match(html,/id="r184-file"/);
 assert.match(html,/SHAPE VALID/);
 assert.match(html,/connect-src 'none'/);
 assert.match(js,/file\.arrayBuffer\(\)/);
 assert.match(js,/validateWorkerReport/);
 assert.match(js,/SOURCE UNAUTHENTICATED/);
 assert.doesNotMatch(js,/fetch\(|XMLHttpRequest|sendBeacon|WebSocket|localStorage|innerHTML/);
});
