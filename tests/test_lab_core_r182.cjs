"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const core = require("../roadmap/lab-core.js");
const fixture = JSON.parse(fs.readFileSync("roadmap/bridge-roadmap.json","utf8"));
function witness() {
 return {
  status:"R18_1_TWO_HOUSE_LOCAL_SIMULATION_PASS",
  process_count:2, distinct_ephemeral_identity_keys:true,
  bilateral_r16_handshake:true,
  signed_xi_exchange_v1_shaped_digest_roundtrip:true,
  bidirectional_local_digest:true,
  durable_request_replay_refused_after_restart:true,
  receiver_pause_refused:true, receiver_revocation_survived_restart:true,
  source_fixture_sha256:core.PAYLOAD_HASH, permitted_operation:"artifact.sha256",
  cross_host_network:false, physical_hosts:1, real_xi_peer_verified:false,
  two_physical_hosts_confirmed:false, live_xi_connected:false,
  r17_external_pilot:"BLOCKED", r18_real_two_host_pilot:"NOT_RUN",
  authority:"none",
  qualification:"Two local synthetic processes, fixture-only cryptography and permissions."
 };
}
test("exact R18.1 witness shape remains untrusted even if valid",()=>{
 const checked=core.validateWitness(witness());
 assert.equal(checked.checked_count,7);
 assert.equal(checked.classification,"LOCAL_FIXTURE_SELF_REPORT_UNTRUSTED");
 assert.equal(checked.independently_authenticated_xi_receipts,0);
 assert.equal(checked.external_gates_promoted,0);
 assert.equal(checked.live_xi_connected,false);
 assert.equal(checked.physical_hosts,1);
});
test("illustrative preview requires explicit non-evidence marker",()=>{
 const v={schema:core.SCHEMA,preview_only:true,classification:"illustrative_fixture_not_fresh_run",witness:witness()};
 assert.equal(core.validatePreview(v).shape,"R18_1_WITNESS_SHAPE_VALID_ONLY");
 assert.throws(()=>core.validatePreview({...v,preview_only:false}),/illustrative/);
 assert.throws(()=>core.validatePreview({...v,classification:"live_verified"}),/illustrative/);
 assert.throws(()=>core.validatePreview({...v,authority:"Xi"}),/additional/);
});
test("extra privilege, identities and secrets refused",()=>{
 for(const [field,value] of [["authority","admin"],["live_xi_connected",true],
  ["two_physical_hosts_confirmed",true],["real_xi_peer_verified",true],
  ["cross_host_network",true],["r18_real_two_host_pilot","PASS"],
  ["r17_external_pilot","APPROVED"],["permitted_operation","shell.exec"],
  ["source_fixture_sha256","0".repeat(64)],["physical_hosts",2],
  ["process_count",3],["bilateral_r16_handshake","true"]]) {
  const doc=witness(); doc[field]=value;
  assert.throws(()=>core.validateWitness(doc),/unexpected|authority/i,field);
 }
 const bad=witness(); bad.private_key="secret";
 assert.throws(()=>core.validateWitness(bad),/fields/);
});
test("missing proof flags and extra keys never pass",()=>{
 const doc=witness();delete doc.receiver_revocation_survived_restart;
 assert.throws(()=>core.validateWitness(doc),/fields/);
 assert.throws(()=>core.validateWitness(null),/object/);
 assert.throws(()=>core.validateWitness([]),/object/);
});
test("read-only 16-gate source snapshot never unlocks external pilot",()=>{
 const result=core.validateGates(fixture);
 assert.equal(result.blocked,16);
 assert.equal(result.verified,0);
 assert.ok(result.gates.every(g=>["missing","candidate_unverified"].includes(g.state)));
});
test("roadmap with promoted gates, live claims or duplicated IDs refused",()=>{
 const clone=()=>JSON.parse(JSON.stringify(fixture));
 let x=clone();x.live_xi_connected=true;
 assert.throws(()=>core.validateGates(x),/roadmap/);
 x=clone();x.gates[0].state="verified";
 assert.throws(()=>core.validateGates(x),/gate/);
 x=clone();x.gates[1].id=x.gates[0].id;
 assert.throws(()=>core.validateGates(x),/gate/);
 x=clone();x.gates.pop();
 assert.throws(()=>core.validateGates(x),/roadmap/);
});
test("redacted export has no transcript, identities or signer claims",()=>{
 const bytes=Buffer.from(JSON.stringify(witness()));
 const digest=crypto.createHash("sha256").update(bytes).digest("hex");
 const report=core.redactedReview("IMPORTED_UNTRUSTED_WITNESS",digest,
   core.validateWitness(witness()),core.validateGates(fixture));
 assert.equal(report.schema,core.REVIEW);
 assert.equal(report.external_gates_outstanding,16);
 assert.equal(report.external_gates_promoted,0);
 assert.equal(report.independently_authenticated_xi_receipts,0);
 assert.equal(report.authority,"none");
 assert.ok(!/private_key|payload_b64|client_nonce|signed_envelope|peer_pin|session_id/i.test(JSON.stringify(report)));
 assert.throws(()=>core.redactedReview("VERIFIED_XI",digest,core.validateWitness(witness())),/unscreened/);
 assert.throws(()=>core.redactedReview("IMPORTED_UNTRUSTED_WITNESS","bad",core.validateWitness(witness())),/unscreened/);
});
test("UI uses textContent and local file bytes, never sends partner data offsite",()=>{
 const html=fs.readFileSync("roadmap/lab.html","utf8");
 const ui=fs.readFileSync("roadmap/lab.js","utf8");
 assert.match(html,/Partner intake/);
 assert.match(html,/LIVE XI CONNECTION: NOT ESTABLISHED/);
 assert.match(html,/type="file"/);
 assert.match(html,/src="\.\/lab-core\.js"/);
 assert.match(html,/src="\.\/lab\.js"/);
 assert.match(html,/connect-src 'self'/);
 assert.match(ui,/file\.arrayBuffer\(\)/);
 assert.match(ui,/textContent/);
 assert.doesNotMatch(ui,/localStorage|sessionStorage|XMLHttpRequest|sendBeacon|WebSocket|innerHTML|importScripts|navigator\.credentials/);
 assert.doesNotMatch(html,/<iframe\b|<form\b/);
});
test("the generated preview if present matches strict source-derived contract",()=>{
 const filename="dist/lab-preview.json";
 if(!fs.existsSync(filename))return;
 const preview=JSON.parse(fs.readFileSync(filename,"utf8"));
 assert.equal(core.validatePreview(preview).checked_count,7);
 assert.equal(preview.witness.physical_hosts,1);
 assert.equal(preview.witness.live_xi_connected,false);
});
