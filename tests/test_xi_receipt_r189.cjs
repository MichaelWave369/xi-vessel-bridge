"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const r=require("../reference/js/xi_receipt_r189.cjs");

test("all four local-only candidates are strict canonical public bytes",()=>{
 assert.deepEqual(Object.keys(r.CASES),["digest","policy","replay","revoked"]);
 for(const id of Object.keys(r.CASES)){
  const b=r.emit(id),v=r.verify(b),doc=JSON.parse(b);
  assert.ok(b.equals(r.canonical(doc)));
  assert.equal(v.case_id,id);
  assert.equal(v.status,"CANONICAL_BYTES_MATCH_UNAUTHENTICATED");
  assert.equal(v.independent_signatures_verified,0);
  assert.equal(v.approved_operations,0);
  assert.equal(v.authority,"none");
  assert.equal(doc.subject.bytes,88);
  assert.equal(doc.subject.sha256,r.FIXTURE_SHA);
  assert.equal(doc.observed_exchange,false);
  assert.equal(doc.r17_external_pilot,"BLOCKED");
  assert.equal(doc.r18_real_two_host_pilot,"NOT_RUN");
 }
});
test("frozen golden vectors match independent Node emission",()=>{
 const fs=require("node:fs");
 const crypto=require("node:crypto");
 const pins=JSON.parse(fs.readFileSync("fixtures/r189-golden-digests.json","utf8"));
 assert.equal(pins.schema,"PhiXi.R18_9_GoldenDigests.v1");
 assert.equal(pins.source_payload_sha256,r.FIXTURE_SHA);
 assert.deepEqual(Object.keys(pins.cases),Object.keys(r.CASES));
 for(const [caseId,pin] of Object.entries(pins.cases)){
  const actual=r.emit(caseId);
  assert.equal(actual.length,pin.bytes);
  assert.equal(crypto.createHash("sha256").update(actual).digest("hex"),pin.sha256);
 }
});
test("never confuse shape, pretty-printed JSON, duplicate keys or order for exact bytes",()=>{
 const original=r.emit("digest"),doc=r.make("digest");
 const variants=[
  Buffer.from(JSON.stringify(doc)+"\n"),
  Buffer.from(JSON.stringify(doc,null,2)),
  original.subarray(0,original.length-1),
  Buffer.concat([original,Buffer.from("\n")]),
  Buffer.concat([Buffer.from(" "),original]),
  Buffer.from(original.toString().replace('"approved_operations":0,','"approved_operations":0,"approved_operations":0,')),
 ];
 for(const b of variants)assert.throws(()=>r.verify(b));
});
test("mutated approval, identity, remote scope and claimed observed exchange refused",()=>{
 const mutations=[
  x=>{x.authority="admin";},x=>{x.approved_operations=1;},
  x=>{x.live_xi_connected=true;},x=>{x.operator_approvals=1;},
  x=>{x.independent_signatures_verified=1;},x=>{x.observed_exchange=true;},
  x=>{x.subject.operation="shell.exec";},x=>{x.subject.sha256="0".repeat(64);},
  x=>{x.subject.bytes=89;},x=>{x.subject.classification="private";},
  x=>{x.parties=["actual-xi-peer","phi-sim"];},x=>{x.transport="https://xi.example";},
  x=>{x.r18_real_two_host_pilot="COMPLETE";},
 ];
 for(const update of mutations){
  const x=r.make("digest");update(x);
  assert.throws(()=>r.verify(r.canonical(x)));
 }
});
test("unsupported Unicode, floats, negative and unsafe integers refused",()=>{
 for(const x of [{"message":"Ξ"},{"num":3.14},{"num":-1},{"num":Number.MAX_SAFE_INTEGER+1},{"x":null},
  {"message":"line\nbreak"}]){
  assert.throws(()=>r.canonical(x));
 }
});
test("unrecognized case, missing input and claimed live capability refused",()=>{
 assert.throws(()=>r.emit("admin"));
 assert.throws(()=>r.verify(Buffer.from("{}")));
 assert.throws(()=>r.verify(Buffer.alloc(5000)));
 assert.equal(r.main(["require-live"]),2);
});
