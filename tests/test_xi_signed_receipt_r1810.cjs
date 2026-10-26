"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const signed=require("../reference/js/xi_signed_receipt_r1810.cjs");
const base=require("../reference/js/xi_receipt_r189.cjs");
const crypto=require("node:crypto");

test("four local-only Ed25519 signatures verified, no external trust promoted",()=>{
 const seen=new Set();
 for(const id of Object.keys(base.CASES)){
  const raw=signed.emit(id);
  const doc=JSON.parse(raw.toString("utf8"));
  const r=signed.verify(raw);
  assert.equal(r.status,"SELF_ISSUED_EPHEMERAL_SIGNATURE_MATH_VALID");
  assert.equal(r.case_id,id);
  assert.equal(r.self_issued_signature_verified,true);
  assert.equal(r.independent_partner_identity_verified,false);
  assert.equal(r.operator_approvals,0);
  assert.equal(r.approved_operations,0);
  assert.equal(r.external_gates_promoted,0);
  assert.equal(r.real_two_host_crossing_tested,false);
  assert.equal(r.live_xi_connected,false);
  assert.equal(r.authority,"none");
  assert.equal(doc.real_xi_identity_verified,false);
  assert.equal(doc.bilateral_consent_verified,false);
  assert.equal(doc.signed_exchange_observed,false);
  assert.equal(doc.r18_real_two_host_pilot,"NOT_RUN");
  assert.equal(base.verify(Buffer.from(doc.receipt_b64,"base64")).case_id,id);
  assert.equal(Buffer.from(doc.public_key_hex,"hex").length,32);
  assert.equal(Buffer.from(doc.signature_hex,"hex").length,64);
  seen.add(doc.public_key_hex);
 }
 assert.equal(seen.size,4,"ephemeral keys should differ");
});

test("signature binds domain-separated exact R18.9 bytes",()=>{
 const raw=signed.emit("digest"),doc=JSON.parse(raw);
 const receipt=Buffer.from(doc.receipt_b64,"base64");
 const message=Buffer.concat([signed.CONTEXT,receipt]);
 assert.equal(crypto.createHash("sha256").update(message).digest("hex"),doc.domain_message_sha256);
 assert.equal(crypto.createHash("sha256").update(receipt).digest("hex"),doc.receipt_sha256);
 const publicKey=crypto.createPublicKey({key:Buffer.concat([
  signed.SPKI_PREFIX,Buffer.from(doc.public_key_hex,"hex")
 ]),format:"der",type:"spki"});
 assert.equal(crypto.verify(null,message,publicKey,Buffer.from(doc.signature_hex,"hex")),true);
 // Without the protocol prefix this signature must fail.
 assert.equal(crypto.verify(null,receipt,publicKey,Buffer.from(doc.signature_hex,"hex")),false);
});

test("false Xi identities, consent, elevated grants and key/receipt tampering rejected",()=>{
 const actual=JSON.parse(signed.emit("digest"));
 const foreign=JSON.parse(signed.emit("policy"));
 const mutations=[
  x=>{x.real_xi_identity_verified=true;},
  x=>{x.bilateral_consent_verified=true;},
  x=>{x.approved_operations=1;},
  x=>{x.signed_exchange_observed=true;},
  x=>{x.live_xi_connected=true;},
  x=>{x.authority="admin";},
  x=>{x.self_issued=false;},
  x=>{x.signer_classification="HUNTER_AUTHENTICATED";},
  x=>{x.suite="Xi.Native.v1";},
  x=>{x.r17_external_pilot="CLEARED";},
  x=>{x.r18_real_two_host_pilot="PASS";},
  x=>{x.public_key_hex=foreign.public_key_hex;},
  x=>{x.signature_hex=foreign.signature_hex;},
  x=>{x.receipt_b64=foreign.receipt_b64;},
  x=>{x.receipt_sha256="0".repeat(64);},
  x=>{x.domain_message_sha256="0".repeat(64);},
  x=>{x.signer_email="operator@example.com";},
 ];
 for(const mutate of mutations){
  const x=JSON.parse(JSON.stringify(actual));mutate(x);
  assert.throws(()=>signed.verify(base.canonical(x)));
 }
});
test("noncanonical, duplicate key, invalid base64 and lost terminal LF rejected",()=>{
 const actual=signed.emit("digest");
 const changed=[
  actual.subarray(0,actual.length-1),
  Buffer.concat([actual,Buffer.from("\n")]),
  Buffer.from(" "+actual),
  Buffer.from(JSON.stringify(JSON.parse(actual),null,2)),
  Buffer.from(actual.toString().replace('"approved_operations":0,',
   '"approved_operations":0,"approved_operations":0,')),
 ];
 for(const b of changed)assert.throws(()=>signed.verify(b));
 const obj=JSON.parse(actual);
 obj.receipt_b64="!!!";
 assert.throws(()=>signed.verify(base.canonical(obj)));
});
test("unknown action and require-live are refused",()=>{
 assert.throws(()=>signed.emit("exec"));
 assert.throws(()=>signed.verify(Buffer.from("{}")));
 assert.throws(()=>signed.verify(Buffer.alloc(9999)));
 assert.equal(signed.main(["require-live"]),2);
});
