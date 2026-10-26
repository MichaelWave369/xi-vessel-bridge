"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const signed=require("../reference/js/xi_signed_receipt_r1810.cjs");
const base=require("../reference/js/xi_receipt_r189.cjs");
const pin=require("../reference/js/xi_pin_policy_r1811.cjs");

function material(){
 const first=signed.emit("digest"),second=signed.emit("digest");
 const a=JSON.parse(first).public_key_hex,b=JSON.parse(second).public_key_hex;
 assert.notEqual(a,b);
 return {first,second,a,b};
}
test("a valid Ed25519 signature from the wrong key is REFUSED",()=>{
 const {first,second,a}=material();
 const rules=pin.makeTestPolicy(a);
 const ok=pin.verify(first,rules);
 assert.equal(ok.status,"LOCAL_SIMULATED_PIN_MATCH_AND_SIGNATURE_VALID_ONLY");
 assert.equal(ok.simulated_local_pin_matched,true);
 assert.equal(ok.signature_mathematically_valid,true);
 assert.equal(ok.out_of_band_key_authentication_verified,false);
 assert.equal(ok.independent_partner_identity_verified,false);
 assert.equal(ok.approved_operations,0);
 assert.equal(ok.operator_approvals,0);
 assert.equal(ok.external_gates_promoted,0);
 assert.equal(ok.authority,"none");
 assert.equal(signed.verify(second).self_issued_signature_verified,true);
 assert.throws(()=>pin.verify(second,rules),/wrong key/);
});
test("explicit local policy rotation permits only new key and revokes old one",()=>{
 const {first,second,a,b}=material();
 const before=pin.makeTestPolicy(a,[],1);
 const after=pin.makeTestPolicy(b,[a],2);
 assert.equal(pin.verify(first,before).policy_epoch,1);
 assert.equal(pin.verify(second,after).policy_epoch,2);
 assert.throws(()=>pin.verify(first,after),/revoked/);
 assert.throws(()=>pin.verify(second,before),/wrong key/);
});
test("policy cannot claim identity, human approval, network or grants",()=>{
 const {first,a,b}=material();
 const source=JSON.parse(pin.makeTestPolicy(a));
 const invalid=[
  x=>{x.external_identity_verified=true;},
  x=>{x.operator_approvals=1;},
  x=>{x.approved_operations=1;},
  x=>{x.live_xi_connected=true;},
  x=>{x.authority="Xi";},
  x=>{x.policy_source="OUT_OF_BAND_VERIFIED";},
  x=>{x.scope="admin";},
  x=>{x.epoch=0;},
  x=>{x.revoked_public_key_hexes=[a];},
  x=>{x.revoked_public_key_hexes=[b,b];},
  x=>{x.private_key="malicious";},
 ];
 for(const mutate of invalid){
  const doc=structuredClone(source);
  mutate(doc);
  assert.throws(()=>pin.parsePolicy(base.canonical(doc)));
 }
 const other=pin.makeTestPolicy(b);
 assert.doesNotThrow(()=>pin.parsePolicy(other));
 assert.throws(()=>pin.verify(first,other));
});
test("canonical policy and signature integrity checked independently",()=>{
 const {first,a}=material();
 const good=pin.makeTestPolicy(a);
 const changed=[
  good.subarray(0,good.length-1),
  Buffer.concat([good,Buffer.from("\n")]),
  Buffer.from(JSON.stringify(JSON.parse(good),null,2)),
  Buffer.from(good.toString().replace('"approved_operations":0,',
   '"approved_operations":0,"approved_operations":0,')),
 ];
 for(const input of changed) assert.throws(()=>pin.parsePolicy(input));
 const tampered=JSON.parse(first);
 tampered.signature_hex="0".repeat(128);
 assert.throws(()=>pin.verify(base.canonical(tampered),good));
});
test("unknown/live status cannot be requested",()=>{
 assert.equal(pin.main(["require-live"]),2);
 assert.throws(()=>pin.verify(Buffer.from("{}"),Buffer.from("{}")));
});
