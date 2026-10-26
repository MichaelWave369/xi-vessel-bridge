#!/usr/bin/env node
"use strict";
/** R18.11 Node pin comparison against separately supplied, SIMULATED test policy.
 * A caller-supplied key pin is not independently authenticated partner identity.
 */
const fs=require("node:fs");
const crypto=require("node:crypto");
const base=require("./xi_receipt_r189.cjs");
const signed=require("./xi_signed_receipt_r1810.cjs");

const SCHEMA="PhiXi.R18_11_SimulatedLocalPinPolicy.v1";
const REPORT="PhiXi.R18_11_LocalPinVerificationReport.v1";
const SOURCE="LOCAL_TEST_KEY_COPY_NOT_INDEPENDENTLY_AUTHENTICATED";
const SCOPE="R18_10_SYNTHETIC_RECEIPT_MATH_ONLY";
const FIELDS=[
 "schema","policy_source","epoch","active_public_key_hex",
 "revoked_public_key_hexes","scope","external_identity_verified",
 "operator_approvals","approved_operations","live_xi_connected","authority"
];
const KEY=/^[0-9a-f]{64}$/;
function requireThat(ok,reason){if(!ok)throw Error(reason);}
function parsePolicy(data){
 requireThat(Buffer.isBuffer(data)&&data.length>0&&data.length<=4096,"bad policy size");
 const utf8=data.toString("utf8");
 requireThat(Buffer.from(utf8,"utf8").equals(data),"not UTF8");
 const obj=JSON.parse(utf8);
 requireThat(obj!==null&&typeof obj==="object"&&!Array.isArray(obj)&&
  Object.keys(obj).length===FIELDS.length&&
  Object.keys(obj).every(k=>FIELDS.includes(k)),"unreviewed policy structure");
 // The byte comparison also rejects duplicate JSON keys parsed by JS.
 requireThat(base.canonical(obj).equals(data),"noncanonical or duplicate JSON keys");
 requireThat(obj.schema===SCHEMA&&obj.policy_source===SOURCE&&obj.scope===SCOPE,
  "wrong test-only source or scope");
 requireThat(Number.isSafeInteger(obj.epoch)&&obj.epoch>=1&&obj.epoch<=65535,
  "bad test epoch");
 requireThat(obj.external_identity_verified===false&&
  obj.operator_approvals===0&&obj.approved_operations===0&&
  obj.live_xi_connected===false&&obj.authority==="none",
  "forbidden authority or grant");
 requireThat(typeof obj.active_public_key_hex==="string"&&KEY.test(obj.active_public_key_hex),
  "bad active key");
 const revoked=obj.revoked_public_key_hexes;
 requireThat(Array.isArray(revoked)&&revoked.length<=8&&
  revoked.every(x=>typeof x==="string"&&KEY.test(x))&&
  JSON.stringify(revoked)===JSON.stringify([...new Set(revoked)].sort())&&
  !revoked.includes(obj.active_public_key_hex),"invalid revocations");
 return obj;
}
function makeTestPolicy(activeHex,revoked=[],epoch=1){
 const obj={
  schema:SCHEMA,policy_source:SOURCE,epoch,
  active_public_key_hex:activeHex,
  revoked_public_key_hexes:[...revoked].sort(),
  scope:SCOPE,external_identity_verified:false,
  operator_approvals:0,approved_operations:0,
  live_xi_connected:false,authority:"none"
 };
 const raw=base.canonical(obj);
 parsePolicy(raw);
 return raw;
}
function verify(envelope,policy){
 const validated=signed.verify(envelope);
 const rules=parsePolicy(policy);
 const obj=JSON.parse(envelope.toString("utf8"));
 const pub=Buffer.from(obj.public_key_hex,"hex");
 const expected=Buffer.from(rules.active_public_key_hex,"hex");
 requireThat(!rules.revoked_public_key_hexes.includes(obj.public_key_hex),
  "key locally revoked");
 requireThat(pub.length===32&&expected.length===32&&crypto.timingSafeEqual(pub,expected),
  "signed with wrong key for local policy");
 return {
  schema:REPORT,
  status:"LOCAL_SIMULATED_PIN_MATCH_AND_SIGNATURE_VALID_ONLY",
  case_id:validated.case_id,
  policy_epoch:rules.epoch,
  test_pin_sha256:crypto.createHash("sha256").update(pub).digest("hex"),
  signature_mathematically_valid:true,
  simulated_local_pin_matched:true,
  independent_partner_identity_verified:false,
  out_of_band_key_authentication_verified:false,
  operator_approvals:0,approved_operations:0,external_gates_promoted:0,
  real_two_host_crossing_tested:false,live_xi_connected:false,authority:"none"
 };
}
function read(path){
 const st=fs.lstatSync(path);
 requireThat(st.isFile()&&st.size>0&&st.size<=8192,"file absent/linked/oversize");
 const b=fs.readFileSync(path);
 requireThat(b.length<=8192,"file changed while reading");
 return b;
}
function main(args){
 if(args.length===1&&args[0]==="require-live"){
  process.stdout.write('{"status":"LIVE_AUTHORITY_REFUSED","authority":"none"}\n');
  return 2;
 }
 const [command,flag,path,policyFlag,policyFile,...rest]=args;
 requireThat(command==="verify"&&flag==="--file"&&
  typeof path==="string"&&policyFlag==="--policy"&&
  typeof policyFile==="string"&&rest.length===0,
  "expected verify --file SIGNED.json --policy TEST-PIN.json");
 process.stdout.write(JSON.stringify(verify(read(path),read(policyFile)))+"\n");
 return 0;
}
if(require.main===module){
 try{process.exitCode=main(process.argv.slice(2));}
 catch(_){process.stderr.write('{"status":"R18_11_PIN_REFUSED","authority":"none","live_xi_connected":false}\n');process.exitCode=2;}
}
module.exports={SCHEMA,REPORT,SOURCE,SCOPE,parsePolicy,makeTestPolicy,verify,main};
