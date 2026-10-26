#!/usr/bin/env node
"use strict";
/** R18.10 Node Ed25519 SELF-ISSUED fixture. No Xi pin, authority or network. */
const fs=require("node:fs");
const crypto=require("node:crypto");
const receipt=require("./xi_receipt_r189.cjs");

const SCHEMA="PhiXi.R18_10_SelfIssuedLocalSignatureFixture.v1";
const RESULT_SCHEMA="PhiXi.R18_10_SelfIssuedVerificationReport.v1";
const SUITE="Ed25519_UNPINNED_EPHEMERAL_TEST_ONLY";
const CONTEXT=Buffer.from("PhiXi.R18_10.SelfIssuedSyntheticReceipt.v1\0","ascii");
const SPKI_PREFIX=Buffer.from("302a300506032b6570032100","hex");
const MAX_BYTES=8192;
const FIELDS=[
 "schema","suite","case_id","receipt_b64","receipt_sha256",
 "domain_message_sha256","public_key_hex","signature_hex",
 "signer_classification","self_issued","real_xi_identity_verified",
 "bilateral_consent_verified","approved_operations","signed_exchange_observed",
 "r17_external_pilot","r18_real_two_host_pilot","live_xi_connected","authority"
];
function requireThat(ok,reason){if(!ok)throw Error(reason);}
function sha(b){return crypto.createHash("sha256").update(b).digest("hex");}
function domainMessage(bytes){return Buffer.concat([CONTEXT,bytes]);}
function canonicalB64(value){
 requireThat(typeof value==="string"&&value.length>0&&value.length<6000&&
  /^[A-Za-z0-9+/]+={0,2}$/.test(value),"invalid base64");
 const bytes=Buffer.from(value,"base64");
 requireThat(bytes.toString("base64")===value,"noncanonical base64");
 return bytes;
}
function hexData(value,length){
 requireThat(typeof value==="string"&&value.length===length*2&&
  /^[0-9a-f]+$/.test(value),"bad lower-case hex");
 return Buffer.from(value,"hex");
}
function emit(caseId){
 const unsigned=receipt.emit(caseId);
 const {privateKey,publicKey}=crypto.generateKeyPairSync("ed25519");
 const der=publicKey.export({format:"der",type:"spki"});
 requireThat(der.length===SPKI_PREFIX.length+32&&
  der.subarray(0,SPKI_PREFIX.length).equals(SPKI_PREFIX),
  "unexpected Ed25519 public DER format");
 const pub=der.subarray(SPKI_PREFIX.length);
 const message=domainMessage(unsigned);
 const signature=crypto.sign(null,message,privateKey);
 requireThat(signature.length===64,"unexpected Ed25519 signature size");
 // Private key never leaves this function; no export, file, or ledger.
 const doc={
  schema:SCHEMA,suite:SUITE,case_id:caseId,
  receipt_b64:unsigned.toString("base64"),receipt_sha256:sha(unsigned),
  domain_message_sha256:sha(message),public_key_hex:pub.toString("hex"),
  signature_hex:signature.toString("hex"),
  signer_classification:"UNPINNED_SELF_ISSUED_LOCAL_KEY",
  self_issued:true,real_xi_identity_verified:false,
  bilateral_consent_verified:false,approved_operations:0,
  signed_exchange_observed:false,r17_external_pilot:"BLOCKED",
  r18_real_two_host_pilot:"NOT_RUN",live_xi_connected:false,
  authority:"none"
 };
 return receipt.canonical(doc);
}
function verify(data){
 requireThat(Buffer.isBuffer(data)&&data.length>0&&data.length<=MAX_BYTES,
  "invalid envelope size");
 const json=data.toString("utf8");
 requireThat(Buffer.from(json,"utf8").equals(data),"non-UTF8 document");
 const doc=JSON.parse(json);
 requireThat(doc!==null&&typeof doc==="object"&&!Array.isArray(doc)&&
  Object.keys(doc).length===FIELDS.length&&
  Object.keys(doc).every(k=>FIELDS.includes(k)),"extra or missing fields");
 // Exact re-serialization rejects duplicate keys, foreign encodings and
 // altered ordering, even when JavaScript JSON.parse would accept them.
 requireThat(receipt.canonical(doc).equals(data),"noncanonical envelope");
 requireThat(doc.schema===SCHEMA&&doc.suite===SUITE&&
  doc.signer_classification==="UNPINNED_SELF_ISSUED_LOCAL_KEY"&&
  doc.self_issued===true&&doc.real_xi_identity_verified===false&&
  doc.bilateral_consent_verified===false&&doc.approved_operations===0&&
  doc.signed_exchange_observed===false&&doc.r17_external_pilot==="BLOCKED"&&
  doc.r18_real_two_host_pilot==="NOT_RUN"&&doc.live_xi_connected===false&&
  doc.authority==="none","privileged self-issued envelope");
 const unsigned=canonicalB64(doc.receipt_b64);
 const inspected=receipt.verify(unsigned);
 requireThat(doc.case_id===inspected.case_id&&
  Object.prototype.hasOwnProperty.call(receipt.CASES,doc.case_id),
  "case is not source-qualified");
 requireThat(doc.receipt_sha256===sha(unsigned),"receipt digest mismatch");
 const message=domainMessage(unsigned);
 requireThat(doc.domain_message_sha256===sha(message),"domain binding mismatch");
 const pub=hexData(doc.public_key_hex,32);
 const sig=hexData(doc.signature_hex,64);
 const publicKey=crypto.createPublicKey({key:Buffer.concat([SPKI_PREFIX,pub]),
  format:"der",type:"spki"});
 requireThat(crypto.verify(null,message,publicKey,sig),"mathematical signature invalid");
 return {
  schema:RESULT_SCHEMA,status:"SELF_ISSUED_EPHEMERAL_SIGNATURE_MATH_VALID",
  case_id:doc.case_id,receipt_sha256:sha(unsigned),
  domain_message_sha256:sha(message),
  self_issued_signature_verified:true,
  independent_partner_identity_verified:false,
  operator_approvals:0,approved_operations:0,
  external_gates_promoted:0,real_two_host_crossing_tested:false,
  live_xi_connected:false,authority:"none"
 };
}
function main(args){
 if(args.length===1&&args[0]==="require-live"){
  process.stdout.write('{"status":"LIVE_AUTHORITY_REFUSED","authority":"none"}\n');
  return 2;
 }
 const [action,flag,value,...extra]=args;
 if(action==="emit"&&flag==="--case"&&typeof value==="string"&&
   (extra.length===0||(extra.length===2&&extra[0]==="--out"))){
  const data=emit(value);
  if(extra.length)fs.writeFileSync(extra[1],data,{flag:"w"});
  else process.stdout.write(data);
  return 0;
 }
 if(action==="verify"&&flag==="--file"&&typeof value==="string"&&extra.length===0){
  const stat=fs.lstatSync(value);
  requireThat(stat.isFile()&&stat.size>0&&stat.size<=MAX_BYTES,
   "invalid input file");
  const raw=fs.readFileSync(value);
  process.stdout.write(JSON.stringify(verify(raw))+"\n");
  return 0;
 }
 throw Error("expected emit --case CASE [--out FILE] or verify --file FILE");
}
if(require.main===module){
 try{process.exitCode=main(process.argv.slice(2));}
 catch(_){process.stderr.write('{"status":"R18_10_REFUSED","authority":"none","live_xi_connected":false}\n');process.exitCode=2;}
}
module.exports={SCHEMA,RESULT_SCHEMA,SUITE,CONTEXT,SPKI_PREFIX,
 emit,verify,main};
