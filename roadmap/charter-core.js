/* R18.7 public charter, source-derived from immutable R18 fixture and 16 missing
 * gate roadmap. This has ZERO authorization power and never collects a key.
 */
(function(root,factory) {
 "use strict";
 const api=factory();
 if(typeof module==="object"&&module.exports) module.exports=api;
 else root.PhiXiCharter=api;
})(typeof window!=="undefined"?window:globalThis,function(){
 "use strict";
 const SCHEMA="PhiXi.R18_7_ProposedSyntheticPilotCharter.v1";
 const FIXTURE_SHA="8370bdb1f706a2168accc1c225a37c98ec907cd3e954b67c1cdcc9d8ddd8feb5";
 const FIXTURE_B64="UEhJLVhJIFIxOCBTWU5USEVUSUMgRElHRVNUIEZJWFRVUkUgdjEKTk8gUFJJVkFURSBEQVRBOyBOTyBBVVRIT1JJVFk7IE5PIFJFTU9URSBSSUdIVFMuCg==";
 const GATE_IDS=Object.freeze(["identity","native_contract","two_operator_approval",
  "transport_profile","least_privilege","consent","provenance","kill_switch",
  "two_host_transcript","durable_receipts","negative_controls","human_data_scope",
  "capsule_byte_integrity","revocation_drill","both_houses_independent",
  "disaster_recovery_drill"]);
 const TESTS=Object.freeze(["wrong_peer","wrong_recipient","tampered_signature",
  "expired_message","wrong_session","scope_escalation","denied_receiver_policy",
  "unilateral_pause","unilateral_revocation","request_replay","restart_replay",
  "tampered_receipt","lost_response_after_commit"]);
 const VARIANTS=Object.freeze(["single_digest_only","digest_and_candidate_negative_controls"]);
 const FLIGHT=Object.freeze([
  {id:"PREPARE",title:"Independent preparation",condition:"Both operators review the exact nonsecret scope; no host may assume the other has consented."},
  {id:"VERIFY",title:"Authenticate and pin",condition:"Verify real public identities out of band and jointly pin a native schema and encrypted transport; none configured here."},
  {id:"AUTHORIZE",title:"Separate human go/no-go",condition:"Two independent human approvals and unilateral stop rights are required before any remote action."},
  {id:"EXCHANGE",title:"One synthetic digest",condition:"Only if every prerequisite passed externally, each host separately confirms the read-only digest and its own signed receipt."},
  {id:"STOP",title:"Disconnect and preserve sovereignty",condition:"Either house may revoke independently. Fail closed on unverified key, scope, transport, time, receipt, replay or disconnect."}
 ]);
 function insist(ok,message){if(!ok)throw Error(message);}
 function exact(v,fields,label){
  insist(v&&typeof v==="object"&&!Array.isArray(v) &&
   Object.keys(v).length===fields.length&&
   Object.keys(v).every(key=>fields.includes(key)),label+" fields refused");
 }
 function validateFixture(f){
  const fields=["schema","payload_b64","size_bytes","sha256","origin",
    "intended_use","classification","authority","live_xi_connected"];
  exact(f,fields,"R18 synthetic fixture");
  insist(f.schema==="PhiXi.R18SyntheticFixture.v1" &&
   f.payload_b64===FIXTURE_B64 && f.size_bytes===88 &&
   f.sha256===FIXTURE_SHA && f.origin==="PHI369-local-synthetic-fixture" &&
   f.intended_use==="digest-only offline operator rehearsal" &&
   f.classification==="synthetic_public" && f.authority==="none" &&
   f.live_xi_connected===false,"Changed synthetic byte fixture or authority claim");
  return Object.freeze({sha256:FIXTURE_SHA,size_bytes:88,classification:"synthetic_public"});
 }
 function validateDraft(p){
  const fields=["schema","status","transport","endpoint_reference","native_schema_sha256",
   "xi_peer_pin","phi_peer_pin","phi_operator_approval","xi_operator_approval",
   "transport_security_verified","provenance_verified","durable_receipts_verified",
   "independent_revocation_verified","data_classification","scope",
   "live_xi_connected","authority"];
  exact(p,fields,"R18 pilot preflight");
  insist(p.schema==="PhiXi.R18PilotDraft.v1"&&
    p.status==="draft_no_approval"&&p.transport==="unconfigured"&&
    p.endpoint_reference===null&&p.native_schema_sha256===null&&
    p.xi_peer_pin===null&&p.phi_peer_pin===null&&
    p.phi_operator_approval===false&&p.xi_operator_approval===false&&
    p.transport_security_verified===false&&p.provenance_verified===false&&
    p.durable_receipts_verified===false&&p.independent_revocation_verified===false&&
    p.data_classification==="synthetic_public"&&p.scope==="digest_only"&&
    p.live_xi_connected===false&&p.authority==="none",
    "Changed candidate preflight or unverifiable approval/endpoint fields");
  return Object.freeze({schema:p.schema,status:p.status});
 }
 function validateRoadmap(roadmap){
  insist(roadmap&&typeof roadmap==="object"&&
   roadmap.schema==="PhiXi.SharedRoadmap.v1"&&
   roadmap.status==="candidate_planning_only"&&
   roadmap.live_xi_connected===false&&roadmap.authority==="none"&&
   Array.isArray(roadmap.gates)&&roadmap.gates.length===16&&
   Array.isArray(roadmap.milestones)&&
   roadmap.milestones.some(m=>m.id==="R17"&&m.state==="blocked")&&
   roadmap.milestones.some(m=>m.id==="R18"&&m.state==="planned"),
   "Current shared roadmap is unreviewed or implies real Xi clearance");
  const names=roadmap.gates.map(g=>g.id);
  insist(names.length===new Set(names).size &&
   GATE_IDS.every(id=>names.includes(id))&&
   roadmap.gates.every(g=>g.state==="missing"&&
     typeof g.requirement==="string"&&g.requirement.length>=20&&
     ["both","both humans","Xi and PHI"].includes(g.owner)),
   "A required external evidence gate has changed or been promoted");
  insist(typeof roadmap.snapshot_date==="string"&&
   /^\d{4}-\d{2}-\d{2}$/.test(roadmap.snapshot_date),"Invalid public source snapshot");
  return Object.freeze({snapshot_date:roadmap.snapshot_date,missing:GATE_IDS.length});
 }
 function validateSources(sources){
  insist(sources&&typeof sources==="object"&&!Array.isArray(sources),"Missing source bundle");
  const fixture=validateFixture(sources.fixture);
  const preflight=validateDraft(sources.preflight);
  const roadmap=validateRoadmap(sources.roadmap);
  return Object.freeze({fixture,preflight,roadmap});
 }
 function charter(sources,mode){
  const inspected=validateSources(sources);
  insist(VARIANTS.includes(mode),"Unreviewed scope variant");
  const negatives=mode==="digest_and_candidate_negative_controls"?[...TESTS]:[];
  const doc={
    schema:SCHEMA,status:"UNAPPROVED_PUBLIC_PROPOSAL",
    classification:"SYNTHETIC_PUBLIC_CANDIDATE_NOT_EXECUTABLE",
    proposed_by:"PHI-side only; Xi review requested, not implied",
    source_roadmap_snapshot:inspected.roadmap.snapshot_date,
    evidence_gates_missing:16,independently_verified_external_gates:0,
    peer:"Xi candidate only; real identity NOT VERIFIED",
    identities:{phi_public_key_pin:null,xi_public_key_pin:null,
      independently_authenticated:false},
    transport:{status:"UNCONFIGURED",endpoint:null,native_schema_sha256:null,
      encrypted_authenticated:false},
    approvals:{phi_operator:false,xi_operator:false,joint_consent:false},
    operation:{name:"artifact.sha256",read_only:true,dry_run_only:true,
      data_classification:"synthetic_public",
      source_fixture_sha256:inspected.fixture.sha256,
      source_fixture_bytes:inspected.fixture.size_bytes,
      max_payload_bytes:inspected.fixture.size_bytes,
      peer_data_included:false},
    rehearsal_mode:mode,proposed_negative_controls:negatives,
    stages:FLIGHT.map(x=>({...x})),
    stop_conditions:[
      "unverified_peer_identity","native_schema_not_jointly_pinned",
      "transport_not_authenticated","missing_separate_human_approvals",
      "unexpected_data_or_scope","expired_or_replayed_request",
      "missing_or_invalid_signed_receipt","either_house_revoked_or_paused",
      "transport_lost_or_delivery_not_confirmed"
    ],
    execution_status:"NOT_RUN",
    real_two_physical_hosts_tested:false,real_xi_peer_verified:false,
    independent_xi_receipts:0,approved_operations:0,
    r17_external_pilot:"BLOCKED",r18_real_two_host_pilot:"NOT_RUN",
    live_xi_connected:false,authority:"none",
    qualification:"Unapproved PHI-side public planning packet, NOT a native Xi contract, transport, approval or live operator decision."
  };
  return doc;
 }
 function validateCharter(d){
  exact(d,["schema","status","classification","proposed_by","source_roadmap_snapshot",
   "evidence_gates_missing","independently_verified_external_gates","peer","identities",
   "transport","approvals","operation","rehearsal_mode","proposed_negative_controls",
   "stages","stop_conditions","execution_status","real_two_physical_hosts_tested",
   "real_xi_peer_verified","independent_xi_receipts","approved_operations",
   "r17_external_pilot","r18_real_two_host_pilot","live_xi_connected",
   "authority","qualification"],"Pilot charter");
  insist(d.schema===SCHEMA &&
    d.status==="UNAPPROVED_PUBLIC_PROPOSAL" &&
    d.classification==="SYNTHETIC_PUBLIC_CANDIDATE_NOT_EXECUTABLE" &&
    d.proposed_by==="PHI-side only; Xi review requested, not implied" &&
    d.evidence_gates_missing===16&&d.independently_verified_external_gates===0&&
    d.peer==="Xi candidate only; real identity NOT VERIFIED" &&
    d.execution_status==="NOT_RUN"&&d.real_two_physical_hosts_tested===false&&
    d.real_xi_peer_verified===false&&d.independent_xi_receipts===0&&
    d.approved_operations===0&&d.r17_external_pilot==="BLOCKED"&&
    d.r18_real_two_host_pilot==="NOT_RUN"&&
    d.live_xi_connected===false&&d.authority==="none"&&
    d.qualification==="Unapproved PHI-side public planning packet, NOT a native Xi contract, transport, approval or live operator decision."&&
    typeof d.source_roadmap_snapshot==="string"&&/^\d{4}-\d{2}-\d{2}$/.test(d.source_roadmap_snapshot),
    "Charter cannot claim authority or external pilot evidence");
  exact(d.identities,["phi_public_key_pin","xi_public_key_pin","independently_authenticated"],"Identity");
  insist(d.identities.phi_public_key_pin===null&&d.identities.xi_public_key_pin===null&&
   d.identities.independently_authenticated===false,"No real identity may be embedded");
  exact(d.transport,["status","endpoint","native_schema_sha256","encrypted_authenticated"],"Transport");
  insist(d.transport.status==="UNCONFIGURED"&&d.transport.endpoint===null&&
    d.transport.native_schema_sha256===null&&d.transport.encrypted_authenticated===false,
    "Charter cannot activate transport");
  exact(d.approvals,["phi_operator","xi_operator","joint_consent"],"Approvals");
  insist(Object.values(d.approvals).every(x=>x===false),"Charter cannot assert human consent");
  exact(d.operation,["name","read_only","dry_run_only","data_classification",
    "source_fixture_sha256","source_fixture_bytes","max_payload_bytes","peer_data_included"],"Operation");
  insist(d.operation.name==="artifact.sha256"&&d.operation.read_only===true&&
    d.operation.dry_run_only===true&&d.operation.data_classification==="synthetic_public"&&
    d.operation.source_fixture_sha256===FIXTURE_SHA&&
    d.operation.source_fixture_bytes===88&&d.operation.max_payload_bytes===88&&
    d.operation.peer_data_included===false,"Unauthorized operation or changed digest bytes");
  insist(VARIANTS.includes(d.rehearsal_mode)&&
    JSON.stringify(d.proposed_negative_controls)===
      JSON.stringify(d.rehearsal_mode===VARIANTS[1]?[...TESTS]:[])&&
    JSON.stringify(d.stages)===JSON.stringify(FLIGHT.map(x=>({...x})))&&
    JSON.stringify(d.stop_conditions)===JSON.stringify([
      "unverified_peer_identity","native_schema_not_jointly_pinned",
      "transport_not_authenticated","missing_separate_human_approvals",
      "unexpected_data_or_scope","expired_or_replayed_request",
      "missing_or_invalid_signed_receipt","either_house_revoked_or_paused",
      "transport_lost_or_delivery_not_confirmed"
    ]),"Charter stages or consent prerequisites changed");
  return d;
 }
 function textForRoom(d){
  validateCharter(d);
  return [
    "Xi ⇄ Φ369 · PHI-SIDE UNAPPROVED R18.7 SYNTHETIC PILOT PROPOSAL",
    "Public source: https://michaelwave369.github.io/xi-vessel-bridge/",
    "Read-only operation proposal: artifact.sha256 on the 88-byte synthetic_public fixture.",
    "Fixture SHA-256: "+FIXTURE_SHA,
    "Mode: "+d.rehearsal_mode+". No remote endpoint, transport or operator keys configured.",
    "Independent out-of-band peer verification, a jointly reviewed native Xi schema, encrypted transport, and TWO distinct human go/no-go approvals are prerequisites.",
    "Either house independently pauses/revokes. Fail closed on key, consent, scope, expiry, replay, invalid receipt or disconnect.",
    "R17 external pilot BLOCKED. R18 real two-host pilot NOT RUN. All 16 external gates missing.",
    "This is a request for documentation and mutual review, NOT an approval or permission grant."
  ].join("\n");
 }
 return Object.freeze({SCHEMA,FIXTURE_SHA,GATE_IDS,TESTS,VARIANTS,FLIGHT,
    validateFixture,validateDraft,validateRoadmap,validateSources,charter,
    validateCharter,textForRoom});
});
