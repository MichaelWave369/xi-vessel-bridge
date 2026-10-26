/* R18.6: PUBLIC PLANNING-ONLY gate board, sourced from roadmap JSON.
 * This is NOT an authority engine, approval store, or Xi-native contract.
 */
(function(root,factory) {
  "use strict";
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  else root.PhiXiGateBoard=api;
})(typeof window!=="undefined"?window:globalThis,function() {
  "use strict";
  const SCHEMA="PhiXi.R18_6_PublicDiscussionAgenda.v1";
  const GROUPS=Object.freeze([
    Object.freeze({id:"scope",title:"01 · Identity, contract and human consent",
      aim:"Agree what would be tested, by whom, and within exactly which limits.",
      ids:Object.freeze(["native_contract","identity","two_operator_approval","consent","least_privilege","human_data_scope"])}),
    Object.freeze({id:"transport",title:"02 · Secure transport and independent control",
      aim:"Separate operators, bound channels, revocation and attributable bytes.",
      ids:Object.freeze(["transport_profile","kill_switch","provenance","both_houses_independent"])}),
    Object.freeze({id:"crossing",title:"03 · Independent two-host field evidence",
      aim:"Only after approval, rehearse one synthetic read-only digest across two physical hosts.",
      ids:Object.freeze(["two_host_transcript","durable_receipts","negative_controls","capsule_byte_integrity"])}),
    Object.freeze({id:"recovery",title:"04 · Revocation and recovery verification",
      aim:"Document rollback, disconnect, restart and fail-closed recovery under both operators.",
      ids:Object.freeze(["revocation_drill","disaster_recovery_drill"])})
  ]);
  const IDS=Object.freeze(GROUPS.flatMap(g=>g.ids));
  function refuse(message){throw Error(message);}
  function review(roadmap){
    if(!roadmap||typeof roadmap!=="object"||Array.isArray(roadmap)||
       roadmap.schema!=="PhiXi.SharedRoadmap.v1"||
       roadmap.status!=="candidate_planning_only"||
       roadmap.live_xi_connected!==false||roadmap.authority!=="none"||
       !Array.isArray(roadmap.gates)||roadmap.gates.length!==16||
       !Array.isArray(roadmap.milestones)||
       !roadmap.milestones.some(x=>x.id==="R17"&&x.state==="blocked")||
       !roadmap.milestones.some(x=>x.id==="R18"&&x.state==="planned")){
      refuse("Source roadmap missing or claims external readiness");
    }
    if(new Set(IDS).size!==16||!IDS.every(id=>roadmap.gates.some(g=>g.id===id))) {
      refuse("Planning map does not cover the source 16-gate roster exactly");
    }
    const byId=new Map();
    for(const gate of roadmap.gates){
      if(!gate||typeof gate!=="object"||Array.isArray(gate)||
         Object.keys(gate).length!==4||
         !["id","owner","state","requirement"].every(k=>Object.hasOwn(gate,k))||
         !IDS.includes(gate.id)||byId.has(gate.id)||
         gate.state!=="missing"||
         typeof gate.owner!=="string"||!["both","both humans","Xi and PHI"].includes(gate.owner)||
         typeof gate.requirement!=="string"||
         gate.requirement.length<20||gate.requirement.length>550){
        refuse("Unreviewed partner gate, claimed clearance or unexpected source fields");
      }
      byId.set(gate.id,Object.freeze({id:gate.id,owner:gate.owner,
        state:"OUTSTANDING_SOURCE_GATE",requirement:gate.requirement}));
    }
    return Object.freeze({
      classification:"PHI_PROPOSED_DISCUSSION_ORDER_ONLY",
      snapshot_date:String(roadmap.snapshot_date||"source-date-unavailable"),
      verified_external_gates:0,remaining_external_gates:16,
      live_xi_connected:false,authority:"none",
      groups:GROUPS.map(g=>Object.freeze({id:g.id,title:g.title,aim:g.aim,
        gates:g.ids.map(id=>byId.get(id))}))
    });
  }
  function normalizeSelection(board,ids){
    if(!board||board.classification!=="PHI_PROPOSED_DISCUSSION_ORDER_ONLY"||
       board.remaining_external_gates!==16||board.verified_external_gates!==0||
       board.live_xi_connected!==false||board.authority!=="none"||
       !Array.isArray(ids)||ids.length>16)refuse("Unverified agenda data");
    const found=new Set(ids);
    if(found.size!==ids.length||ids.some(id=>typeof id!=="string"||!IDS.includes(id)))
      refuse("Unknown or repeated discussion topics");
    return IDS.filter(id=>found.has(id));
  }
  function agenda(board,ids){
    const ordered=normalizeSelection(board,ids);
    if(!ordered.length)refuse("Choose at least one open topic");
    const map=new Map(board.groups.flatMap(g=>g.gates).map(g=>[g.id,g]));
    return Object.freeze({
      schema:SCHEMA,classification:"PUBLIC_UNAPPROVED_DISCUSSION_AGENDA",
      source_snapshot_date:board.snapshot_date,
      proposed_by:"PHI-side planning fixture",
      topics:ordered.map(id=>({
        id,owner:map.get(id).owner,question:map.get(id).requirement,
        source_state:"missing",status:"DISCUSSION_ONLY_NOT_APPROVED"
      })),
      requested_partner_action:"Review documentation and discuss human-controlled evidence path only. Do not share private keys, credentials, private URLs or personal data.",
      externally_verified_gates:0,external_gates_remaining:16,
      approved_operations:0,live_xi_connected:false,authority:"none",
      r17_external_pilot:"BLOCKED",r18_real_two_host_pilot:"NOT_RUN"
    });
  }
  function agendaText(document){
    if(!document||document.schema!==SCHEMA||
       document.classification!=="PUBLIC_UNAPPROVED_DISCUSSION_AGENDA"||
       document.authority!=="none"||document.live_xi_connected!==false||
       document.externally_verified_gates!==0||document.approved_operations!==0||
       document.external_gates_remaining!==16||
       !Array.isArray(document.topics)||
       document.topics.some(t=>t.status!=="DISCUSSION_ONLY_NOT_APPROVED")) {
      refuse("Only unapproved public agenda can be copied");
    }
    return [
      "XI ⇄ Φ · PHI-side proposed discussion agenda (NOT APPROVAL)",
      "Source: https://michaelwave369.github.io/xi-vessel-bridge/roadmap.html",
      "Source snapshot: "+document.source_snapshot_date,
      ...document.topics.map((t,i)=>(i+1)+". ["+t.id+"] ("+t.owner+") "+t.question),
      "We are requesting public docs and mutual human review only. Do NOT post secrets.",
      "R17 external pilot BLOCKED; R18 real two-host test NOT RUN.",
      "All 16 external evidence gates remain outstanding. No permissions granted."
    ].join("\n\n");
  }
  return Object.freeze({SCHEMA,GROUPS,IDS,review,agenda,agendaText});
});
