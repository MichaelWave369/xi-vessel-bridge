/* PhiXi R18.3 local ONLY: deterministic fault-state teaching simulator.
 * No real keys/signatures, Python worker, external Xi service, crypto grant,
 * network requests, or filesystem state. These cases are illustrations, not proofs.
 */
(function(root,factory){
  "use strict";
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  else root.PhiXiFaultLab=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  "use strict";
  const SCHEMA="PhiXi.R18_3_LocalFaultScenario.v1";
  const REPORT_SCHEMA="PhiXi.R18_3_IllustrativeFaultReview.v1";
  const RULES=Object.freeze({
    operation:"artifact.sha256", session:"r18_3_test_session",
    id:"synthetic_request_01", digest:"8370bdb1f706a2168accc1c225a37c98ec907cd3e954b67c1cdcc9d8ddd8feb5",
    ttl:45
  });
  const cases=[
    ["baseline","Valid local digest","NORMAL","none","ACCEPTED","Illustrates a permitted local digest completing with one receipt."],
    ["wrong-peer","Unpinned sender","IDENTITY","wrong_peer","REFUSED","Receiver refuses a sender not matching its pinned test identity."],
    ["wrong-recipient","Wrong recipient","IDENTITY","wrong_recipient","REFUSED","Request cannot be redirected to a different house."],
    ["signature-tamper","Tampered signed bytes","INTEGRITY","signature_tamper","REFUSED","Changing a signed envelope invalidates the abstract signature flag."],
    ["expired","Expired request","FRESHNESS","expired","REFUSED","An expired request fails the bounded freshness check."],
    ["wrong-session","Cross-session injection","BINDING","wrong_session","REFUSED","Request must bind to the current local session."],
    ["scope-escalation","Repository write request","PERMISSION","scope_escalation","REFUSED","Only read-only synthetic artifact.sha256 is permitted."],
    ["receiver-deny","No receiver opt-in","PERMISSION","receiver_deny","REFUSED","Receiver owns its own allowlist; no grant from the sender."],
    ["paused","Receiver locally paused","CONTROL","paused","REFUSED","A local pause denies incoming requests without changing the sender."],
    ["revoked","Receiver revoked peer","CONTROL","revoked","REFUSED","Local revocation takes precedence over incoming signed requests."],
    ["duplicate","Duplicate request ID","REPLAY","duplicate","REFUSED","A committed request ID cannot be executed a second time."],
    ["restart-replay","Replay after restart","REPLAY","restart_replay","REFUSED","Durable ledger survives a simulated receiver restart."],
    ["receipt-tamper","Mutated result receipt","RECEIPT","receipt_tamper","RESULT_REFUSED","The requester rejects a result whose receipt binder was changed."],
    ["lost-reply","Commit then lose reply","RECOVERY","lost_reply","RETRY_REFUSED","After a lost response, safe at-most-once behavior refuses a replay."]
  ];
  const CASES=Object.freeze(cases.map(row=>Object.freeze({
    id:row[0],name:row[1],group:row[2],fault:row[3],expected:row[4],description:row[5]
  })));
  const INDEX=Object.freeze(Object.fromEntries(CASES.map(x=>[x.id,x])));
  function requireCase(id){
    if(typeof id!=="string" || !Object.prototype.hasOwnProperty.call(INDEX,id))
      throw Error("Unknown fixed local simulation scenario");
    return INDEX[id];
  }
  function step(out,stage,house,decision,note){
    out.push({stage,house,decision,note});
  }
  function runScenario(id){
    const spec=requireCase(id);
    const trace=[];
    // An abstract state machine. NOT a cryptographic Ed25519 verifier.
    const phi={pinned:true,session:RULES.session,hasReceipt:false};
    const xi={allowDigest:true,paused:false,revoked:false,
      pinnedSender:true,session:RULES.session,ledger:new Set()};
    let packet={id:RULES.id,session:RULES.session,
      operation:RULES.operation,permission:"read_only",dryRun:true,
      expectedRecipient:true,senderMatchesPin:true,
      signatureShapeValid:true,created:1000,expires:1000+RULES.ttl};
    step(trace,"handshake","BOTH","SIMULATED","Assume R16 local fixture handshake succeeded; no real keys or signatures used.");
    switch(spec.fault){
      case "wrong_peer":packet.senderMatchesPin=false;break;
      case "wrong_recipient":packet.expectedRecipient=false;break;
      case "signature_tamper":packet.signatureShapeValid=false;break;
      case "expired":packet.expires=999;break;
      case "wrong_session":packet.session="foreign_session";break;
      case "scope_escalation":packet.operation="repo.write";packet.permission="explicit_grant";break;
      case "receiver_deny":xi.allowDigest=false;break;
      case "paused":xi.paused=true;break;
      case "revoked":xi.revoked=true;break;
      case "duplicate":xi.ledger.add(packet.id);break;
      case "restart_replay":xi.ledger.add(packet.id);step(trace,"restart","XI-SIM","LEDGER_RESTORED","Process memory reset; durable request-ID record remains.");break;
      case "receipt_tamper":
      case "lost_reply":
      case "none":break;
      default:throw Error("Unknown internal injection mode");
    }
    step(trace,"request","PHI-SIM","ILLUSTRATIVE_SEND",
      "Fixed public synthetic digest-only request. No data transferred between computers.");
    const now=1000;
    const failures=[
      [xi.paused,"LOCAL_PAUSE","Receiver's own pause switch is active."],
      [xi.revoked,"PEER_REVOKED","Receiver's own peer revocation remains active."],
      [!xi.pinnedSender || !packet.senderMatchesPin,"WRONG_PEER","Sender does not match receiver's pinned abstract identity."],
      [!packet.expectedRecipient,"WRONG_RECIPIENT","Recipient binding is not the receiving house."],
      [!packet.signatureShapeValid,"ALTERED_SIGNED_BYTES","Abstract signed-byte integrity condition failed. No cryptography executed."],
      [packet.session!==xi.session,"WRONG_SESSION","Request does not belong to the receiving house's local session."],
      [now>packet.expires || now<packet.created || packet.expires-packet.created!==RULES.ttl,
        "STALE_REQUEST","Request freshness/expiry condition failed."],
      [packet.operation!==RULES.operation || packet.permission!=="read_only" || packet.dryRun!==true,
        "SCOPE_DENIED","Only explicitly approved dry-run read-only digest is allowed."],
      [!xi.allowDigest,"RECEIVER_POLICY_DENIED","The receiver has not opted in to the digest operation."],
      [xi.ledger.has(packet.id),"DURABLE_REPLAY_DENIED","Request ID already consumed by the receiver."]
    ];
    const first=failures.find(x=>x[0]);
    let observed, reason, committed=false, receiptAccepted=false, retryDenied=false;
    if(first){
      observed="REFUSED";reason=first[1];
      step(trace,"admission","XI-SIM","DENIED",first[2]);
    }else{
      xi.ledger.add(packet.id); committed=true;
      step(trace,"commit","XI-SIM","COMMITTED",
        "Synthetic digest receipt committed exactly once to the local illustrative ledger.");
      if(spec.fault==="lost_reply"){
        step(trace,"delivery","NETWORK-FIXTURE","DROPPED",
          "The generated response is lost after receiver commit.");
        retryDenied=xi.ledger.has(packet.id);
        step(trace,"retry","XI-SIM","DENIED",
          "Redelivery of the same request ID is refused; no second execution.");
        observed=retryDenied?"RETRY_REFUSED":"UNSAFE_RETRY_ACCEPTED";
        reason="AT_MOST_ONCE_RECOVERY";
      }else{
        const receipt={requestId:packet.id,operation:RULES.operation,digest:RULES.digest,
          signatureShapeValid:true,requestBound:true};
        if(spec.fault==="receipt_tamper") receipt.requestBound=false;
        if(!receipt.signatureShapeValid || !receipt.requestBound ||
            receipt.requestId!==packet.id || receipt.operation!==RULES.operation ||
            receipt.digest!==RULES.digest){
          observed="RESULT_REFUSED";reason="RECEIPT_BINDING_DENIED";
          step(trace,"receipt","PHI-SIM","DENIED","Result binder mismatch; requester refuses to confirm.");
        }else{
          receiptAccepted=true;phi.hasReceipt=true;observed="ACCEPTED";reason="SAFE_SYNTHETIC_DIGEST";
          step(trace,"receipt","PHI-SIM","ACCEPTED","Abstract receipt binder matches fixed synthetic request.");
        }
      }
    }
    const pass=observed===spec.expected;
    return {
      schema:SCHEMA,scenario_id:spec.id,title:spec.name,category:spec.group,
      injected_fault:spec.fault,expected:spec.expected,observed,pass,
      denial_reason:reason,receiver_commits:committed?1:0,
      requester_confirmed:receiptAccepted,duplicate_retry_refused:retryDenied,
      abstract_signature_only:true,physical_hosts:1,
      independent_xi_evidence:0,live_xi_connected:false,authority:"none",
      trace
    };
  }
  function runAll(){
    return CASES.map(c=>runScenario(c.id));
  }
  function exportReview(results){
    if(!Array.isArray(results) || results.length<1 || results.length>CASES.length)
      throw Error("No valid cases for review export");
    const ids=new Set();
    const summaries=results.map(r=>{
      const expected=runScenario(r&&r.scenario_id);
      if(ids.has(expected.scenario_id))throw Error("Duplicate simulation case");
      ids.add(expected.scenario_id);
      // Only an exactly reproducible outcome can become a redacted illustrative review.
      if(JSON.stringify(r)!==JSON.stringify(expected))throw Error("Unrecognized simulation result");
      return {scenario_id:r.scenario_id,expected:r.expected,observed:r.observed,
        pass:r.pass,receiver_commits:r.receiver_commits};
    });
    return {
      schema:REPORT_SCHEMA,classification:"ILLUSTRATIVE_DETERMINISTIC_BROWSER_SIMULATION",
      scenarios:summaries,scenarios_passed:summaries.filter(s=>s.pass).length,
      source:"PhiXi.R18_3_LocalFaultScenario.v1",physical_hosts:1,
      independent_xi_evidence:0,external_gates_promoted:0,
      r17_external_pilot:"BLOCKED",r18_real_two_host_pilot:"NOT_RUN",
      live_xi_connected:false,authority:"none",
      qualification:"No real Ed25519 validation, process execution, network transfer, Xi endpoint or external operator authorization."
    };
  }
  return Object.freeze({SCHEMA,REPORT_SCHEMA,CASES,RULES,runScenario,runAll,exportReview});
});
