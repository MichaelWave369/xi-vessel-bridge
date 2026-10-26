/* R18.2 shared local-only viewer: validators assert witness SHAPE, NOT identity/trust.
   No remote Xi calls, private key access, execution permissions or grants. */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PhiXiLab = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";
  const SCHEMA = "PhiXi.R18_2_LocalLabPreview.v1";
  const REVIEW = "PhiXi.R18_2_LocalLabReview.v1";
  const WITNESS_STATUS = "R18_1_TWO_HOUSE_LOCAL_SIMULATION_PASS";
  const PAYLOAD_HASH = "8370bdb1f706a2168accc1c225a37c98ec907cd3e954b67c1cdcc9d8ddd8feb5";
  const BOOL_TRUE = Object.freeze([
    "distinct_ephemeral_identity_keys", "bilateral_r16_handshake",
    "signed_xi_exchange_v1_shaped_digest_roundtrip", "bidirectional_local_digest",
    "durable_request_replay_refused_after_restart", "receiver_pause_refused",
    "receiver_revocation_survived_restart"
  ]);
  const BOOL_FALSE = Object.freeze([
    "cross_host_network", "real_xi_peer_verified", "two_physical_hosts_confirmed",
    "live_xi_connected"
  ]);
  const ALL_KEYS = Object.freeze([
    "status", "process_count", ...BOOL_TRUE, "source_fixture_sha256",
    "permitted_operation", ...BOOL_FALSE, "physical_hosts",
    "r17_external_pilot", "r18_real_two_host_pilot",
    "authority", "qualification"
  ]);
  const CHECKS = Object.freeze([
    Object.freeze({id:"keys", label:"Two ephemeral key identities", field:"distinct_ephemeral_identity_keys", type:"fixture"}),
    Object.freeze({id:"handshake", label:"Bilateral signed R16 handshake", field:"bilateral_r16_handshake", type:"fixture"}),
    Object.freeze({id:"digest", label:"Signed digest roundtrip", field:"signed_xi_exchange_v1_shaped_digest_roundtrip", type:"fixture"}),
    Object.freeze({id:"bidirectional", label:"Both houses request a digest", field:"bidirectional_local_digest", type:"fixture"}),
    Object.freeze({id:"replay", label:"Replay denied after process restart", field:"durable_request_replay_refused_after_restart", type:"negative"}),
    Object.freeze({id:"pause", label:"Receiver pauses its own access", field:"receiver_pause_refused", type:"negative"}),
    Object.freeze({id:"revoke", label:"Revocation persists after restart", field:"receiver_revocation_survived_restart", type:"negative"})
  ]);
  function refuse(message) { throw new Error(message); }
  function exact(obj, fields, name) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) refuse(name + " must be an object");
    const keys = Object.keys(obj);
    if (keys.length !== fields.length || !keys.every(k => fields.includes(k))) {
      refuse(name + " has missing or additional fields");
    }
    return obj;
  }
  function validateWitness(witness) {
    exact(witness, ALL_KEYS, "R18.1 witness");
    if (witness.status !== WITNESS_STATUS ||
        witness.process_count !== 2 || witness.physical_hosts !== 1 ||
        witness.source_fixture_sha256 !== PAYLOAD_HASH ||
        witness.permitted_operation !== "artifact.sha256" ||
        witness.r17_external_pilot !== "BLOCKED" ||
        witness.r18_real_two_host_pilot !== "NOT_RUN" ||
        witness.authority !== "none" ||
        witness.qualification !== "Two local synthetic processes, fixture-only cryptography and permissions." ||
        !BOOL_TRUE.every(k => witness[k] === true) ||
        !BOOL_FALSE.every(k => witness[k] === false)) {
      refuse("Witness has unexpected values or claims external authority");
    }
    return {
      shape: "R18_1_WITNESS_SHAPE_VALID_ONLY",
      checks: CHECKS.map(x=>({id:x.id, label:x.label, type:x.type, reported: true})),
      checked_count: CHECKS.length,
      local_processes: 2, physical_hosts: 1, fixture_sha256: PAYLOAD_HASH,
      classification: "LOCAL_FIXTURE_SELF_REPORT_UNTRUSTED",
      independently_authenticated_xi_receipts: 0,
      external_gates_promoted: 0,
      live_xi_connected: false, authority: "none",
      r17_external_pilot: "BLOCKED", r18_real_two_host_pilot: "NOT_RUN"
    };
  }
  function validatePreview(doc) {
    exact(doc, ["schema", "preview_only", "classification", "witness"], "preview");
    if (doc.schema !== SCHEMA || doc.preview_only !== true ||
        doc.classification !== "illustrative_fixture_not_fresh_run") {
      refuse("Preview must be explicitly illustrative");
    }
    return validateWitness(doc.witness);
  }
  function validateGates(roadmap) {
    if (!roadmap || typeof roadmap !== "object" || roadmap.schema !== "PhiXi.SharedRoadmap.v1" ||
        roadmap.live_xi_connected !== false || roadmap.authority !== "none" ||
        roadmap.status !== "candidate_planning_only" || !Array.isArray(roadmap.gates) ||
        roadmap.gates.length !== 16 || !Array.isArray(roadmap.milestones) ||
        !roadmap.milestones.some(m => m.id === "R17" && m.state === "blocked") ||
        !roadmap.milestones.some(m => m.id === "R18" && m.state === "planned")) {
      refuse("Source roadmap contract changed or claims live authority");
    }
    const ids = new Set();
    const gates = roadmap.gates.map(g => {
      if (!g || typeof g.id !== "string" || !/^[a-z_]{3,35}$/.test(g.id) ||
          ids.has(g.id) || !["missing", "candidate_unverified"].includes(g.state) ||
          typeof g.requirement !== "string" || g.requirement.length < 15 ||
          g.requirement.length > 500 || typeof g.owner !== "string" || g.owner.length > 60) {
        refuse("Source roadmap gate changed; cannot promote evidence");
      }
      ids.add(g.id);
      return {id:g.id, owner:g.owner, state:g.state, requirement:g.requirement};
    });
    return {gates, blocked: gates.length, verified: 0, source_date: roadmap.snapshot_date || "source undated"};
  }
  function redactedReview(classification, sha256, stats, gates) {
    if (!["ILLUSTRATIVE_PREVIEW","IMPORTED_UNTRUSTED_WITNESS"].includes(classification) ||
        typeof sha256 !== "string" || !/^[a-f0-9]{64}$/.test(sha256) ||
        !stats || stats.shape !== "R18_1_WITNESS_SHAPE_VALID_ONLY") {
      refuse("Cannot export unscreened evidence");
    }
    return {
      schema: REVIEW, source_kind: classification, source_bytes_sha256: sha256,
      witness_shape: stats.shape,
      reported_local_controls: CHECKS.map(c => c.id),
      reported_count: stats.checked_count,
      local_processes: 2, physical_hosts: 1,
      independently_authenticated_xi_receipts: 0, external_gates_promoted: 0,
      external_gates_outstanding: gates ? gates.blocked : 16,
      live_xi_connected: false, authority: "none",
      r17_external_pilot: "BLOCKED", r18_real_two_host_pilot: "NOT_RUN",
      qualification: "Local browser review only. Not a signature check, live peer authentication or trusted Xi approval."
    };
  }
  return { SCHEMA, REVIEW, PAYLOAD_HASH, CHECKS, ALL_KEYS,
    validateWitness, validatePreview, validateGates, redactedReview };
});
