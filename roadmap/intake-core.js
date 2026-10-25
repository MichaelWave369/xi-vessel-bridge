/* Phi-Xi R17.2 offline partner intake: candidate-only, no permission authority.
 * Shared by browser UI and dependency-free Node negative controls.
 * Nothing here contacts Xi or authenticates a human/agent.
 */
(function (root, factory) {
  "use strict";
  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PhiXiIntake = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";
  var SLOTS = Array.from({ length: 13 }, function (_, i) {
    return "xi-preview-" + String(i + 1).padStart(2, "0");
  });
  var EXPECTED_PHI = ["phi.artifact.sha256", "phi.porch.inventory", "phi.handshake.observe"];
  var HEX = /^[a-f0-9]{64}$/;
  var FIXTURE_HASH = "8370bdb1f706a2168accc1c225a37c98ec907cd3e954b67c1cdcc9d8ddd8feb5";
  var REGISTRY_SCHEMA = "PhiXi.CapabilityRegistry.Candidate.v1";
  var RESPONSE_SCHEMA = "PhiXi.PartnerCapabilityResponse.Candidate.v1";
  var PREFLIGHT_SCHEMA = "PhiXi.R18PilotDraft.v1";
  var TRANSCRIPT_SCHEMA = "PhiXi.R18TranscriptCandidate.v1";
  var REVIEW_SCHEMA = "PhiXi.PartnerIntakeReview.R17_2.v1";
  var regKeys = ["schema", "snapshot_date", "status", "source_url",
    "public_advertised_count", "live_xi_connected", "authority", "auto_grants",
    "disclosure", "xi_slots", "phi_candidates", "partner_request"];
  var slotKeys = ["slot_id", "public_name", "native_operation", "schema_sha256",
    "endpoint_id", "independently_verified", "authorized", "state", "source"];
  var phiKeys = ["id", "name", "scope", "read_only", "exposed_remotely", "source"];
  var pilotKeys = ["schema", "status", "transport", "endpoint_reference",
    "native_schema_sha256", "xi_peer_pin", "phi_peer_pin", "phi_operator_approval",
    "xi_operator_approval", "transport_security_verified", "provenance_verified",
    "durable_receipts_verified", "independent_revocation_verified",
    "data_classification", "scope", "live_xi_connected", "authority"];
  var transcriptKeys = ["schema", "fixture_sha256", "phi_observed_sha256",
    "xi_observed_sha256", "phi_receipt_reference", "xi_receipt_reference",
    "two_physical_hosts_confirmed", "notes", "status"];
  function insist(ok, reason) { if (!ok) throw Error(reason); }
  function fields(obj, expected, label) {
    insist(obj !== null && typeof obj === "object" && !Array.isArray(obj), "Invalid " + label + " object");
    var names = Object.keys(obj).sort();
    insist(names.length === expected.length &&
      names.every(function (key, i) { return key === expected.slice().sort()[i]; }),
      "Unexpected or missing " + label + " fields");
  }
  function bounded(s, label, max) {
    insist(typeof s === "string" && s.length > 0 && s.length <= max &&
      !/[\u0000-\u001f]/.test(s), "Invalid " + label);
  }
  function sourceURL(s) {
    bounded(s, "evidence URL", 1024);
    var url;
    try { url = new URL(s); } catch (_) { throw Error("Invalid evidence URL"); }
    insist(url.protocol === "https:" && !url.username && !url.password &&
      ["www.xi-field.com", "xi-field.com", "github.com", "room.xi-field.com"].includes(url.hostname),
      "Evidence URL outside known public-source hosts");
    insist(!url.search && (!url.hash || url.hash === "#community"),
      "Evidence URLs cannot carry query tokens or unrecognized fragments");
  }
  function canonical(obj) {
    if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
    if (obj !== null && typeof obj === "object") {
      return "{" + Object.keys(obj).sort().map(function (key) {
        return JSON.stringify(key) + ":" + canonical(obj[key]);
      }).join(",") + "}";
    }
    return JSON.stringify(obj);
  }
  function verifyRegistry(reg) {
    fields(reg, regKeys, "registry");
    insist(reg.schema === REGISTRY_SCHEMA && reg.snapshot_date === "2026-10-25" &&
      reg.status === "unmapped_public_preview" && reg.public_advertised_count === 13 &&
      reg.live_xi_connected === false && reg.authority === "none" &&
      reg.auto_grants === false, "Registry identity, scope or authority violation");
    sourceURL(reg.source_url);
    bounded(reg.disclosure, "registry disclosure", 1024);
    insist(Array.isArray(reg.xi_slots) && reg.xi_slots.length === 13,
      "Registry has unexpected number of slots");
    reg.xi_slots.forEach(function (s, i) {
      fields(s, slotKeys, "preview slot");
      insist(s.slot_id === SLOTS[i] && s.public_name === null && s.native_operation === null &&
        s.schema_sha256 === null && s.endpoint_id === null &&
        s.independently_verified === false && s.authorized === false &&
        s.state === "awaiting_partner_spec" && s.source === "public_count_only",
        "Unexpected authority or mapping in Xi slot");
    });
    insist(Array.isArray(reg.phi_candidates) && reg.phi_candidates.length === 3,
      "PHI local candidate roster mismatch");
    var ids = [];
    reg.phi_candidates.forEach(function (candidate) {
      fields(candidate, phiKeys, "PHI candidate");
      insist(candidate.read_only === true && candidate.exposed_remotely === false,
        "PHI candidate cannot be exposed remotely");
      bounded(candidate.id, "candidate ID", 100);
      bounded(candidate.name, "candidate name", 240);
      bounded(candidate.scope, "candidate scope", 240);
      sourceURL(candidate.source);
      ids.push(candidate.id);
    });
    insist(ids.slice().sort().join("|") === EXPECTED_PHI.slice().sort().join("|"),
      "Unexpected local candidate ID");
    fields(reg.partner_request, ["requested_information", "recipient", "note"], "partner request");
    insist(Array.isArray(reg.partner_request.requested_information) &&
      reg.partner_request.requested_information.length >= 6,
      "Missing partner contract questions");
    reg.partner_request.requested_information.forEach(function (s) {
      bounded(s, "contract question", 1024);
    });
    bounded(reg.partner_request.recipient, "recipient", 240);
    bounded(reg.partner_request.note, "partner note", 1024);
    return reg;
  }
  function verifyResponse(response, registryHash) {
    fields(response, ["schema", "reply_to_registry_sha256", "records", "statement"], "partner response");
    insist(response.schema === RESPONSE_SCHEMA && response.reply_to_registry_sha256 === registryHash,
      "Partner response does not bind to this registry");
    bounded(response.statement, "response statement", 1024);
    insist(Array.isArray(response.records) && response.records.length <= 13,
      "Partner record count exceeded");
    var slots = [];
    response.records.forEach(function (item) {
      fields(item, ["slot_id", "name", "operation", "schema_sha256", "endpoint_description",
        "evidence_url", "source_author"], "partner record");
      insist(SLOTS.includes(item.slot_id) && !slots.includes(item.slot_id),
        "Unknown or duplicate candidate slot");
      bounded(item.name, "capability name", 120);
      bounded(item.operation, "candidate operation", 160);
      bounded(item.source_author, "attribution", 160);
      bounded(item.endpoint_description, "endpoint description", 512);
      insist(typeof item.schema_sha256 === "string" && HEX.test(item.schema_sha256),
        "Missing or malformed proposed schema digest");
      sourceURL(item.evidence_url);
      slots.push(item.slot_id);
    });
    return { state: "SELF_REPORTED_CANDIDATES_ONLY", slots: slots.sort(),
      count: slots.length, independentProofCount: 0 };
  }
  function verifyPreflight(doc) {
    fields(doc, pilotKeys, "pilot preflight");
    insist(doc.schema === PREFLIGHT_SCHEMA && doc.status === "draft_no_approval" &&
      doc.transport === "unconfigured" && doc.scope === "digest_only" &&
      doc.data_classification === "synthetic_public" &&
      doc.live_xi_connected === false && doc.authority === "none",
      "Pilot draft attempted to promote privileges or live transport");
    var optional = ["endpoint_reference", "native_schema_sha256", "xi_peer_pin", "phi_peer_pin"];
    var bools = ["phi_operator_approval", "xi_operator_approval",
      "transport_security_verified", "provenance_verified",
      "durable_receipts_verified", "independent_revocation_verified"];
    var present = 0;
    optional.forEach(function (key) {
      var value = doc[key];
      insist(value === null || (typeof value === "string" && value.length > 0 && value.length <= 512),
        "Invalid draft reference");
      if (value !== null) present++;
    });
    bools.forEach(function (key) {
      insist(typeof doc[key] === "boolean", "Invalid self-reported approval flag");
      if (doc[key]) present++;
    });
    return { state: "BLOCKED_PENDING_INDEPENDENT_PROOF", missing: 10 - present,
      selfReported: present, independentProofCount: 0 };
  }
  function verifyTranscript(doc) {
    fields(doc, transcriptKeys, "pilot transcript");
    insist(doc.schema === TRANSCRIPT_SCHEMA && doc.fixture_sha256 === FIXTURE_HASH &&
      ["not_run", "candidate_unverified"].includes(doc.status) &&
      typeof doc.two_physical_hosts_confirmed === "boolean" &&
      typeof doc.notes === "string" && doc.notes.length <= 800,
      "Invalid transcript evidence or unauthorized status");
    ["phi_observed_sha256", "xi_observed_sha256"].forEach(function (key) {
      insist(doc[key] === null || (typeof doc[key] === "string" && HEX.test(doc[key])),
        "Invalid observation digest");
    });
    ["phi_receipt_reference", "xi_receipt_reference"].forEach(function (key) {
      insist(doc[key] === null || (typeof doc[key] === "string" &&
        doc[key].length > 0 && doc[key].length <= 256), "Invalid receipt reference");
    });
    if (doc.status === "not_run") {
      insist(doc.two_physical_hosts_confirmed === false &&
        ["phi_observed_sha256", "xi_observed_sha256", "phi_receipt_reference",
          "xi_receipt_reference"].every(function (key) { return doc[key] === null; }),
        "Not-run transcript falsely reported external evidence");
    }
    return {
      state: doc.status === "not_run" ? "NOT_RUN" : "CANDIDATE_SELF_REPORT_ONLY",
      reportedMatch: doc.phi_observed_sha256 === FIXTURE_HASH &&
        doc.xi_observed_sha256 === FIXTURE_HASH,
      independentlyAuthenticatedReceipts: 0
    };
  }
  function review(reg, registryHash, input) {
    verifyRegistry(reg);
    insist(typeof registryHash === "string" && HEX.test(registryHash),
      "Registry hash required");
    var result = { schema: REVIEW_SCHEMA, stage: "R17.2",
      verdict: "BLOCKED_PENDING_EXTERNAL_EVIDENCE",
      registry_sha256: registryHash,
      candidate_slots: [], unmapped_slots: SLOTS.slice(),
      file_reviews: {}, independently_verified_partner_capabilities: 0,
      authorized_operations: 0, live_xi_connected: false, authority: "none",
      claims_not_established: ["live_xi_connected", "peer_authenticated",
        "human_authorization", "external_two_host_test"],
      required_independent_evidence: [
        "Independently pinned partner public keys",
        "Verified native Xi schemas and transport contract",
        "Both human operator approvals",
        "Authenticated encrypted two-host transport and consent",
        "Independent signed runtime receipts and replay tests",
        "Independent pause/revoke/disconnect tests"
      ],
      disclosure: "Syntax and self-reports are not authentic identity or permissions." };
    if (input.response) {
      var r = verifyResponse(input.response, registryHash);
      result.candidate_slots = r.slots;
      result.unmapped_slots = SLOTS.filter(function (s) { return !r.slots.includes(s); });
      result.file_reviews.partner_response = { state: r.state, candidate_count: r.count,
        independent_proof_count: 0, authorization_count: 0 };
    } else result.file_reviews.partner_response = { state: "NOT_SUPPLIED", candidate_count: 0 };
    if (input.preflight) {
      var p = verifyPreflight(input.preflight);
      result.file_reviews.pilot_preflight = { state: p.state,
        missing_claim_count: p.missing, unverified_candidate_claim_count: p.selfReported,
        independent_proof_count: 0 };
    } else result.file_reviews.pilot_preflight = { state: "NOT_SUPPLIED" };
    if (input.transcript) {
      var t = verifyTranscript(input.transcript);
      result.file_reviews.pilot_transcript = { state: t.state,
        self_reported_digest_match: t.reportedMatch,
        independently_authenticated_receipts: 0 };
    } else result.file_reviews.pilot_transcript = { state: "NOT_SUPPLIED" };
    return result;
  }
  return { SLOTS: SLOTS, FIXTURE_HASH: FIXTURE_HASH,
    canonical: canonical, verifyRegistry: verifyRegistry,
    verifyResponse: verifyResponse, verifyPreflight: verifyPreflight,
    verifyTranscript: verifyTranscript, review: review };
});
