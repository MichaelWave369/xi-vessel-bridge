"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const core = require("../roadmap/intake-core.js");
const reg = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../roadmap/capability-registry.json"), "utf8"));
const copy = (v) => JSON.parse(JSON.stringify(v));
const canonicalHash = createHash("sha256").update(core.canonical(reg)).digest("hex");

const response = (records=[]) => ({
  schema: "PhiXi.PartnerCapabilityResponse.Candidate.v1",
  reply_to_registry_sha256: canonicalHash,
  statement: "Synthetic local test only",
  records
});
const row = (id="xi-preview-01") => ({
  slot_id: id, name: "synthetic candidate", operation: "example.read",
  schema_sha256: "a".repeat(64), endpoint_description: "No real endpoint",
  evidence_url: "https://www.xi-field.com/#community",
  source_author: "Fictional tester"
});
const pilot = () => ({
  schema: "PhiXi.R18PilotDraft.v1", status: "draft_no_approval",
  transport: "unconfigured", endpoint_reference: null,
  native_schema_sha256: null, xi_peer_pin: null, phi_peer_pin: null,
  phi_operator_approval: false, xi_operator_approval: false,
  transport_security_verified: false, provenance_verified: false,
  durable_receipts_verified: false, independent_revocation_verified: false,
  data_classification: "synthetic_public", scope: "digest_only",
  live_xi_connected: false, authority: "none"
});
const transcript = () => ({
  schema: "PhiXi.R18TranscriptCandidate.v1",
  fixture_sha256: core.FIXTURE_HASH, phi_observed_sha256: null,
  xi_observed_sha256: null, phi_receipt_reference: null,
  xi_receipt_reference: null, two_physical_hosts_confirmed: false,
  notes: "No pilot conducted", status: "not_run"
});
test("R17.1 source registry passes strict browser scope", () => {
  assert.equal(core.verifyRegistry(reg), reg);
  assert.equal(core.SLOTS.length, 13);
  assert.match(canonicalHash, /^[a-f0-9]{64}$/);
});
test("exact 13 anonymous slots cannot be promoted", () => {
  const changed = copy(reg); changed.xi_slots[0].native_operation = "os.shell";
  assert.throws(() => core.verifyRegistry(changed));
  const changed2 = copy(reg); changed2.auto_grants = true;
  assert.throws(() => core.verifyRegistry(changed2));
});
test("valid candidate remains unverified", () => {
  const c = core.verifyResponse(response([row()]), canonicalHash);
  assert.equal(c.count, 1);
  assert.equal(c.independentProofCount, 0);
});
test("response bound to different registry is refused", () => {
  const incoming = response([row()]);
  incoming.reply_to_registry_sha256 = "0".repeat(64);
  assert.throws(() => core.verifyResponse(incoming, canonicalHash));
});
test("duplicate, unknown and extra-field operations refused", () => {
  assert.throws(() => core.verifyResponse(response([row(),row()]), canonicalHash));
  assert.throws(() => core.verifyResponse(response([row("not-a-slot")]), canonicalHash));
  const altered = row(); altered.permission = "admin";
  assert.throws(() => core.verifyResponse(response([altered]), canonicalHash));
});
test("candidate URLs cannot be arbitrary remote or query secrets", () => {
  for (const address of ["file:///etc/passwd", "http://www.xi-field.com",
                         "https://attacker.example.test/", "https://github.com/path?token=private"]) {
    const altered = row(); altered.evidence_url = address;
    assert.throws(() => core.verifyResponse(response([altered]), canonicalHash));
  }
});
test("preflight draft never proves an external gate", () => {
  let p = core.verifyPreflight(pilot());
  assert.equal(p.state, "BLOCKED_PENDING_INDEPENDENT_PROOF");
  assert.equal(p.missing, 10);
  const claimed = pilot();
  claimed.xi_operator_approval = true;
  claimed.xi_peer_pin = "self-reported-not-a-real-key";
  p = core.verifyPreflight(claimed);
  assert.equal(p.selfReported, 2);
  assert.equal(p.independentProofCount, 0);
});
test("preflight refuses fake live status, shell scope and network transport", () => {
  for (const [field,value] of [["live_xi_connected",true],["authority","admin"],
    ["scope","repo.write"], ["transport","tcp://0.0.0.0"], ["phi_operator_approval","true"]]) {
    const p = pilot(); p[field] = value;
    assert.throws(() => core.verifyPreflight(p));
  }
});
test("not-run transcript cannot assert a two-host result", () => {
  assert.equal(core.verifyTranscript(transcript()).state, "NOT_RUN");
  const modified = transcript(); modified.two_physical_hosts_confirmed = true;
  assert.throws(() => core.verifyTranscript(modified));
});
test("claimed matching hashes cannot promote real Xi execution", () => {
  const t = transcript();
  t.status = "candidate_unverified";
  t.phi_observed_sha256 = core.FIXTURE_HASH;
  t.xi_observed_sha256 = core.FIXTURE_HASH;
  t.two_physical_hosts_confirmed = true;
  const result = core.verifyTranscript(t);
  assert.equal(result.reportedMatch, true);
  assert.equal(result.independentlyAuthenticatedReceipts, 0);
});
test("redacted review contains no candidate body or source author's private text", () => {
  const incoming = response([row()]);
  const review = core.review(reg, canonicalHash,
    { response: incoming, preflight: pilot(), transcript: transcript() });
  assert.equal(review.candidate_slots[0], "xi-preview-01");
  assert.equal(review.file_reviews.partner_response.state, "SELF_REPORTED_CANDIDATES_ONLY");
  assert.equal(review.live_xi_connected, false);
  assert.equal(review.authorized_operations, 0);
  assert.ok(!JSON.stringify(review).includes("Fictional tester"));
  assert.ok(!JSON.stringify(review).includes("example.read"));
});
test("unknown or injected top-level claims are refused", () => {
  const incoming = response([]);
  incoming.grant = "ALL";
  assert.throws(() => core.verifyResponse(incoming, canonicalHash));
  const altered = copy(reg);
  altered.live_xi_connected = true;
  assert.throws(() => core.verifyRegistry(altered));
});
