/* R17.2 browser-only Xi handoff viewer.
 * Files are processed in memory and never uploaded. Only the same-origin static
 * capability-registry.json is fetched; export strips all supplied free text.
 */
(function () {
  "use strict";
  var core = window.PhiXiIntake;
  var registry = null;
  var registryHash = null;
  var selected = { response: null, preflight: null, transcript: null };
  var fingerprints = {};
  var report = null;
  var revisions = { response: 0, preflight: 0, transcript: 0 };
  var SLOTS = core.SLOTS;

  function find(id) { return document.getElementById(id); }
  function label(id, text) { find(id).textContent = text; }
  function encodeDigest(arrayBuffer) {
    return crypto.subtle.digest("SHA-256", arrayBuffer).then(function (buffer) {
      return Array.from(new Uint8Array(buffer)).map(function (n) {
        return n.toString(16).padStart(2, "0");
      }).join("");
    });
  }
  function resetSlots(candidateSlots) {
    var target = find("slots");
    target.replaceChildren();
    SLOTS.forEach(function (id) {
      var item = document.createElement("div");
      item.className = "slot" + (candidateSlots.includes(id) ? " candidate" : "");
      var name = document.createElement("b");
      name.textContent = id;
      var caption = document.createElement("span");
      caption.textContent = candidateSlots.includes(id) ?
        "Self-reported · Unverified" : "Unmapped · No grant";
      item.append(name, caption);
      target.append(item);
    });
  }
  function draw() {
    if (!registry || !registryHash) return;
    try {
      report = core.review(registry, registryHash, selected);
      report.input_sha256 = Object.assign({ registry: fingerprints.registry }, {
        response: fingerprints.response || null,
        preflight: fingerprints.preflight || null,
        transcript: fingerprints.transcript || null
      });
      // Empty fingerprints intentionally omitted; don't imply phantom files.
      Object.keys(report.input_sha256).forEach(function (k) {
        if (report.input_sha256[k] === null) delete report.input_sha256[k];
      });
      label("stat-candidates", String(report.candidate_slots.length));
      label("verdict", report.verdict.replaceAll("_", " "));
      var count = report.candidate_slots.length;
      label("summary", count ?
        String(count) + " nominated Xi slot(s). Syntax checked locally; zero independently authenticated or authorized. " +
          "Preflight: " + report.file_reviews.pilot_preflight.state +
          ". Transcript: " + report.file_reviews.pilot_transcript.state + "." :
        "No partner capabilities nominated. Existing public previews are still not verified operations.");
      resetSlots(report.candidate_slots);
      var gates = find("gates");
      gates.replaceChildren();
      report.required_independent_evidence.forEach(function (requirement) {
        var item = document.createElement("li");
        item.textContent = requirement;
        gates.append(item);
      });
      label("report-json", JSON.stringify(report, null, 2));
      find("export").disabled = false;
    } catch (error) {
      report = null;
      find("export").disabled = true;
      showError("Validation refused: " + error.message);
    }
  }
  function showError(message) {
    var element = find("alert");
    element.style.display = "block";
    element.textContent = message;
  }
  function clearError() {
    var element = find("alert");
    element.style.display = "none";
    element.textContent = "";
  }
  async function readSelected(kind, file, ticket) {
    if (!file) {
      selected[kind] = null; delete fingerprints[kind];
      label(kind + "-state", "Not supplied");
      clearError(); draw(); return;
    }
    if (file.size > 128 * 1024 || file.size === 0) {
      selected[kind] = null; delete fingerprints[kind];
      label(kind + "-state", "Refused: empty or larger than 128 KiB");
      showError("Refused an empty or oversized local JSON file.");
      draw(); return;
    }
    try {
      var bytes = await file.arrayBuffer();
      var raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      var parsed = JSON.parse(raw);
      if (kind === "response") core.verifyResponse(parsed, registryHash);
      if (kind === "preflight") core.verifyPreflight(parsed);
      if (kind === "transcript") core.verifyTranscript(parsed);
      var fingerprint = await encodeDigest(bytes);
      if (ticket !== revisions[kind]) return;
      selected[kind] = parsed;
      fingerprints[kind] = fingerprint;
      label(kind + "-state", "Shape accepted · " + fingerprint.slice(0, 14) +
        "… · NOT independently verified");
      clearError(); draw();
    } catch (error) {
      if (ticket !== revisions[kind]) return;
      selected[kind] = null; delete fingerprints[kind];
      label(kind + "-state", "Refused: invalid candidate JSON");
      draw();
      // Deliberately avoid showing user-supplied values or raw file data in errors.
      showError("This candidate file did not match its strict non-authorizing format.");
    }
  }
  function attach(kind) {
    find(kind).addEventListener("change", function () {
      var ticket = ++revisions[kind];
      selected[kind] = null; delete fingerprints[kind];
      readSelected(kind, this.files && this.files[0], ticket);
    });
  }
  function clear() {
    ["response", "preflight", "transcript"].forEach(function (kind) {
      revisions[kind]++;
      selected[kind] = null;
      delete fingerprints[kind];
      find(kind).value = "";
      label(kind + "-state", "Not supplied");
    });
    clearError();
    draw();
  }
  find("clear").addEventListener("click", clear);
  ["response", "preflight", "transcript"].forEach(attach);
  find("example").addEventListener("click", function () {
    if (!registryHash) {
      showError("Local registry must load successfully before the example can run.");
      return;
    }
    clear();
    // These are deliberately fictional claims, not Hunter's runtime data.
    selected.response = {
      schema: "PhiXi.PartnerCapabilityResponse.Candidate.v1",
      reply_to_registry_sha256: registryHash,
      statement: "Synthetic demonstration only, not a message from Xi",
      records: [{
        slot_id: "xi-preview-01", name: "EXAMPLE ONLY: candidate digest",
        operation: "example.digest.read", schema_sha256: "a".repeat(64),
        endpoint_description: "No real host or endpoint",
        evidence_url: "https://www.xi-field.com/#community",
        source_author: "Fictional demonstration, not Xi staff"
      }]
    };
    selected.preflight = {
      schema: "PhiXi.R18PilotDraft.v1", status: "draft_no_approval",
      transport: "unconfigured", endpoint_reference: null,
      native_schema_sha256: null, xi_peer_pin: null, phi_peer_pin: null,
      phi_operator_approval: false, xi_operator_approval: false,
      transport_security_verified: false, provenance_verified: false,
      durable_receipts_verified: false, independent_revocation_verified: false,
      data_classification: "synthetic_public", scope: "digest_only",
      live_xi_connected: false, authority: "none"
    };
    selected.transcript = {
      schema: "PhiXi.R18TranscriptCandidate.v1", fixture_sha256: core.FIXTURE_HASH,
      phi_observed_sha256: null, xi_observed_sha256: null,
      phi_receipt_reference: null, xi_receipt_reference: null,
      two_physical_hosts_confirmed: false, notes: "Synthetic local preview only",
      status: "not_run"
    };
    label("response-state", "Fictional local example · no partner file");
    label("preflight-state", "Fictional local example · no partner approval");
    label("transcript-state", "Fictional local example · no two-host test");
    draw();
  });
  find("export").addEventListener("click", function () {
    if (!report || !registryHash) return;
    // Report includes only counts, named slot IDs, digests, and blocker categories.
    var data = JSON.stringify(report, null, 2) + "\n";
    var link = document.createElement("a");
    var url = URL.createObjectURL(new Blob([data], { type: "application/json" }));
    link.href = url;
    link.download = "phi-xi-r17-2-redacted-review.json";
    link.style.display = "none";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  });
  resetSlots([]);
  (async function () {
    try {
      if (!crypto || !crypto.subtle) throw Error("Secure local context required");
      var response = await fetch("./capability-registry.json", { cache: "no-store" });
      if (!response.ok) throw Error("Capability registry missing");
      var raw = await response.text();
      if (raw.length > 128 * 1024) throw Error("Registry too large");
      var candidate = JSON.parse(raw);
      core.verifyRegistry(candidate);
      // Matches Python r171 document_hash: deterministic JSON, sorted keys,
      // compact separators, UTF-8. Registry fields are ASCII-keyed JSON.
      var canonical = new TextEncoder().encode(core.canonical(candidate));
      registryHash = await encodeDigest(canonical);
      fingerprints.registry = await encodeDigest(new TextEncoder().encode(raw));
      registry = candidate;
      label("registry-state", "Local registry loaded and shape verified · canonical SHA-256 " +
        registryHash + " · No external evidence or grants checked.");
      clearError();
      draw();
    } catch (error) {
      find("export").disabled = true;
      label("registry-state", "Registry unavailable or invalid · intake disabled");
      showError("Unable to load a valid same-origin local registry. " +
        "Serve the roadmap directory over HTTP on localhost, or check its source files.");
    }
  })();
})();
