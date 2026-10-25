/* Read-only R17.3 Commons Gateway: no Xi calls, grants or analytics. */
(function () {
  "use strict";
  const byId = (id) => document.getElementById(id);
  function isFixtureMilestone(m) {
    return m && typeof m === "object" &&
      (m.id === "R15" || m.id === "R16") &&
      m.state === "local_fixture_verified" && Array.isArray(m.evidence_links) &&
      m.evidence_links.length > 0;
  }
  function safeRoadmap(doc) {
    if (!doc || doc.schema !== "PhiXi.SharedRoadmap.v1" ||
      doc.live_xi_connected !== false || doc.authority !== "none" ||
      doc.status !== "candidate_planning_only" || !Array.isArray(doc.milestones) ||
      !Array.isArray(doc.gates) || doc.gates.length !== 16 ||
      !doc.milestones.some((m) => m.id === "R17" && m.state === "blocked") ||
      !doc.milestones.some((m) => m.id === "R18" && m.state === "planned") ||
      doc.gates.some((g) => !["missing", "candidate_unverified"].includes(g.state))) {
      throw Error("Roadmap has unrecognized authority or changed evidence states");
    }
    const found = doc.milestones.filter(isFixtureMilestone);
    if (found.length !== 2) throw Error("Local fixture evidence unexpectedly changed");
    const preview = doc.xi_public_preview;
    if (!preview || preview.capabilities_count !== 13 ||
      preview.sovereign_doors_count !== 12 ||
      !Array.isArray(preview.verified_capability_ids) ||
      preview.verified_capability_ids.length !== 0 ||
      !Array.isArray(preview.verified_door_ids) ||
      preview.verified_door_ids.length !== 0) {
      throw Error("Public Xi preview roster is no longer a non-authorizing snapshot");
    }
    return doc;
  }
  function safeRegistry(reg) {
    if (!reg || reg.schema !== "PhiXi.CapabilityRegistry.Candidate.v1" ||
      reg.live_xi_connected !== false || reg.auto_grants !== false ||
      reg.authority !== "none" || reg.status !== "unmapped_public_preview" ||
      !Array.isArray(reg.xi_slots) || reg.xi_slots.length !== 13 ||
      reg.xi_slots.some((slot) => slot.authorized !== false ||
        slot.independently_verified !== false || slot.native_operation !== null)) {
      throw Error("Registry cannot be displayed as remotely verified");
    }
    return reg;
  }
  function safeManifest(obj) {
    const expected = [
      "request.json", "synthetic-fixture.json",
      "pilot-preflight-draft.json", "transcript-template.json"
    ];
    if (!obj || obj.schema !== "PhiXi.PublicHandoffManifest.R17_3.v1" ||
      obj.live_xi_connected !== false || obj.authority !== "none" ||
      !Array.isArray(obj.files) || obj.files.length !== expected.length) {
      throw Error("Public handoff manifest does not match expected non-authorizing format");
    }
    obj.files.forEach((file, i) => {
      if (!file || file.name !== expected[i] ||
        typeof file.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(file.sha256) ||
        !Number.isInteger(file.size_bytes) || file.size_bytes <= 0 ||
        file.size_bytes > 32768) {
        throw Error("Public handoff manifest has an unexpected entry");
      }
    });
    return obj;
  }
  async function sourceJSON(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw Error("Missing local " + path);
    return response.json();
  }
  let manifest = null;
  Promise.all([
    sourceJSON("./bridge-roadmap.json").then(safeRoadmap),
    sourceJSON("./capability-registry.json").then(safeRegistry),
    sourceJSON("./handoff/manifest.json").then(safeManifest)
  ]).then(([roadmap, registry, handoff]) => {
    if (roadmap.xi_public_preview.capabilities_count !== registry.public_advertised_count ||
      registry.live_xi_connected !== false) throw Error("Public preview count mismatch");
    byId("milestones").textContent = "2";
    byId("gatecount").textContent = String(roadmap.gates.length);
    byId("capcount").textContent = String(registry.xi_slots.length);
    byId("doorscount").textContent = String(roadmap.xi_public_preview.sovereign_doors_count);
    byId("source-date").textContent = "Xi public preview snapshot: " + roadmap.snapshot_date +
      ". Local fixture evidence in source; external pilot not verified.";
    byId("evidence-status").textContent = "Source-bound status confirmed";
    manifest = handoff;
  }).catch(() => {
    byId("evidence-status").textContent = "Evidence data unavailable or unrecognized";
    byId("source-date").textContent = "Static descriptions are historical. Check the repository for the current status.";
  });

  document.querySelectorAll('a[href^="./handoff/"][download]').forEach((anchor) => {
    anchor.addEventListener("click", async (event) => {
      if (!manifest || !crypto || !crypto.subtle) return;
      const name = anchor.getAttribute("download");
      const entry = manifest.files.find((f) => f.name === name);
      if (!entry) { event.preventDefault(); return; }
      event.preventDefault();
      const original = anchor.textContent;
      anchor.textContent = "Checking SHA-256…";
      try {
        const response = await fetch("./handoff/" + name);
        if (!response.ok) throw Error("Missing static test packet");
        const bytes = await response.arrayBuffer();
        if (bytes.byteLength !== entry.size_bytes) throw Error("Unexpected packet size");
        const digest = await crypto.subtle.digest("SHA-256", bytes);
        const hex = Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, "0")).join("");
        if (hex !== entry.sha256) throw Error("Packet SHA-256 mismatch");
        const url = URL.createObjectURL(new Blob([bytes], { type: "application/json" }));
        const trigger = document.createElement("a");
        trigger.href = url;
        trigger.download = name;
        document.body.append(trigger);
        trigger.click();
        trigger.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1200);
      } catch (_) {
        byId("evidence-status").textContent = "Download blocked: public packet integrity check failed";
      } finally {
        anchor.textContent = original;
      }
    });
  });

  const title = byId("offline-title"), detail = byId("offline-detail");
  async function offlineReady(force) {
    const button = byId("offline-refresh");
    if (!("serviceWorker" in navigator) || !window.isSecureContext) {
      title.textContent = "Offline caching unavailable here";
      detail.textContent = "Use HTTPS or localhost in a browser that supports service workers. No private files are cached.";
      return;
    }
    button.disabled = true;
    try {
      const reg = await navigator.serviceWorker.register("./sw.js", { scope: "./" });
      if (force && navigator.onLine) await reg.update();
      await navigator.serviceWorker.ready;
      title.textContent = navigator.onLine ? "Public offline pack prepared" : "Working from saved public pages";
      detail.textContent = "Public gateway, roadmap, registry, intake and handoff files cached. External sites still require internet. Reload may be needed after first install.";
    } catch (_) {
      title.textContent = "Offline pack not yet available";
      detail.textContent = "Open again while online to cache the public pages. The gateway never caches imported partner JSON.";
    } finally {
      button.disabled = false;
    }
  }
  byId("offline-refresh").addEventListener("click", () => offlineReady(true));
  window.addEventListener("offline", () => offlineReady(false));
  window.addEventListener("online", () => offlineReady(false));
  offlineReady(false);
})();
