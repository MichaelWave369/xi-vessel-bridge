/* R18.2 public static lab console. No Xi requests or cryptographic simulation.
   Browser never stores imported files outside this page's in-memory selection. */
(function () {
  "use strict";
  const core = window.PhiXiLab;
  const byId = id => document.getElementById(id);
  const MAX_BYTES = 16 * 1024;
  let current = null;
  let gates = null;
  let revision = 0;
  const fileInput = byId("local-file");
  const status = byId("input-status");
  function tell(message) { status.textContent = message; }
  function reset(message) {
    ++revision;
    current = null;
    fileInput.value = "";
    byId("mode").textContent = "Nothing selected";
    byId("reported").textContent = "Not inspected";
    byId("fingerprint").textContent = "Not loaded";
    byId("export").disabled = true;
    byId("check-grid").replaceChildren();
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No evidence loaded. Preview or import a redacted local simulation summary.";
    byId("check-grid").append(empty);
    tell(message);
  }
  function hex(raw) { return [...new Uint8Array(raw)].map(x=>x.toString(16).padStart(2,"0")).join(""); }
  async function fingerprint(bytes) {
    if (!window.crypto || !window.crypto.subtle) throw Error("SHA-256 unavailable: open via HTTPS or localhost");
    return hex(await window.crypto.subtle.digest("SHA-256", bytes));
  }
  function putCheck(check, kind) {
    const card = document.createElement("article");
    card.className = "check";
    const label = document.createElement("span");
    label.textContent = "REPORTED · " + (check.type === "negative" ? "DENIAL" : "LOCAL FIXTURE");
    const heading = document.createElement("h3");
    heading.textContent = check.label;
    const note = document.createElement("p");
    note.textContent = kind === "ILLUSTRATIVE_PREVIEW"
      ? "Illustrative source template. Not freshly executed."
      : "Field is true in imported JSON; signer not authenticated.";
    card.append(label, heading, note);
    return card;
  }
  function present(kind, summary, sha, name) {
    current = {kind, summary, sha};
    byId("mode").textContent = kind === "ILLUSTRATIVE_PREVIEW"
      ? "ILLUSTRATIVE ONLY · SOURCE TEMPLATE" : "UNTRUSTED LOCAL FILE · SHAPE VALID";
    byId("reported").textContent = String(summary.checked_count) + " positive control claims; not independently verified";
    byId("fingerprint").textContent = sha;
    byId("check-grid").replaceChildren(...summary.checks.map(c=>putCheck(c,kind)));
    byId("export").disabled = false;
    tell(name + " inspected locally. This is not proof of Xi identity or live transport.");
  }
  async function processBytes(bytes, kind, name, check, ticket) {
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_BYTES) throw Error("File exceeds 16 KiB or is empty");
    const text = new TextDecoder("utf-8", {fatal:true}).decode(bytes);
    const doc = JSON.parse(text);
    const summary = check(doc);
    const sha = await fingerprint(bytes);
    if (ticket !== revision) return;
    present(kind,summary,sha,name);
  }
  byId("show-preview").addEventListener("click", async () => {
    const ticket = ++revision;
    byId("export").disabled = true;
    current = null;
    fileInput.value = "";
    tell("Reading the illustrative preview from this site's public assets…");
    try {
      const response = await fetch("./lab-preview.json", {cache:"no-store"});
      if (!response.ok) throw Error("Static preview unavailable");
      const bytes = await response.arrayBuffer();
      await processBytes(bytes, "ILLUSTRATIVE_PREVIEW", "Static example", core.validatePreview, ticket);
    } catch (_) {
      if (ticket === revision) reset("Preview unavailable or invalid. No evidence promoted.");
    }
  });
  fileInput.addEventListener("change", async () => {
    const ticket = ++revision;
    const file = fileInput.files && fileInput.files[0];
    current = null;
    byId("export").disabled = true;
    if (!file) { reset("No file chosen."); return; }
    if (file.size === 0 || file.size > MAX_BYTES) {
      reset("Local report must contain 1–16 KiB of JSON. File rejected.");
      return;
    }
    tell("Inspecting file bytes locally…");
    try {
      const bytes = await file.arrayBuffer();
      await processBytes(bytes, "IMPORTED_UNTRUSTED_WITNESS",
        "Imported report", core.validateWitness, ticket);
    } catch (_) {
      if (ticket === revision) reset("File refused: unexpected shape, altered fixture, or unauthorized status.");
    }
  });
  byId("clear").addEventListener("click", () => reset("Imported report and preview cleared from this page."));
  byId("export").addEventListener("click", () => {
    if (!current) return;
    let report;
    try { report = core.redactedReview(current.kind,current.sha,current.summary,gates); }
    catch (_) { reset("Review export refused by local validator."); return; }
    const bytes = new Blob([JSON.stringify(report,null,2) + "\n"],{type:"application/json"});
    const url = URL.createObjectURL(bytes);
    const a = document.createElement("a");
    a.href=url; a.download="xi-r182-redacted-review.json";
    document.body.append(a);
    a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url),1500);
  });
  function appendGate(entry) {
    const item = document.createElement("article");
    item.className = "gate";
    const title = document.createElement("h3");
    title.textContent = entry.id.replace(/_/g," ");
    const sub = document.createElement("small");
    sub.textContent = "OUTSTANDING · " + entry.owner + " · " + entry.state;
    const p = document.createElement("p");
    p.textContent = entry.requirement;
    item.append(title,sub,p);
    return item;
  }
  fetch("./bridge-roadmap.json", {cache:"no-store"}).then(response => {
    if (!response.ok) throw Error("Source roadmap missing");
    return response.json();
  }).then(doc => {
    gates = core.validateGates(doc);
    byId("gate-list").replaceChildren(...gates.gates.map(appendGate));
    byId("gate-total").textContent = String(gates.blocked);
    byId("gate-status").textContent = "Read-only source snapshot " + gates.source_date +
      ": " + gates.blocked + " unresolved external requirements; zero independently verified by this page.";
  }).catch(() => {
    gates = null;
    byId("gate-status").textContent =
      "Source roadmap unavailable or incompatible. No gates can be considered complete.";
  });
  reset("No evidence loaded. External Xi pilot remains blocked.");
})();
