/* R17.3 public-only offline cache. Never cache partner file imports or arbitrary URLs. */
"use strict";
const PREFIX = "phi-xi-commons-public-";
const CACHE_NAME = PREFIX + "__VERSION__";
const ASSETS = Object.freeze([
  "./", "./index.html", "./roadmap.html", "./capabilities.html", "./intake.html",
  "./commons.css", "./commons.js", "./intake-core.js", "./intake.js",
  "./bridge-roadmap.json", "./capability-registry.json", "./manifest.webmanifest",
  "./lab.html", "./lab.css", "./lab.js", "./lab-core.js", "./lab-preview.json",
  "./fault.html", "./fault.css", "./fault.js", "./fault-core.js",
  "./room.html", "./room.css", "./room.js",
  "./gates.html", "./gates.css", "./gates.js", "./gates-core.js",
  "./handoff/manifest.json", "./handoff/request.json",
  "./handoff/synthetic-fixture.json", "./handoff/pilot-preflight-draft.json",
  "./handoff/transcript-template.json"
]);
const allowed = new Set(ASSETS.map((asset) => new URL(asset, self.registration.scope).pathname));
self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    // Install fails instead of claiming an offline pack when a public file is missing.
    await cache.addAll(ASSETS.map((asset) => new URL(asset, self.registration.scope)));
    await self.skipWaiting();
  })());
});
self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((name) => name.startsWith(PREFIX) && name !== CACHE_NAME)
      .map((name) => caches.delete(name)));
    await self.clients.claim();
  })());
});
self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || !allowed.has(url.pathname)) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    try {
      const response = await fetch(req);
      if (!response.ok || response.type !== "basic") throw Error("Unacceptable static response");
      await cache.put(req, response.clone());
      return response;
    } catch (_) {
      const saved = await cache.match(req, { ignoreSearch: true });
      if (saved) return saved;
      return new Response("Public offline asset unavailable", {
        status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }
  })());
});
