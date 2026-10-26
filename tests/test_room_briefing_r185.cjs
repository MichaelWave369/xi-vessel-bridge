"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs");
const html=fs.readFileSync("roadmap/room.html","utf8");
const script=fs.readFileSync("roadmap/room.js","utf8");
function textarea(id){
 const match=html.match(new RegExp('<textarea id="'+id+'"[^>]*>([\\s\\S]*?)<\\/textarea>'));
 assert.ok(match,"missing public "+id+" textarea");
 return match[1];
}
test("one-minute briefing binds actual merged R18.4 success and public gateway",()=>{
 const msg=textarea("brief");
 assert.match(msg,/michaelwave369\.github\.io\/xi-vessel-bridge\//);
 assert.match(msg,/actions\/runs\/40254943486/);
 assert.match(msg,/two independently keyed Python processes/i);
 assert.match(msg,/14 real local-worker fault cases/i);
 assert.match(msg,/NOT connected to Xi/);
 assert.match(msg,/16 external readiness gates remain unresolved/);
 assert.doesNotMatch(msg,/PRIVATE KEY|BEGIN [A-Z ]+ PRIVATE KEY|Bearer [A-Za-z0-9]/);
});
test("session follow-up requests documentation and human consent without secrets",()=>{
 const msg=textarea("asks");
 assert.match(msg,/Xi-native read-only operation schema/);
 assert.match(msg,/out of band/);
 assert.match(msg,/separately approved, revocable two-host synthetic test/);
 assert.match(msg,/don't paste private endpoints/);
 assert.match(msg,/not approval on Xi's behalf/);
});
test("browser clipboard helper is click-only and forbids contact with Xi",()=>{
 assert.match(html,/connect-src 'none'/);
 assert.match(html,/form-action 'none'/);
 assert.match(html,/id="copy-brief"/);
 assert.match(html,/id="copy-asks"/);
 assert.match(html,/src="\.\/room.js"/);
 assert.match(script,/addEventListener\("click"/);
 assert.match(script,/navigator\.clipboard\.writeText\(field\.value\)/);
 assert.match(script,/field\.select\(\)/);
 assert.doesNotMatch(script,/\bfetch\(|\bWebSocket\b|\bXMLHttpRequest\b|\bsendBeacon\b|\blocalStorage\b|\bsessionStorage\b|\binnerHTML\b|\bexecCommand\b/);
 assert.doesNotMatch(html,/<form\b|<iframe\b|type="password"/);
});
test("room packet keeps the trust boundary and evidence links explicit",()=>{
 assert.match(html,/EXTERNAL PILOT BLOCKED/);
 assert.match(html,/REAL TWO-HOST TEST NOT RUN/);
 assert.match(html,/Authenticated live Xi peers/);
 assert.match(html,/13 Xi capability and 12 door counts remain/);
 assert.match(html,/https:\/\/github\.com\/MichaelWave369\/xi-vessel-bridge\/actions\/runs\/40254943500/);
});
