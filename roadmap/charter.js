/* R18.7: fixed same-origin public file reads and human-click local export ONLY.
 * No operator keys, private endpoints, approvals, remote calls or persistence.
 */
(function(){
 "use strict";
 const api=window.PhiXiCharter,byId=id=>document.getElementById(id);
 let sources=null,proposal=null,requestId=0;
 function status(v){byId("status").textContent=v;}
 function element(tag,cls,text){
  const node=document.createElement(tag);
  if(cls)node.className=cls;
  if(text!==undefined)node.textContent=text;
  return node;
 }
 function steps(){
  byId("sequence").replaceChildren(...api.FLIGHT.map((p,i)=>{
   const card=element("article","step");
   card.append(element("small",null,String(i+1).padStart(2,"0")+" / "+p.id),
    element("h3",null,p.title),element("p",null,p.condition));
   return card;
  }));
 }
 function clear(message){
  requestId++;
  proposal=null;
  byId("copy").disabled=byId("export").disabled=true;
  byId("preview").textContent="No charter built.";
  status(message);
 }
 async function checkedJson(path){
  const res=await fetch(path,{cache:"no-store"});
  if(!res.ok)throw Error("Source file is unavailable");
  const bytes=await res.arrayBuffer();
  if(bytes.byteLength===0||bytes.byteLength>32768)throw Error("Unexpected source document size");
  return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
 }
 async function load(){
  const ticket=++requestId;
  status("Reading and checking existing public R18 source packets…");
  try{
   const [fixture,preflight,roadmap]=await Promise.all([
    checkedJson("./handoff/synthetic-fixture.json"),
    checkedJson("./handoff/pilot-preflight-draft.json"),
    checkedJson("./bridge-roadmap.json")
   ]);
   const incoming={fixture,preflight,roadmap};
   api.validateSources(incoming);
   if(ticket!==requestId)return;
   sources=incoming;
   status("Three public sources checked. All 16 gates missing and both operator approvals false.");
  }catch(_){
   if(ticket!==requestId)return;
   sources=null;
   clear("Source data unavailable, unreviewed, or promoted. Charter generation refused.");
  }
 }
 byId("build").addEventListener("click",()=>{
  if(!sources){
   status("Public sources have not passed validation; no charter created.");
   return;
  }
  try{
   const doc=api.charter(sources,byId("scope").value);
   api.validateCharter(doc);
   proposal=doc;
   byId("preview").textContent=JSON.stringify(doc,null,2);
   byId("copy").disabled=byId("export").disabled=false;
   status("Public proposal assembled. Zero human approvals, zero authenticated Xi peers, zero executable rights.");
  }catch(_){clear("Candidate refused: unknown scope, altered sources or authority violation.");}
 });
 byId("scope").addEventListener("change",()=>{
  proposal=null;byId("preview").textContent="Select Build to generate a new public draft.";
  byId("copy").disabled=byId("export").disabled=true;
 });
 byId("clear").addEventListener("click",()=>clear("Local proposal cleared. No source states or remote permissions changed."));
 byId("copy").addEventListener("click",async()=>{
  if(!proposal)return;
  let message;
  try{message=api.textForRoom(proposal);}catch(_){clear("Unreviewed proposal cannot be copied.");return;}
  if(!navigator.clipboard||typeof navigator.clipboard.writeText!=="function"){
   status("Clipboard unavailable. Draft remains visible below for manual copy.");
   return;
  }
  try{await navigator.clipboard.writeText(message);status("Public UNAPPROVED proposal copied on your request.");}
  catch(_){status("Clipboard permission denied. No content transmitted.");}
 });
 byId("export").addEventListener("click",()=>{
  if(!proposal)return;
  try{api.validateCharter(proposal);}
  catch(_){clear("Export refused: proposal modified or unsafe.");return;}
  const blob=new Blob([JSON.stringify(proposal,null,2)+"\n"],{type:"application/json"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");a.href=url;a.download="xi-phi-r187-unapproved-synthetic-pilot-charter.json";
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1500);
 });
 steps();load();
})();