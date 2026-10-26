/* Browser-only R18.3 rendering. Never fetch, transmit, persist, or execute external code. */
(function(){
  "use strict";
  const core=window.PhiXiFaultLab;
  const byId=id=>document.getElementById(id);
  let results=[];
  const choice=byId("scenario");
  for(const spec of core.CASES){
    const opt=document.createElement("option");
    opt.value=spec.id;opt.textContent=spec.name+" · "+spec.group;
    choice.append(opt);
  }
  byId("scenario-count").textContent=String(core.CASES.length);
  function explain(){
    const scenario=core.CASES.find(s=>s.id===choice.value);
    byId("scenario-desc").textContent=scenario ? scenario.description : "Choose a known scenario.";
  }
  choice.addEventListener("change",explain);
  function node(tag,cls,value){
    const x=document.createElement(tag);
    if(cls)x.className=cls;
    x.textContent=value;return x;
  }
  function renderTrace(trace){
    const root=byId("trace");
    root.replaceChildren(...trace.map(item=>{
      const li=node("li",null,"");
      li.append(node("strong",null,item.house),node("span","tag",item.decision),
        node("span",null,item.stage.toUpperCase()+" · "+item.note));
      return li;
    }));
  }
  function renderMatrix(reports){
    byId("matrix").replaceChildren(...reports.map(r=>{
      const box=node("article","scenario","");
      box.append(node("span","state",r.pass?"ILLUSTRATIVE PASS":"FIXTURE MISMATCH"),
        node("h3",null,r.title),
        node("p",null,"Expected "+r.expected+" · Got "+r.observed+" · "+r.denial_reason));
      return box;
    }));
  }
  function render(reports){
    results=reports;
    const latest=reports[reports.length-1];
    byId("decision").textContent=latest.pass?"EXPECTED OUTCOME":"FIXTURE MISMATCH";
    byId("decision").className="decision "+(latest.pass?"denied":"failed");
    byId("expected").textContent=latest.expected;
    byId("observed").textContent=latest.observed;
    byId("reason").textContent=latest.denial_reason;
    byId("commits").textContent=String(latest.receiver_commits);
    byId("download").disabled=reports.length===0 || reports.some(x=>!x.pass);
    byId("status").textContent=
      reports.length+" deterministic browser case(s) inspected; "+
      reports.filter(x=>x.pass).length+" match expected policy. No real Xi traffic or signature verification.";
    renderTrace(latest.trace);
    renderMatrix(reports);
  }
  byId("run").addEventListener("click",()=>{
    render([core.runScenario(choice.value)]);
  });
  byId("run-all").addEventListener("click",()=>{
    render(core.runAll());
  });
  byId("reset").addEventListener("click",()=>{
    results=[];
    byId("decision").textContent="NOT RUN";
    byId("decision").className="decision";
    byId("expected").textContent="Not selected";
    byId("observed").textContent="Not run";
    byId("reason").textContent="None";
    byId("commits").textContent="0";
    byId("download").disabled=true;
    byId("trace").replaceChildren(node("li",null,"No simulation selected."));
    byId("matrix").replaceChildren(node("div","empty","Run all scenarios to populate the failure matrix."));
    byId("status").textContent="Cleared. R17 externally blocked; real R18 crossing NOT RUN.";
  });
  byId("download").addEventListener("click",()=>{
    if(!results.length)return;
    const report=core.exportReview(results);
    const blob=new Blob([JSON.stringify(report,null,2)+"\n"],{type:"application/json"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");a.href=url;a.download="r183-illustrative-failure-review.json";
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1500);
  });
  explain();
})();
