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

  // R18.4 evidence file import: intentionally validates only local JSON SHAPE.
  // No network calls, no persistence, no authentication, no privilege changes.
  const reportInput=byId("r184-file");
  let importRevision=0;
  function clearWorker(message){
    importRevision++;
    reportInput.value="";
    byId("r184-verdict").textContent="NOT INSPECTED";
    byId("r184-status").textContent=message;
    byId("r184-results").replaceChildren(
      node("div","empty","Import the redacted local-worker CI report to see reported test outcomes.")
    );
  }
  byId("r184-clear").addEventListener("click",()=>{
    clearWorker("Report cleared from browser memory. No external Xi evidence promoted.");
  });
  reportInput.addEventListener("change",async()=>{
    const revision=++importRevision;
    const file=reportInput.files && reportInput.files[0];
    byId("r184-verdict").textContent="INSPECTING LOCAL FILE";
    if(!file || file.size<1 || file.size>32768){
      clearWorker("Refused: only nonempty local JSON reports up to 32 KiB.");
      return;
    }
    try{
      const raw=await file.arrayBuffer();
      const body=new TextDecoder("utf-8",{fatal:true}).decode(raw);
      const evidence=core.validateWorkerReport(JSON.parse(body));
      if(revision!==importRevision)return;
      byId("r184-verdict").textContent="SHAPE VALID · SOURCE UNAUTHENTICATED";
      byId("r184-status").textContent=
        "Local JSON reports "+evidence.reported_passes+" of "+evidence.case_count+
        " worker cases. This browser cannot verify who generated it.";
      byId("r184-results").replaceChildren(...evidence.cases.map(row=>{
        const box=node("article","scenario","");
        box.append(node("span","state","IMPORTED · UNTRUSTED"),
          node("h3",null,row.name),
          node("p",null,"Reported "+row.observed+" · "+row.commits+" receiver commit(s)"));
        return box;
      }));
    }catch(_){
      if(revision===importRevision){
        clearWorker("R18.4 file rejected: unknown fields, unsafe claims or incompatible summary.");
      }
    }
  });
  explain();
})();
