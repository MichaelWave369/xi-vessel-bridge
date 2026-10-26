/* R18.6 local-only discussion agenda UI. No partner calls, approval controls,
 * persistence, private-file intake or status mutations.
 */
(function(){
  "use strict";
  const model=window.PhiXiGateBoard;
  const el=id=>document.getElementById(id);
  let board=null,selected=new Set();
  function make(tag,cls,value){
    const item=document.createElement(tag);
    if(cls)item.className=cls;
    if(value!==undefined)item.textContent=value;
    return item;
  }
  function status(message){el("status").textContent=message;}
  function currentAgenda(){
    if(!board||!selected.size)throw Error("Select a public discussion topic");
    return model.agenda(board,[...selected]);
  }
  function refresh(){
    el("picked").textContent=String(selected.size);
    el("copy").disabled=el("export").disabled=!board||selected.size===0;
    status(board
      ? selected.size+" public topic(s) selected. All 16 external gates are still MISSING; zero approved."
      : "Read-only roadmap unavailable. No permission status changed.");
  }
  function render(){
    const holder=el("phases");
    holder.replaceChildren(...board.groups.map(group=>{
      const panel=make("section","phase");
      const head=make("div","phase-head");
      head.append(make("h3",null,group.title),make("p",null,group.aim));
      panel.append(head);
      for(const gate of group.gates){
        const area=make("div","gate"),label=make("label"),checkbox=document.createElement("input");
        checkbox.type="checkbox";checkbox.value=gate.id;checkbox.checked=selected.has(gate.id);
        const body=make("div");
        body.append(make("strong",null,gate.id.replace(/_/g," ")),
          make("small",null,gate.owner.toUpperCase()+" · MISSING IN SOURCE"),
          make("p",null,gate.requirement));
        label.append(checkbox,body);area.append(label);panel.append(area);
        checkbox.addEventListener("change",()=>{
          if(checkbox.checked)selected.add(gate.id);else selected.delete(gate.id);
          refresh();
        });
      }
      return panel;
    }));
    refresh();
  }
  el("first").addEventListener("click",()=>{
    if(!board)return;
    selected=new Set(model.GROUPS[0].ids);
    render();
  });
  el("clear").addEventListener("click",()=>{selected.clear();if(board)render();else refresh();});
  el("copy").addEventListener("click",async()=>{
    let words;
    try{words=model.agendaText(currentAgenda());}
    catch(_){status("Agenda rejected: missing source validation.");return;}
    if(!navigator.clipboard||typeof navigator.clipboard.writeText!=="function"){
      status("Clipboard unavailable. Use JSON export or browser HTTPS.");return;
    }
    try{await navigator.clipboard.writeText(words);status("Public unapproved agenda copied. You choose whether to share it.");}
    catch(_){status("Clipboard denied. Use the public JSON download instead.");}
  });
  el("export").addEventListener("click",()=>{
    let doc;
    try{doc=currentAgenda();}
    catch(_){status("Agenda rejected: no valid topics selected.");return;}
    const file=new Blob([JSON.stringify(doc,null,2)+"\n"],{type:"application/json"});
    const u=URL.createObjectURL(file),a=document.createElement("a");
    a.href=u;a.download="phi-xi-r186-public-discussion-agenda.json";
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(u),1500);
  });
  fetch("./bridge-roadmap.json",{cache:"no-store"}).then(response=>{
    if(!response.ok)throw Error("source unavailable");
    return response.json();
  }).then(doc=>{
    board=model.review(doc);
    selected.clear();render();
  }).catch(()=>{
    board=null;selected.clear();
    el("phases").replaceChildren(make("div","empty",
      "Roadmap missing, changed, or contains a promoted gate. Refusing to plan from unverified source."));
    refresh();
  });
})();
