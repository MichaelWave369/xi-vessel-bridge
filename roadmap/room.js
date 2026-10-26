/* R18.5: literal public text copied only after user's click. No Xi network,
 * no persistence, dynamic messages, identity, tokens, or clipboard read. */
(function(){
  "use strict";
  const targets=Object.freeze({brief:"copy-brief-status",asks:"copy-asks-status"});
  for(const id of Object.keys(targets)){
    const button=document.querySelector('[data-copy="'+id+'"]');
    const field=document.getElementById(id);
    const status=document.getElementById(targets[id]);
    if(!button||!field||!status)continue;
    button.addEventListener("click",async()=>{
      // Does not read browser clipboard. Only fixed, source-reviewed public text.
      field.select();
      if(!navigator.clipboard||typeof navigator.clipboard.writeText!=="function"){
        status.textContent="Text selected. Copy manually with Ctrl+C.";
        return;
      }
      try{
        await navigator.clipboard.writeText(field.value);
        status.textContent="Public briefing copied. Share it only when you choose.";
      }catch(_){
        status.textContent="Copy unavailable. Text selected; use Ctrl+C.";
      }
    });
  }
})();
