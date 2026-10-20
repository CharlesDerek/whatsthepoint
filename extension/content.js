(() => {
  let timer, running=false;
  const inspect=async()=>{
    if(running || !document.body) return;
    running=true;
    try {
      const text=(document.title+'\n'+(document.querySelector('meta[name="description"]')?.content || '')+'\n'+document.body.innerText).slice(0,32000);
      const result=await chrome.runtime.sendMessage({type:'inspect',text});
      if(result.error) {
        // A lost portal connection must not leave an existing tab silently unfiltered.
        location.replace(chrome.runtime.getURL('gate.html')+'#'+location.href.split('#')[0]);
      }
    } catch { /* An uninstalled extension has no authority over the page. */ }
    finally {running=false;}
  };
  document.addEventListener('click', event=>{
    const link=event.composedPath().find(el=>el?.tagName==='A' && el.href);
    if(!link || event.button!==0 || event.defaultPrevented || link.hasAttribute('download')) return;
    const target=new URL(link.href,location.href);
    if(target.origin===location.origin && target.pathname===location.pathname && target.search===location.search && target.hash) return;
    if(['mailto:','tel:'].includes(target.protocol)) return;
    event.preventDefault(); event.stopImmediatePropagation();
    chrome.runtime.sendMessage({type:'link',url:target.href,newTab:event.ctrlKey || event.metaKey || link.target==='_blank'}).catch(()=>{});
  },true);
  const start=()=>{
    inspect();
    new MutationObserver(()=>{clearTimeout(timer);timer=setTimeout(inspect,1500);}).observe(document.body,{childList:true,subtree:true,characterData:true});
  };
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',start,{once:true}); else start();
  chrome.runtime.onMessage.addListener(message=>{if(message.type==='recheck') inspect();});
})();
