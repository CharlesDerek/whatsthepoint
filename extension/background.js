import {cleanUrl, portalOrigin, classify, exactRule} from './common.js';
const gate = chrome.runtime.getURL('gate.html');
const options = chrome.runtime.getURL('options.html');
const host = 'org.whatsthepoint.identity';
let queue = Promise.resolve();
const serialized = task => { const next = queue.then(task); queue = next.catch(() => {}); return next; };
const ready = (async () => {
  await chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
  await chrome.storage.managed.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
  const stale = await chrome.declarativeNetRequest.getSessionRules();
  await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:stale.map(r=>r.id)});
  await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:[10],addRules:[{
    id:10,priority:2,action:{type:'redirect',redirect:{regexSubstitution:`${gate}#\\0`}},
    condition:{regexFilter:'^https?://.*',resourceTypes:['main_frame'],requestMethods:['get']}
  }]});
  await chrome.alarms.create('recheck',{periodInMinutes:0.5});
})();
async function settings() {
  const local = await chrome.storage.local.get(['portal','token','requireNative']);
  const managed = await chrome.storage.managed.get(['portal','token','requireNative']);
  // Presence of a managed portal locks the entire configuration; never combine
  // an admin portal with a user-controlled credential or alternate identity mode.
  const config = managed.portal ? managed : local;
  return {...config,managed:!!managed.portal};
}
async function nativeIdentity(required) {
  try {
    const result = await chrome.runtime.sendNativeMessage(host,{type:'identity'});
    if (result.error || !result.identity) throw new Error(result.error || 'Desktop identity unavailable.');
    return result.identity;
  } catch(error) {
    if (required) throw new Error('The desktop identity companion is required. Ask your administrator to register it.');
    return null;
  }
}
async function request(path, body) {
  const config = await settings();
  if (!config.portal || !config.token) throw new Error('This browser is not enrolled. Open the extension settings.');
  const portal = portalOrigin(config.portal);
  const response = await fetch(`${portal}/agent/${path}`,{
    method:body === undefined ? 'GET' : 'POST', credentials:'omit', cache:'no-store', redirect:'error',
    headers:{Authorization:`Bearer ${config.token}`,'X-WTP-Request':'1','Content-Type':'application/json'},
    body:body === undefined ? undefined : JSON.stringify(body),signal:AbortSignal.timeout(8000)
  });
  if (!response.ok) {
    const error = await response.json().catch(()=>({}));
    throw new Error(error.error || `Portal unavailable (${response.status}). Navigation remains blocked.`);
  }
  return response.json();
}
async function check(raw, categories=[]) {
  const config = await settings();
  const identity = await nativeIdentity(config.requireNative);
  return request('check',{url:cleanUrl(raw),categories,identity});
}
async function removePermit(tabId) {
  await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:[100000+tabId]});
}
async function evidence(tabId, raw) {
  const saved=(await chrome.storage.session.get(`verdict-${tabId}`))[`verdict-${tabId}`];
  return saved?.url===cleanUrl(raw) ? saved.categories : [];
}
async function permit(tabId, raw) {
  const tab = await chrome.tabs.get(tabId);
  if (!tab.url?.startsWith(gate)) throw new Error('The navigation check is no longer active.');
  const result = await check(raw,await evidence(tabId,raw));
  if (result.action !== 'allow') return result;
  const rule = exactRule(100000+tabId,tabId,result.url);
  const supported = await chrome.declarativeNetRequest.isRegexSupported({regex:rule.condition.regexFilter,isCaseSensitive:true});
  if (!supported.isSupported) throw new Error('This URL is too complex for a safe navigation permit.');
  await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:[rule.id],addRules:[rule]});
  try { await chrome.tabs.update(tabId,{url:result.url}); }
  catch(error) { await removePermit(tabId); throw error; }
  return result;
}
async function readPage(tabId,raw) {
  const result = await check(raw,await evidence(tabId,raw));
  if (result.action !== 'sanitize') return {verdict:result};
  // No portal credential or browser cookies are sent to the destination. Do not
  // follow redirects: every new destination requires its own policy decision.
  const response = await fetch(result.url,{credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',cache:'no-store',signal:AbortSignal.timeout(8000)});
  if (!response.ok || !response.headers.get('content-type')?.toLowerCase().includes('text/html')) throw new Error('Reader mode requires an HTML page without redirects.');
  const reader = response.body.getReader(); let length=0, html=''; const decoder=new TextDecoder();
  try {
    while (true) {
      const {done,value}=await reader.read(); if(done) break;
      length+=value.byteLength;
      if(length>1024*1024) throw new Error('Reader pages are limited to 1 MB.');
      html+=decoder.decode(value,{stream:true});
    }
    html+=decoder.decode();
  } finally { await reader.cancel(); }
  return {verdict:result,html};
}
async function handle(message,sender) {
  await ready;
  if (sender.id !== chrome.runtime.id) throw new Error('Unknown sender.');
  const internal = sender.url?.split('#')[0];
  if (internal === options) {
    if(message.type==='settings') {
      const config=await settings();
      const identity=await nativeIdentity(false);
      let policy=null, error=null;
      try { policy=await request('policy'); } catch(e) {error=e.message;}
      return {portal:config.portal,managed:config.managed,requireNative:config.requireNative,identity,policy,error};
    }
    if(message.type==='enroll') {
      if((await settings()).managed) throw new Error('Enrollment is controlled by your administrator.');
      const portal=portalOrigin(message.portal);
      if(!/^[0-9a-f]{64}$/i.test(message.token)) throw new Error('Enter the profile token shown by your portal.');
      await chrome.storage.local.set({portal,token:message.token,requireNative:!!message.requireNative});
      return {ok:true};
    }
  }
  if (internal === gate && sender.tab) {
    if(message.type==='check') return check(message.url,await evidence(sender.tab.id,message.url));
    if(message.type==='continue') return serialized(()=>permit(sender.tab.id,message.url));
    if(message.type==='reader') return readPage(sender.tab.id,message.url);
    if(message.type==='classify-reader') {
      const policy=await request('policy');
      return check(message.url,classify(message.text,policy.categories));
    }
    if(message.type==='pending') return (await chrome.storage.session.get(`pending-${sender.tab.id}`))[`pending-${sender.tab.id}`] || null;
  }
  // Content scripts may submit bounded text for classification, but cannot mint
  // navigation permits, choose a different tab, or read enrollment credentials.
  if (message.type==='inspect' && sender.tab && sender.frameId===0 && /^https?:/.test(sender.url || '')) {
    const policy=await request('policy');
    const verdict=await check(sender.url,classify(message.text,policy.categories));
    if(verdict.action!=='allow') {
      const current=await chrome.tabs.get(sender.tab.id);
      if(cleanUrl(current.url)===cleanUrl(sender.url)) {
        await serialized(()=>removePermit(sender.tab.id));
        // Keep a content-based block on the gate; never drop its category evidence
        // and accidentally re-authorize the same page based on URL alone.
        await chrome.storage.session.set({[`verdict-${sender.tab.id}`]:verdict});
        await chrome.tabs.update(sender.tab.id,{url:`${gate}#${verdict.url}`});
      }
    }
    return verdict;
  }
  if(message.type==='link' && sender.tab && sender.frameId===0 && /^https?:/.test(sender.url || '')) {
    const url=cleanUrl(message.url);
    // The built-in DNR gate remains authoritative even if a page intercepts clicks.
    if(message.newTab) await chrome.tabs.create({url:`${gate}#${url}`});
    else await chrome.tabs.update(sender.tab.id,{url:`${gate}#${url}`});
    return {ok:true};
  }
  throw new Error('Unsupported request.');
}
chrome.runtime.onMessage.addListener((message,sender,respond)=>{
  handle(message,sender).then(value=>respond({value}),error=>respond({error:error.message})); return true;
});
chrome.action.onClicked.addListener(()=>chrome.runtime.openOptionsPage());
chrome.webNavigation.onBeforeNavigate.addListener(details=>{
  if(details.frameId===0 && /^https?:/.test(details.url)) chrome.storage.session.set({[`pending-${details.tabId}`]:details.url});
});
chrome.webNavigation.onCommitted.addListener(details=>{
  if(details.frameId===0) serialized(async()=>{await ready; await removePermit(details.tabId);}).catch(()=>{});
});
chrome.tabs.onRemoved.addListener(tabId=>serialized(async()=>{
  await ready; await removePermit(tabId);
  await chrome.storage.session.remove([`pending-${tabId}`,`verdict-${tabId}`]);
}).catch(()=>{}));
chrome.alarms.onAlarm.addListener(async alarm=>{
  if(alarm.name!=='recheck') return;
  await ready;
  // Also expires a permit if navigation never commits (aborted or hung request).
  await serialized(async()=>{
    const rules=await chrome.declarativeNetRequest.getSessionRules();
    await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:rules.map(r=>r.id)});
  });
  for(const tab of await chrome.tabs.query({url:['http://*/*','https://*/*']})) {
    chrome.tabs.sendMessage(tab.id,{type:'recheck'}).catch(()=>{});
  }
});
