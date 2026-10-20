export function cleanUrl(raw) {
  if (typeof raw !== 'string' || raw.length > 4096) throw new Error('URL exceeds 4096 characters.');
  const url = new URL(raw);
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw new Error('Only HTTP(S) links without embedded credentials are allowed.');
  url.hash = '';
  for (const key of [...url.searchParams.keys()]) {
    if (/^utm_/i.test(key) || /^(fbclid|gclid|dclid|msclkid|mc_cid|mc_eid)$/i.test(key)) url.searchParams.delete(key);
  }
  return url.href;
}
export function portalOrigin(raw) {
  const url = new URL(raw);
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(url.hostname)))) throw new Error('Use an HTTPS portal origin, or HTTP on loopback for local testing.');
  return url.origin;
}
export function classify(text, categories) {
  text = String(text).slice(0,32000).toLowerCase();
  return categories.filter(c => c.id !== 'unclassified' && c.terms.filter(term => {
    let start = 0, index;
    while ((index = text.indexOf(term, start)) !== -1) {
      const before = [...text.slice(0,index)].at(-1) || '';
      const after = [...text.slice(index + term.length)][0] || '';
      if (!/[\p{L}\p{N}]/u.test(before) && !/[\p{L}\p{N}]/u.test(after)) return true;
      start = index + term.length;
    }
    return false;
  }).length >= c.threshold).map(c => c.id);
}
export function exactRule(id, tabId, url) {
  return {id, priority:100, action:{type:'allow'}, condition:{regexFilter:`^${cleanUrl(url).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, isUrlFilterCaseSensitive:true, resourceTypes:['main_frame'], requestMethods:['get'], tabIds:[tabId]}};
}
