'use strict';

const paths = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  shield: '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z"/><path d="m8 12 3 3 5-6"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  devices: '<rect x="3" y="4" width="15" height="11" rx="2"/><path d="M7 20h7m-3-5v5"/><rect x="17" y="10" width="5" height="11" rx="1"/>',
  settings: '<path d="M4 7h16M4 17h16"/><circle cx="8" cy="7" r="3"/><circle cx="16" cy="17" r="3"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/>',
  globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
  logout: '<path d="M10 4H4v16h6M9 12h12m-4-4 4 4-4 4"/>',
  terminal: '<path d="m5 7 5 5-5 5m8 0h6"/>',
  bolt: '<path d="m13 2-9 12h7l-1 8 10-13h-7z"/>',
};
const icon = name => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.shield}</svg>`;
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const num = value => new Intl.NumberFormat().format(value || 0);
const date = value => value ? new Date(value * 1000).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : 'Not yet';
const time = value => new Date(value * 1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
const badge = (value, label = value) => `<span class="badge ${esc(value)}">${value === 'allowed' || value === 'allow' ? '↗' : value === 'blocked' || value === 'block' ? '⊘' : '·'} ${esc(label)}</span>`;
const empty = (message, name='shield') => `<div class="empty">${icon(name)}${esc(message)}</div>`;
const button = (action, label, name, cls='', extra='') => `<button type="button" data-action="${action}" class="${cls}" ${extra}>${name ? icon(name) : ''}${label}</button>`;
const views = {overview:['Overview','grid'],queries:['Query log','activity'],rules:['Your rules','shield'],lists:['Blocklists','list'],clients:['Clients','devices'],browser:['Browser protection','shield'],endpoints:['Endpoints','devices'],settings:['Settings','settings']};
const root = document.querySelector('#root');
const modal = document.querySelector('#modal');
let session = null, currentView = 'overview', requestId = 0, toastTimer;
let browserData, endpointData, endpointEnrollment;
let queryFilter = {search:'',decision:'',before:''}, queryRows = [], loadedRules = [];

async function api(path, method='GET', data) {
  const headers = {'X-WTP-Request':'1'};
  if (session?.csrf) headers['X-CSRF-Token'] = session.csrf;
  if (data !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`/api${path}`, {method, headers, credentials:'same-origin', body:data === undefined ? undefined : JSON.stringify(data)});
  let body;
  try { body = await response.json(); } catch { body = {error:'The service returned an unexpected response.'}; }
  if (!response.ok) {
    if (response.status === 401 && path !== '/login') { session = null; showLogin(); }
    throw new Error(body.error || `Request failed (${response.status}).`);
  }
  return body;
}
function toast(message, error=false) {
  const el = document.querySelector('#toast');
  el.textContent = message;
  el.className = `show${error?' error':''}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.className='', 5000);
}
function showLogin() {
  requestId++;
  if (modal.open) modal.close();
  root.innerHTML = `<main class="login-page">
    <section class="login-story"><div class="brand"><img src="/favicon.svg" alt="">what’s the point<small> </small></div>
      <div><div class="login-motif"><div class="motif-node">${icon('globe')}</div><span class="motif-line"></span><div class="motif-node main-node">${icon('shield')}</div><span class="motif-line"></span><div class="motif-node">${icon('devices')}</div></div>
      <h1>Your network.<br>Your rules.<br><em>That’s the point.</em></h1><p>A little less noise. A lot more control. Open source web filtering, built in Rust and made to stay out of your way.</p></div>
      <span class="small">DNS protection. Browser policies. One portal.</span>
    </section>
    <section class="login-form"><div class="login-box"><div class="eyebrow">THE NETWORK CONSOLE</div><h2>Welcome back.</h2><p>Your corner of the internet is waiting.</p>
      <form id="login-form" class="form-stack"><label>Username<input name="username" autocomplete="username" required maxlength="64" autofocus placeholder="admin"></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" required maxlength="1024" placeholder="Your administrator password"></label>
      <div id="login-error" class="error-text" role="alert"></div><button class="primary" type="submit">Sign in to your console ${icon('arrow')}</button></form>
      <p class="login-note">First time here? Create your administrator with <code>wtp init</code> in the terminal. Your credentials stay on your server.</p>
    </div></section></main>`;
}
function shell() {
  root.innerHTML = `<div class="layout"><aside class="sidebar">
    <div class="brand"><img src="/favicon.svg" alt=""><div>what’s the point<small>LESS NOISE. MORE INTERNET.</small></div></div>
    <div class="nav-label">WORKSPACE</div><nav aria-label="Main navigation">${Object.entries(views).map(([key,[label,img]])=>`<button type="button" data-view="${key}">${icon(img)}${label}<span class="nav-dot" hidden></span></button>`).join('')}</nav>
    <div class="sidebar-foot"><div class="engine-card"><strong><span class="dot"></span>Rust under the hood.</strong><small>Open source. On your terms.</small></div>
    <div class="user"><div class="avatar">${esc(session.username[0]?.toUpperCase() || 'A')}</div><div><strong>${esc(session.username)}</strong><small>Administrator</small></div>${button('logout','', 'logout','', 'aria-label="Sign out" title="Sign out"')}</div></div>
    </aside><main class="main"><header class="topbar"><div class="breadcrumb">Workspace <span>/</span><b id="crumb">Overview</b></div><span class="mobile-brand">what’s the point</span><div class="top-status"><a href="https://github.com/CharlesDerek/whatsthepoint" target="_blank" rel="noreferrer">Open source ↗</a><span id="connection"><span class="dot"></span>Console connected</span></div></header>
    <div class="content"><div id="page"></div><footer class="footer"><span>Built with Rust. <strong>Run by you.</strong></span><span>One point closer to a less annoying internet.</span></footer></div></main></div>`;
}
function head(title, subtitle, actions='') {
  return `<div class="page-head"><div><div class="eyebrow">YOUR NETWORK, AT A GLANCE</div><h1>${title}</h1><p>${subtitle}</p></div><div class="actions">${actions}</div></div>`;
}
async function navigate(view, quiet=false) {
  if (!views[view] || !session) return;
  currentView = view;
  const id = ++requestId;
  document.querySelectorAll('[data-view]').forEach(el => { const active = el.dataset.view===view; el.classList.toggle('active',active); el.setAttribute('aria-current', active?'page':'false'); });
  document.querySelector('#crumb').textContent = views[view][0];
  if (!quiet) {
    history.replaceState(null,'',`#${view}`);
    document.querySelector('#page').innerHTML = empty('Loading your network…','activity');
  }
  try {
    const content = await renderers[view]();
    if (id !== requestId || !session) return;
    document.querySelector('#page').innerHTML = content;
    document.querySelectorAll('[data-height]').forEach(el=>el.style.height=`${Math.max(0,Math.min(100,Number(el.dataset.height)))}%`);
    document.querySelectorAll('[data-width]').forEach(el=>el.style.width=`${Math.max(0,Math.min(100,Number(el.dataset.width)))}%`);
    document.querySelector('#connection').innerHTML = '<span class="dot"></span>Console connected';
  } catch(error) {
    if (id !== requestId || !session) return;
    document.querySelector('#connection').textContent = 'Connection interrupted';
    if (!quiet) document.querySelector('#page').innerHTML = `<div class="notice">${esc(error.message)}</div>${button('reload','Try again','refresh')}`;
  }
}
function queryTable(rows, compact=false) {
  if (!rows.length) return empty('No queries yet. Point a device at this resolver to see what’s happening.','activity');
  return `<div class="table-wrap"><table><thead><tr><th>Domain</th><th>Client</th><th>Status</th>${compact?'':'<th>Reason</th><th>Type</th>'}<th>Response</th><th>Time</th>${compact?'':'<th>Rule</th>'}</tr></thead><tbody>${rows.map(q=>`<tr>
    <td class="domain" title="${esc(q.domain)}">${esc(q.domain)}</td><td class="mono">${esc(q.client)}</td><td>${badge(q.decision)}</td>${compact?'':`<td>${esc(q.reason)}</td><td class="small">${esc(q.qtype)}</td>`}<td class="small">${q.cached?'↻ ':''}${num(q.elapsed_ms)} ms</td><td class="small">${time(q.at)}</td>${compact?'':`<td>${button('quick-rule',q.decision==='blocked'?'Allow':'Block',null,'text-button',`data-domain="${esc(q.domain)}" data-rule-action="${q.decision==='blocked'?'allow':'block'}"`)}</td>`}</tr>`).join('')}</tbody></table></div>`;
}
function chart(stats) {
  const nowHour = Math.floor(Date.now()/3600000)*3600;
  const values = Array.from({length:24},(_,i) => {
    const hour=nowHour-(23-i)*3600, item=stats.hourly.find(row=>row[0]===hour);
    return {hour,total:item?.[1]||0,blocked:item?.[2]||0};
  });
  const max = Math.max(4,...values.map(v=>v.total));
  return `<div class="chart" role="img" aria-label="Hourly DNS queries over the last 24 hours: ${num(stats.total)} queries, ${num(stats.blocked)} blocked."><div class="axis-y"><span>${num(max)}</span><span>${num(Math.round(max*.75))}</span><span>${num(Math.round(max*.5))}</span><span>${num(Math.round(max*.25))}</span><span>0</span></div>
    <div class="bars">${values.map(v=>`<div class="bar-slot" title="${esc(new Date(v.hour*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}))} · ${v.total} queries · ${v.blocked} blocked"><div class="bar-stack"><div class="bar-part blocked-color" data-height="${v.blocked/max*100}"></div><div class="bar-part allowed-color" data-height="${(v.total-v.blocked)/max*100}"></div></div></div>`).join('')}</div>
    <div class="axis-x">${[0,6,12,18,23].map(i=>`<span>${new Date(values[i].hour*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span>`).join('')}</div>${stats.total?'':'<div class="chart-empty">A quiet start.<br>Your real traffic will appear here.</div>'}</div>`;
}
const renderers = {
  async overview() {
    const [s, recent] = await Promise.all([api('/stats'),api('/queries')]);
    const percent = s.total ? (s.blocked/s.total*100).toFixed(1) : '0';
    return head('A clearer view of your network.','A little less noise. A lot more peace of mind.',`<span class="period">${icon('clock')} Last 24 hours</span>${button('test','Test a domain','terminal')}`)
    + `<div class="welcome"><div class="welcome-mark">↗</div><div class="welcome-copy"><h2>${s.domains ? 'Your filter has a point.' : 'Give your filter something to filter.'}</h2><p>${s.domains ? `${num(s.domains)} blocklist domains and ${num(s.rules)} custom rules. Quietly doing their thing.` : 'Add a community blocklist to catch ads, trackers, and known bad destinations.'}</p></div>${button(s.domains?'add-rule':'go-lists',s.domains?'Add a rule':'Add protection','plus', 'lime')}</div>`
    + (!s.query_log?'<div class="notice">Query logging is disabled. Traffic metrics and history are unavailable; filtering is still active.</div>':'')
    + `<div class="stats">${[
      ['Total queries',num(s.total),'globe','Actual queries in your retained history'],
      ['Queries blocked',num(s.blocked),'shield',`<strong>${percent}%</strong> of all queries`],
      ['Average response',`${s.latency.toFixed(1)} <span class="small">ms</span>`,'bolt',`<strong>${s.total?Math.round(s.cached/s.total*100):0}%</strong> served from cache`],
      ['Active clients',num(s.clients),'devices','Unique IP addresses seen today']
    ].map(([label,value,img,note])=>`<div class="stat"><div class="stat-top">${label}${icon(img)}</div><div class="stat-value">${value}</div><div class="stat-note">${note}</div></div>`).join('')}</div>`
    + `<div class="dashboard-grid"><section class="panel"><div class="panel-head"><div><h2>Traffic, without the noise.</h2><p>Every request has a story. Here’s the bigger picture.</p></div><div class="legend"><span><i class="allowed-color"></i>Other queries</span><span><i class="blocked-color"></i>Blocked</span></div></div><div class="panel-body">${chart(s)}<div class="chart-summary"><span>Upstream errors <b>${num(s.errors)}</b></span><span>Service uptime <b>${Math.floor(s.uptime/3600)}h ${Math.floor(s.uptime%3600/60)}m</b></span></div></div></section>
    <section class="panel"><div class="panel-head"><div><h2>Stopped at the door.</h2><p>Most blocked domains · last 24 hours</p></div>${icon('shield')}</div><div class="panel-body">${s.top.length?s.top.map(([domain,count])=>`<div class="top-domain"><span class="mono" title="${esc(domain)}">${esc(domain)}</span><strong>${num(count)}</strong><div class="progress-track"><div class="progress-fill" data-width="${count/s.top[0][1]*100}"></div></div></div>`).join(''):empty('Nothing to report. And sometimes, that’s the point.')}</div></section></div>`
    + `<section class="panel"><div class="panel-head"><div><h2>Just passed through.</h2><p>A live look at your latest DNS requests.</p></div>${button('go-queries','View query log →',null,'text-button')}</div>${queryTable(recent.slice(0,6),true)}<div class="table-footer"><span><span class="dot"></span>Updates every 10 seconds</span><span>Stored on your server</span></div></section>`;
  },
  async queries() {
    const params = new URLSearchParams(Object.entries(queryFilter).filter(([,v])=>v));
    queryRows = await api(`/queries?${params}`);
    return head('Every query. In plain sight.','See what passed, what stopped, and why.',button('reload','Refresh','refresh')+button('clear-log','Clear history','trash'))
    + `<form id="query-filter" class="filters"><input name="search" aria-label="Search domains or client IPs" placeholder="Search a domain or client IP…" value="${esc(queryFilter.search)}"><select name="decision" aria-label="Filter by decision">${[['','All decisions'],['allowed','Allowed'],['blocked','Blocked'],['error','Errors']].map(([v,l])=>`<option value="${v}" ${queryFilter.decision===v?'selected':''}>${l}</option>`).join('')}</select><button type="submit">Apply filters</button></form>`
    + `<section class="panel">${queryTable(queryRows)}<div class="table-footer"><span>Up to 100 queries per page · ↻ means cached</span><div class="actions">${queryFilter.before?button('newest-queries','Newest',null,'text-button'):''}${queryRows.length===100?button('older-queries','Older queries →',null,'text-button'):''}</div></div></section>`;
  },
  async rules() {
    loadedRules = await api('/rules');
    return head('Your network. Your call.','Domain rules also apply to subdomains. Explicit allow rules take priority.',button('test','Test a domain','terminal')+button('add-rule','Add a rule','plus','primary'))
      + `<section class="panel"><div class="panel-head"><h2>Custom rules <span class="badge neutral">${num(loadedRules.length)}</span></h2><input id="rule-search" aria-label="Search rules" placeholder="Find a rule…"></div><div id="rules-table">${rulesTable(loadedRules)}</div></section>`;
  },
  async lists() {
    const lists = await api('/lists');
    return head('Good company. Better filtering.','Community-maintained protection, with the last good copy always kept locally.',button('import-list','Import a list','plus'))
    + `<div class="notice">Managed feeds refresh daily. Downloads contact GitHub only when installed or refreshed. Domain lists and hosts files are supported.</div>`
    + `<div class="cards">${lists.map(list=>`<section class="panel feed-card"><div class="feed-icon">${icon('shield')}</div><h2>${esc(list.name)}</h2><p>${list.preset?'A community feed, automatically refreshed every day.':'Your imported domains. Re-import the same name to replace this list.'}</p><div class="feed-meta"><span><b>${num(list.count)}</b> domains</span><span>${date(list.updated_at)}</span></div>${list.error?`<p class="error-text">${esc(list.error)}</p>`:''}<div class="actions">${list.preset?button('refresh-list','Refresh','refresh','',`data-id="${list.id}"`):''}${button('delete-list','Remove','trash','danger',`data-id="${list.id}"`)}</div></section>`).join('')}
    ${[['hagezi-light','HaGeZi Light','A gentle starting point. Ads, tracking, and threats, with a focus on keeping everyday sites working.'],['hagezi-normal','HaGeZi Normal','Broader coverage for ads, trackers, and malicious destinations. Some sites may need an allow rule.']].filter(([preset])=>!lists.some(l=>l.preset===preset)).map(([preset,name,desc])=>`<section class="panel feed-card"><div class="feed-icon">${icon('globe')}</div><h2>${name}</h2><p>${desc}</p><div class="feed-meta"><span>Community maintained</span><a href="https://github.com/hagezi/dns-blocklists" target="_blank" rel="noreferrer">About this list ↗</a></div>${button('install-feed','Add protection','plus','primary',`data-preset="${preset}"`)}</section>`).join('')}</div>`;
  },
  async clients() {
    const clients = await api('/clients');
    return head('Who’s on your network?','Clients seen by this resolver in the last 24 hours.',button('reload','Refresh','refresh'))
    + `<div class="notice">Clients are identified by source IP. A router that proxies DNS may appear as a single client. All clients use the same policy in this release.</div><section class="panel">${clients.length?`<div class="table-wrap"><table><thead><tr><th>Client IP</th><th>Total queries</th><th>Blocked</th><th>Last seen</th></tr></thead><tbody>${clients.map(c=>`<tr><td class="mono">${esc(c.ip)}</td><td>${num(c.total)}</td><td>${num(c.blocked)}</td><td>${date(c.last_seen)}</td></tr>`).join('')}</tbody></table></div>`:empty('No clients yet. Configure your device’s DNS to start.','devices')}</section>`;
  },
  async endpoints() {
    endpointData = await api('/endpoints');
    return renderEndpoints(endpointData);
  },
  async browser() {
    browserData = await api('/browser');
    return renderBrowser(browserData);
  },
  async settings() {
    const [s,audit] = await Promise.all([api('/settings'),api('/audit')]), c=s.config;
    const row=(a,b)=>`<div class="detail-row"><span>${a}</span><b>${esc(b)}</b></div>`;
    return head('Under the hood.','Simple defaults. Explicit configuration. No surprises.',button('logout','Sign out','logout'))
    + `<div class="detail-grid"><section class="panel"><div class="panel-head"><h2>Resolver</h2>${badge('neutral',`v${s.version}`)}</div><div class="panel-body">
    ${row('DNS · UDP & TCP',c.dns_bind)}${row('Console listener',c.http_bind)}${row('Public origin',c.public_origin)}${row('Cache capacity',`${num(c.cache_entries)} responses`)}${row('Query logging',c.query_log?'Enabled':'Disabled')}${row('History retention',`${c.retention_days} days / ${num(c.max_log_entries)} entries`)}${row('Allowed clients',c.allowed_clients.join(', '))}
    <p class="small">Change these values in your TOML configuration and restart the service. Generate a template with <code>wtp config</code>.</p></div></section>
    <section class="panel"><div class="panel-head"><h2>Encrypted upstreams</h2>${icon('shield')}</div><div class="panel-body">${c.upstreams.map((u,i)=>`<div class="detail-row"><span>${i===0?'Primary':'Fallback'}</span><b>${esc(u.url)}<br><small>${esc(u.bootstrap)}</small></b></div>`).join('')}<p class="small">DNS over HTTPS with certificate verification and explicit bootstrap IPs. An upstream failure returns SERVFAIL. Plaintext fallback is never used.</p><hr><h3>Administrator account</h3><p class="small">Changing your password signs out every active session.</p>${button('password','Change password','shield')}</div></section></div>
    <section class="panel"><div class="panel-head"><h2>Administrator activity</h2><small>Latest 100 events</small></div>${audit.length?`<div class="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Event</th><th>Detail</th></tr></thead><tbody>${audit.map(a=>`<tr><td class="small">${date(a.at)}</td><td>${esc(a.actor)}</td><td class="mono">${esc(a.event)}</td><td>${esc(a.detail)}</td></tr>`).join('')}</tbody></table></div>`:empty('No administrative events yet.')}</section>`;
  }
};
function rulesTable(rules) {
  return rules.length?`<div class="table-wrap"><table><thead><tr><th>Domain + subdomains</th><th>Action</th><th>Note</th><th>Created</th><th>Manage</th></tr></thead><tbody>${rules.map(r=>`<tr><td class="domain">${esc(r.domain)}</td><td>${badge(r.action==='block'?'blocked':'allowed',r.action)}</td><td>${esc(r.note)}</td><td class="small">${date(r.created_at)}</td><td><div class="actions">${button('edit-rule','Edit',null,'text-button',`data-id="${r.id}"`)}${button('delete-rule','','trash','icon-btn danger',`data-id="${r.id}" aria-label="Delete rule for ${esc(r.domain)}"`)}</div></td></tr>`).join('')}</tbody></table></div>`:empty('No matching rules. Add one to make your point.');
}
function openModal(title,content) {
  modal.innerHTML=`<div class="modal-head"><h2 id="modal-title">${title}</h2>${button('close-modal','','close','icon-btn','aria-label="Close dialog"')}</div>${content}`;
  if (!modal.open) modal.showModal();
  modal.querySelector('input:not([type=hidden]),textarea,select')?.focus();
}
function ruleModal(rule={}) {
  openModal(rule.id?'Edit your rule':'Make a rule.',`<form id="rule-form" class="form-stack"><div class="row"><label>Domain<input name="domain" value="${esc(rule.domain || '')}" placeholder="example.com" required maxlength="253" ${rule.id?'readonly':''}></label><label>Action<select name="action"><option value="block" ${rule.action==='block'?'selected':''}>Block</option><option value="allow" ${rule.action==='allow'?'selected':''}>Allow</option></select></label></div><label>Note <small>Optional. A little context helps future you.</small><input name="note" value="${esc(rule.note || '')}" maxlength="256" placeholder="Why this rule exists"></label><small>Includes all subdomains. Allow rules override blocks, including blocks on more specific subdomains.</small><div class="form-error error-text" role="alert"></div><div class="modal-actions">${button('close-modal','Cancel')}<button class="primary" type="submit">Save rule</button></div></form>`);
}
async function confirmAction(title, message, action, after) {
  openModal(title, `<p>${esc(message)}</p><div class="modal-actions">${button('close-modal','Cancel')}<button type="button" id="confirm-action" class="primary">Confirm</button></div>`);
  document.querySelector('#confirm-action').addEventListener('click', async event=>{
    event.target.disabled=true;
    try { const result=await action(); modal.close(); await navigate(currentView); if(after) after(result); } catch(error) { toast(error.message,true); event.target.disabled=false; }
  });
}
document.addEventListener('click', async event=>{
  const nav=event.target.closest('[data-view]');
  if(nav){ await navigate(nav.dataset.view); return; }
  const el=event.target.closest('[data-action]');
  if(!el) return;
  const action=el.dataset.action;
  try {
    switch(action) {
      case 'endpoint-enroll': endpointModal(); break;
      case 'endpoint-edit': endpointModal(el.dataset.id); break;
      case 'endpoint-export': downloadEndpoint(); break;
      case 'endpoint-quarantine': {
        const endpoint=endpointData.devices.find(d=>d.id===el.dataset.id);
        await confirmAction(endpoint.quarantined?'Restore approved connections?':'Quarantine this endpoint?', endpoint.quarantined?'The agent will restore the approved network policy at its next refresh.':'Only its management connection, loopback, and configured address discovery will remain available.',()=>api(`/endpoints/${endpoint.id}`,'POST',{revision:endpoint.revision,network:JSON.parse(endpoint.network),quarantined:!endpoint.quarantined}));
        break;
      }
      case 'browser-enroll': browserProfileModal(el.dataset.id); break;
      case 'browser-rotate': await confirmAction('Replace this profile token?', 'This reactivates the profile and invalidates its previous token. Copy the replacement into the enrolled browser.', async()=>{return await api(`/browser/profiles/${el.dataset.id}/rotate`,'POST');},showEnrollment); break;
      case 'browser-rule': browserRuleModal(el.dataset.id); break;
      case 'browser-category': browserCategoryModal(el.dataset.id); break;
      case 'browser-preview': browserPreviewModal(); break;
      case 'browser-revoke': await confirmAction('Revoke this browser profile?', 'Its credential will stop authorizing browser requests.', ()=>api(`/browser/profiles/${el.dataset.id}/revoke`,'POST')); break;
      case 'browser-delete-rule': await saveBrowserPolicy({...browserData.policy,rules:browserData.policy.rules.filter(r=>r.id!==el.dataset.id)}); break;
      case 'browser-delete-category': await saveBrowserPolicy({...browserData.policy,categories:browserData.policy.categories.filter(c=>c.id!==el.dataset.id)}); break;
      case 'close-modal': modal.close(); break;
      case 'reload': await navigate(currentView); break;
      case 'logout': await api('/logout','POST'); session=null; showLogin(); break;
      case 'go-lists': await navigate('lists'); break;
      case 'go-queries': queryFilter.before=''; await navigate('queries'); break;
      case 'add-rule': ruleModal(); break;
      case 'edit-rule': ruleModal(loadedRules.find(r=>r.id===Number(el.dataset.id))); break;
      case 'quick-rule': ruleModal({domain:el.dataset.domain,action:el.dataset.ruleAction}); break;
      case 'delete-rule': await confirmAction('Remove this rule?','The domain will return to the remaining policy and blocklists.',()=>api(`/rules/${el.dataset.id}`,'DELETE')); break;
      case 'delete-list': await confirmAction('Remove this blocklist?','Its domains will stop contributing to your policy.',()=>api(`/lists/${el.dataset.id}`,'DELETE')); break;
      case 'clear-log': await confirmAction('Clear query history?','This permanently removes stored DNS queries and resets the dashboard totals. New queries will continue to be logged.',()=>api('/queries','DELETE')); break;
      case 'older-queries': queryFilter.before=String(queryRows.at(-1).id); await navigate('queries'); break;
      case 'newest-queries': queryFilter.before=''; await navigate('queries'); break;
      case 'install-feed':
      case 'refresh-list': {
        el.disabled=true; el.textContent='Downloading…';
        const result=action==='install-feed'?await api('/lists/preset','POST',{preset:el.dataset.preset}):await api(`/lists/${el.dataset.id}/refresh`,'POST');
        toast(result.count?`${num(result.count)} domains added. That’s the point.`:'Blocklist refreshed.');
        await navigate('lists');
        break;
      }
      case 'import-list':
        openModal('Bring your own blocklist.',`<form id="import-form" class="form-stack"><label>List name<input name="name" required maxlength="80" placeholder="My blocklist"></label><label>Domains or hosts file<textarea name="contents" required placeholder="ads.example.com&#10;0.0.0.0 tracker.example.com"></textarea></label><small>One domain per line or hosts format. Reusing a list name replaces that list atomically. Maximum 16 MiB; adblock syntax is not supported.</small><div class="form-error error-text" role="alert"></div><div class="modal-actions">${button('close-modal','Cancel')}<button class="primary" type="submit">Import list</button></div></form>`); break;
      case 'test':
        openModal('What would happen?',`<p>Check your current local policy without sending a DNS query. Upstream blocks and aliases are evaluated during actual resolution.</p><form id="test-form" class="form-stack"><label>Domain<input name="domain" required placeholder="blocked.test" maxlength="253"></label><div class="form-error error-text" role="alert"></div><button class="primary" type="submit">Test policy ${icon('arrow')}</button></form><div id="test-result" aria-live="polite"></div>`); break;
      case 'password':
        openModal('Change your password.',`<form id="password-form" class="form-stack"><label>Current password<input name="current" type="password" required autocomplete="current-password"></label><label>New password<input name="password" type="password" required minlength="12" maxlength="1024" autocomplete="new-password"></label><label>Confirm new password<input name="confirm" type="password" required minlength="12" autocomplete="new-password"></label><small>At least 12 characters. All sessions will be signed out.</small><div class="form-error error-text" role="alert"></div><button class="primary" type="submit">Change password</button></form>`); break;
    }
  } catch(error) {
    toast(error.message,true);
    if(action==='install-feed'||action==='refresh-list') await navigate('lists');
  }
});
document.addEventListener('input',event=>{
  if(event.target.id==='rule-search') {
    const search=event.target.value.toLowerCase();
    document.querySelector('#rules-table').innerHTML=rulesTable(loadedRules.filter(r=>`${r.domain} ${r.note}`.toLowerCase().includes(search)));
  }
});
document.addEventListener('submit',async event=>{
  event.preventDefault();
  const form=event.target, data=Object.fromEntries(new FormData(form)), submit=form.querySelector('[type="submit"]');
  const errorEl=form.querySelector('.form-error') || document.querySelector('#login-error');
  if(errorEl) errorEl.textContent='';
  submit.disabled=true;
  try {
    switch(form.getAttribute('id')) {
      case 'endpoint-form': await saveEndpoint(data); break;
      case 'browser-profile-form': await enrollBrowser(data); break;
      case 'browser-rule-form': await saveBrowserRule(data); break;
      case 'browser-category-form': await saveBrowserCategory(data); break;
      case 'browser-default-form': await saveBrowserPolicy({...browserData.policy,default_action:data.default_action}); break;
      case 'browser-preview-form': { const result=await api('/browser/preview','POST',{profile_id:Number(data.profile_id),url:data.url,text:data.text}); document.querySelector('#browser-preview-result').textContent=JSON.stringify(result.verdict,null,2); break; }
      case 'login-form':
        session=await api('/login','POST',data);
        shell(); await navigate(views[location.hash.slice(1)]?location.hash.slice(1):'overview'); break;
      case 'query-filter':
        queryFilter={search:data.search,decision:data.decision,before:''}; await navigate('queries'); break;
      case 'rule-form':
        await api('/rules','POST',data); modal.close(); toast('Rule saved. Policy updated immediately.'); await navigate(currentView); break;
      case 'import-form': {
        const result=await api('/lists','POST',data); modal.close(); toast(`${num(result.count)} domains imported.`); await navigate('lists'); break;
      }
      case 'test-form': {
        const result=await api('/test','POST',data);
        document.querySelector('#test-result').innerHTML=`<div class="test-result">${badge(result.blocked?'blocked':'allowed')}<p>${esc(result.reason)}${result.matched?` · matched <code>${esc(result.matched)}</code>`:''}</p></div>`; break;
      }
      case 'password-form':
        if(data.password!==data.confirm) throw new Error('The new passwords do not match.');
        await api('/password','POST',{current:data.current,password:data.password}); modal.close(); session=null; showLogin(); toast('Password changed. Sign in again.'); break;
    }
  } catch(error) { if(errorEl) errorEl.textContent=error.message; else toast(error.message,true); }
  finally { submit.disabled=false; }
});
window.addEventListener('hashchange',()=>{ if(session) navigate(location.hash.slice(1)); });
setInterval(()=>{ if(session && currentView==='overview' && !modal.open && !document.hidden) navigate('overview',true); },10000);
(async()=>{
  try { session=await api('/me'); shell(); await navigate(views[location.hash.slice(1)]?location.hash.slice(1):'overview'); }
  catch { showLogin(); }
})();

function renderBrowser({policy,profiles,events}) {
  const actions=[['allow','Allow'],['block','Block'],['sanitize','Sanitized reader']];
  return head('Protection follows the desktop profile.','Check destinations, categorize pages, and apply rules from the top down.',button('browser-preview','Test a page','terminal')+button('browser-enroll','Enroll a profile','plus','primary'))
  + `<div class="notice">DNS blocks apply first. Browser rules run in organization → group → profile order, then by ascending priority and rule ID. The first match wins. An unavailable portal pauses navigation.</div>`
  + `<section class="panel"><div class="panel-head"><div><h2>Browser rules</h2><p>Revision ${policy.revision} · paths include their descendants; category evidence can block or sanitize.</p></div>${button('browser-rule','Add browser rule','plus')}</div>
  <div class="table-wrap"><table><thead><tr><th>Scope</th><th>Priority</th><th>Match</th><th>Action</th><th>Manage</th></tr></thead><tbody>${policy.rules.map(r=>`<tr><td>${esc(r.scope)} ${esc(r.target)}</td><td>${r.priority}</td><td>${esc(r.kind)} <span class="mono">${esc(r.pattern || 'Every page')}</span>${r.enabled?'':' · disabled'}</td><td>${esc(r.action)}</td><td class="browser-actions">${button('browser-rule','Edit',null,'text-button',`data-id="${esc(r.id)}"`)}${button('browser-delete-rule','Remove',null,'text-button',`data-id="${esc(r.id)}"`)}</td></tr>`).join('') || '<tr><td colspan="5">No browser rules yet. DNS protection and the default below still apply.</td></tr>'}</tbody></table></div>
  <form id="browser-default-form" class="filters"><label>When no rule matches <select name="default_action">${actions.map(([a,n])=>`<option value="${a}" ${policy.default_action===a?'selected':''}>${n}</option>`).join('')}</select></label><button type="submit">Save default</button><span class="form-error error-text" role="alert"></span></form></section>
  <section class="panel"><div class="panel-head"><div><h2>Page categories</h2><p>Explainable domain and phrase matching. Add a category rule above to enforce it.</p></div>${button('browser-category','Add category','plus')}</div><div class="table-wrap"><table><thead><tr><th>Category</th><th>Domains</th><th>Distinct phrase threshold</th><th>Manage</th></tr></thead><tbody>${policy.categories.map(c=>`<tr><td>${esc(c.name)}<br><small>${esc(c.id)}</small></td><td>${esc(c.domains.join(', ') || 'None')}</td><td>${c.terms.length?`${c.threshold} of ${c.terms.length}`:'Domain only'}${c.id==='unclassified'?' · no evidence':''}</td><td class="browser-actions">${button('browser-category','Edit',null,'text-button',`data-id="${esc(c.id)}"`)}${button('browser-delete-category','Remove',null,'text-button',`data-id="${esc(c.id)}"`)}</td></tr>`).join('')}</tbody></table></div></section>
  <section class="panel"><div class="panel-head"><div><h2>Enrolled desktop profiles</h2><p>Use a separate credential for each OS account. Native identity uses a Unix UID or Windows SID.</p></div></div><div class="table-wrap"><table><thead><tr><th>Profile</th><th>Group</th><th>Desktop identity</th><th>Last seen</th><th>Status</th></tr></thead><tbody>${profiles.map(p=>`<tr><td>${esc(p.name)}<br><small>Profile ${p.id}</small></td><td>${esc(p.group_name || 'No group')}</td><td>${p.require_native?`${esc(p.os)} · ${esc(p.account_id)}`:'Token enrollment'}</td><td>${date(p.last_seen)}</td><td class="browser-actions">${button('browser-enroll','Edit',null,'text-button',`data-id="${p.id}"`)}${button('browser-rotate','New token',null,'text-button',`data-id="${p.id}"`)}${p.revoked?'Revoked':button('browser-revoke','Revoke',null,'text-button danger',`data-id="${p.id}"`)}</td></tr>`).join('') || '<tr><td colspan="5">Enroll a profile, then load the extension and enter its token.</td></tr>'}</tbody></table></div></section>
  <section class="panel"><div class="panel-head"><div><h2>Browser decisions</h2><p>Latest 100 checks · URL query strings and page text are not stored in this history.</p></div>${button('reload','Refresh','refresh')}</div><div class="table-wrap"><table><thead><tr><th>Time / profile</th><th>Destination</th><th>Decision</th><th>Evidence</th></tr></thead><tbody>${events.map(([at,name,url,action,reason,categories])=>`<tr><td>${date(at)}<br>${esc(name)}</td><td class="domain" title="${esc(url)}">${esc(url)}</td><td>${esc(action)}</td><td>${esc(reason)}<br><small>${esc(categories)}</small></td></tr>`).join('') || '<tr><td colspan="4">Browser checks will appear here after enrollment.</td></tr>'}</tbody></table></div></section>`;
}
function browserProfileModal(id) {
  const p=browserData.profiles.find(p=>p.id===Number(id)) || {name:'',group_name:'',os:'',account_id:'',require_native:false};
  openModal(id?'Edit desktop profile':'Enroll a desktop profile',`<form id="browser-profile-form" class="form-stack"><input type="hidden" name="id" value="${id || ''}"><label>Profile name<input name="name" required maxlength="80" value="${esc(p.name)}" placeholder="Alex · work laptop"></label><label>Policy group<input name="group_name" maxlength="80" value="${esc(p.group_name)}" placeholder="Students"></label><div class="row"><label>Operating system<select name="os">${[['','Not bound'],['linux','Linux'],['windows','Windows'],['macos','macOS']].map(([v,n])=>`<option value="${v}" ${p.os===v?'selected':''}>${n}</option>`).join('')}</select></label><label>OS account ID<input name="account_id" maxlength="256" value="${esc(p.account_id)}" placeholder="UID or Windows SID"></label></div><label>Identity requirement<select name="require_native"><option value="false" ${p.require_native?'':'selected'}>Profile token</option><option value="true" ${p.require_native?'selected':''}>Native desktop identity required</option></select></label><p class="small">Run <code>wtp-native --identity</code> on the desktop to find its account ID. Native identity is a local account report, not hardware attestation.</p><div class="form-error error-text" role="alert"></div><button class="primary" type="submit">${id?'Save profile':'Create profile token'}</button></form>`);
}
function showEnrollment(result) {
  openModal('Profile enrolled',`<p>Copy this token into the extension on this desktop account. It is displayed only once.</p><label>Portal<input readonly value="${esc(result.portal)}"></label><label>Profile token<input readonly value="${esc(result.token)}" aria-label="New profile token"></label><p>Profile ID: ${result.id}. Load the repository’s <code>extension/</code> folder in Chrome, Edge, or Chromium, then open its settings.</p>${button('close-modal','Done')}`);
}
async function enrollBrowser(data) {
  const {id,...profile}=data;
  const result=await api(id?`/browser/profiles/${id}`:'/browser/profiles','POST',{...profile,require_native:data.require_native==='true'});
  if(id) {modal.close();toast('Desktop profile updated.');} else showEnrollment(result);
  await navigate('browser');
}
function browserRuleModal(id) {
  const r=browserData.policy.rules.find(r=>r.id===id) || {id:'rule-'+crypto.randomUUID().slice(0,8),scope:'global',target:'',priority:100,kind:'domain',pattern:'',action:'block',enabled:true};
  const select=(name,items,current)=>`<select name="${name}">${items.map(([v,l])=>`<option value="${v}" ${v===current?'selected':''}>${l}</option>`).join('')}</select>`;
  openModal(id?'Edit browser rule':'Add browser rule',`<form id="browser-rule-form" class="form-stack"><input type="hidden" name="id" value="${esc(r.id)}"><div class="row"><label>Scope${select('scope',[['global','Organization'],['group','Group'],['profile','Desktop profile']],r.scope)}</label><label>Group name or profile ID<input name="target" value="${esc(r.target)}" maxlength="80" placeholder="Leave empty for organization"></label></div><div class="row"><label>Priority<input type="number" name="priority" value="${r.priority}" min="0" max="100000" required></label><label>Match${select('kind',[['domain','Domain + subdomains'],['path','URL path + descendants'],['category','Page category'],['all','Every page']],r.kind)}</label></div><label>Pattern<input name="pattern" value="${esc(r.pattern)}" maxlength="4096" placeholder="example.com, https://example.com/path, or category ID"></label><small>Category IDs: ${browserData.policy.categories.map(c=>esc(c.id)).join(', ')}. Leave the pattern empty for every page.</small><div class="row"><label>Action${select('action',[['block','Block'],['allow','Allow'],['sanitize','Sanitized reader']],r.action)}</label><label>Status${select('enabled',[['true','Enabled'],['false','Disabled']],String(r.enabled))}</label></div><div class="form-error error-text" role="alert"></div><button class="primary" type="submit">Save browser rule</button></form>`);
}
async function saveBrowserRule(data) {
  const rule={...data,priority:Number(data.priority),enabled:data.enabled==='true'};
  await saveBrowserPolicy({...browserData.policy,rules:[...browserData.policy.rules.filter(r=>r.id!==rule.id),rule]});
}
function browserCategoryModal(id) {
  const c=browserData.policy.categories.find(c=>c.id===id) || {id:'',name:'',domains:[],terms:[],threshold:1};
  openModal(id?'Edit category':'Add category',`<form id="browser-category-form" class="form-stack"><div class="row"><label>Category ID<input name="id" value="${esc(c.id)}" required maxlength="64" pattern="[A-Za-z0-9_-]+" ${id?'readonly':''}></label><label>Name<input name="name" value="${esc(c.name)}" required maxlength="80"></label></div><label>Domains <small>One per line; includes subdomains</small><textarea name="domains" rows="3">${esc(c.domains.join('\n'))}</textarea></label><label>Content phrases <small>One per line; whole words, case insensitive</small><textarea name="terms" rows="4">${esc(c.terms.join('\n'))}</textarea></label><label>Distinct phrases required<input type="number" name="threshold" value="${c.threshold}" min="1" max="50" required></label><div class="form-error error-text" role="alert"></div><button class="primary" type="submit">Save category</button></form>`);
}
async function saveBrowserCategory(data) {
  const lines=value=>value.split('\n').map(s=>s.trim()).filter(Boolean);
  const category={id:data.id,name:data.name,domains:lines(data.domains),terms:lines(data.terms),threshold:Number(data.threshold)};
  await saveBrowserPolicy({...browserData.policy,categories:[...browserData.policy.categories.filter(c=>c.id!==category.id),category]});
}
async function saveBrowserPolicy(policy) {
  await api('/browser/policy','POST',policy);modal.close();toast('Browser policy saved. New checks use this revision.');await navigate('browser');
}
function browserPreviewModal() {
  openModal('Test a page for a desktop profile',`<form id="browser-preview-form" class="form-stack"><label>Desktop profile<select name="profile_id" required>${browserData.profiles.filter(p=>!p.revoked).map(p=>`<option value="${p.id}">${esc(p.name)}</option>`).join('')}</select></label><label>URL<input name="url" type="url" required placeholder="https://example.com/path"></label><label>Sample page text<textarea name="text" rows="4" maxlength="32000" placeholder="Optional text to test inferred categories"></textarea></label><small>This preview assumes the enrolled OS identity matches. It does not visit the destination.</small><div class="form-error error-text" role="alert"></div><button class="primary" type="submit">Evaluate page</button><pre id="browser-preview-result" class="browser-verdict"></pre></form>`);
}

function renderEndpoints({devices,public_key}) {
  return head('Control the whole desktop.', 'Publish signed network policies to privileged endpoint agents.', button('reload','Refresh','refresh')+button('endpoint-enroll','Enroll an endpoint','plus','primary'))
  + `<div class="notice">Endpoint rules allow only approved IP addresses, ports, and physical interfaces. Add your management server and an approved web gateway before activation. Browser profiles control page access separately. An expired policy puts the endpoint into management-only quarantine.</div>
  <section class="panel"><div class="panel-head"><div><h2>Managed endpoints</h2><p>Status is reported by each agent. A recent report is not hardware attestation.</p></div></div><div class="table-wrap"><table><thead><tr><th>Endpoint</th><th>Published policy</th><th>Agent report</th><th>Last seen</th><th>Manage</th></tr></thead><tbody>${devices.map(d=>`<tr><td>${esc(d.name)}<br><small>${esc(d.platform)} · ${esc(d.control)}</small></td><td>Revision ${d.revision}<br>${d.quarantined?'Quarantine':'Approved connections'}</td><td>${!d.last_seen?'Not enrolled':Date.now()/1000-d.last_seen>90?'Offline / stale':esc(d.reported_state)}<br><small>Reported revision ${d.reported_revision} · ${esc(d.detail)}</small></td><td>${date(d.last_seen)}</td><td class="browser-actions">${button('endpoint-edit','Edit policy',null,'text-button',`data-id="${d.id}"`)}${button('endpoint-quarantine',d.quarantined?'Restore':'Quarantine',null,'text-button',`data-id="${d.id}"`)}</td></tr>`).join('') || '<tr><td colspan="5">No endpoints enrolled. Create a policy and install its agent with administrator access.</td></tr>'}</tbody></table></div></section>
  <section class="panel"><div class="panel-head"><div><h2>Policy verification key</h2><p>The enrollment file pins this portal’s Ed25519 public key.</p><code class="endpoint-key">${esc(public_key)}</code></div></div></section>`;
}
function endpointModal(id) {
  const d=endpointData.devices.find(d=>d.id===id);
  const n=d?JSON.parse(d.network):{interfaces:[],dns_servers:[],allowed_tcp:[],allowed_udp:[],dhcp:true};
  openModal(d?'Edit endpoint policy':'Enroll an endpoint',`<form id="endpoint-form" class="form-stack"><input type="hidden" name="id" value="${id || ''}"><input type="hidden" name="revision" value="${d?.revision || 0}">
  ${d?`<p>Publishing a revision for ${esc(d.name)}. Changes arrive at the next agent refresh.</p>`:`<label>Endpoint name<input name="name" required maxlength="80" placeholder="Alex · managed laptop"></label><label>Operating system<select name="platform"><option value="linux">Linux</option><option value="windows">Windows</option><option value="macos">macOS</option></select></label><label>Management server IP:port<input name="control" required placeholder="192.0.2.10:443"></label>`}
  <label>Approved physical interfaces <small>One per line; fixed at enrollment</small><textarea name="interfaces" rows="2" required ${d?'readonly':''} placeholder="eth0, Ethernet, or en0 — one actual interface per line">${esc(n.interfaces.join('\n'))}</textarea></label>
  <label>Approved DNS server IPs <small>One per line</small><textarea name="dns_servers" rows="2">${esc(n.dns_servers.join('\n'))}</textarea></label>
  <label>Approved TCP destinations <small>One IP:port per line; IPv6 uses [address]:port</small><textarea name="allowed_tcp" rows="4" placeholder="192.0.2.20:443">${esc(n.allowed_tcp.join('\n'))}</textarea></label>
  <label>Approved UDP destinations <small>DNS uses the resolver list above</small><textarea name="allowed_udp" rows="2">${esc(n.allowed_udp.join('\n'))}</textarea></label>
  <label>Address configuration<select name="dhcp"><option value="true" ${n.dhcp?'selected':''}>Allow DHCP</option><option value="false" ${n.dhcp?'':'selected'}>Static address only</option></select></label>
  <p class="small">The management destination is always retained. All other connections are blocked. Use a console or recovery channel for first activation.</p><div class="form-error error-text" role="alert"></div><button class="primary" type="submit">${d?'Publish policy':'Create enrollment file'}</button></form>`);
}
async function saveEndpoint(data) {
  const lines=value=>value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
  const d=endpointData.devices.find(d=>d.id===data.id);
  const network={interfaces:lines(data.interfaces),dns_servers:lines(data.dns_servers),allowed_tcp:lines(data.allowed_tcp),allowed_udp:lines(data.allowed_udp),dhcp:data.dhcp==='true'};
  const control=d?.control || data.control.trim();
  if(!network.allowed_tcp.includes(control)) network.allowed_tcp.push(control);
  if(d) {
    await api(`/endpoints/${d.id}`,'POST',{revision:Number(data.revision),network,quarantined:d.quarantined});
    modal.close();await navigate('endpoints');toast('Signed policy published. Check the agent’s reported revision.');
  } else {
    const result=await api('/endpoints','POST',{name:data.name,platform:data.platform,control,network});
    endpointEnrollment=result.config;
    modal.close();await navigate('endpoints');
    openModal('Save endpoint enrollment',`<p>Download this file once and transfer it securely to the endpoint administrator. It contains a private device credential and the pinned policy key.</p><p>Install the matching agent with the instructions in <code>docs/endpoint-enforcement.md</code>. Installation requires administrator access and changes the device firewall.</p>${button('endpoint-export','Download enrollment JSON','devices','primary')}`);
  }
}
function downloadEndpoint() {
  if(!endpointEnrollment) return;
  const url=URL.createObjectURL(new Blob([JSON.stringify(endpointEnrollment,null,2)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='endpoint-config.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  endpointEnrollment=null;modal.close();
}
