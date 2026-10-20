const {test,expect,chromium}=require('@playwright/test');
const {mkdtempSync,rmSync,mkdirSync,writeFileSync}=require('node:fs');
const {tmpdir}=require('node:os');
const {join,resolve}=require('node:path');
const http=require('node:http');

test('real extension gates navigation, redirects, content, reader, profiles and revocation',async({request})=>{
  test.setTimeout(120000);
  const hits=new Map();
  const server=http.createServer((req,res)=>{
    hits.set(req.url,(hits.get(req.url)||0)+1);
    if(req.url==='/redirect') {res.writeHead(302,{Location:'/blocked/secret'});res.end();return;}
    res.setHeader('Content-Type','text/html');
    if(req.url.startsWith('/content')) res.end('<h1>Online casino</h1><p>Bet now</p>');
    else if(req.url==='/reader') res.end('<main><h1>A readable page</h1><p>Useful article text</p><script>fetch("/script-leaked")</script><img src="/image-leaked"><form action="/form-leaked"><input value="secret"></form><a href="/blocked/secret">A checked link</a><a href="javascript:alert(1)">Unsafe link</a></main>');
    else res.end('<h1>Allowed destination</h1><a href="/blocked/secret?utm_source=ad">Blocked click</a>');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin=`http://127.0.0.1:${server.address().port}`;
  const dir=mkdtempSync(join(tmpdir(),'wtp-extension-'));
  let context;
  try {
    const login=await request.post('/api/login',{headers:{'X-WTP-Request':'1'},data:{username:'admin',password:'browser-test-password'}});
    expect(login.ok()).toBe(true);
    const {csrf}=await login.json();
    const headers={'X-WTP-Request':'1','X-CSRF-Token':csrf};
    const enrollment=await (await request.post('/api/browser/profiles',{headers,data:{name:'Extension test',group_name:'Students',os:'',account_id:'',require_native:false}})).json();
    const initial=await (await request.get('/api/browser')).json();
    const rule=(id,path,action)=>({id,scope:'global',target:'',priority:10,kind:'path',pattern:origin+path,action,enabled:true});
    const policy={...initial.policy,rules:[rule('network-block','/blocked','block'),rule('reader','/reader','sanitize'),{id:'content-block',scope:'global',target:'',priority:1,kind:'category',pattern:'gambling',action:'block',enabled:true}]};
    const saved=await request.post('/api/browser/policy',{headers,data:policy});expect(saved.ok()).toBe(true);
    const extensionPath=resolve('extension');
    context=await chromium.launchPersistentContext(dir,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${extensionPath}`,`--load-extension=${extensionPath}`]});
    let worker=context.serviceWorkers()[0];
    if(!worker) worker=await context.waitForEvent('serviceworker');
    const extensionId=new URL(worker.url()).hostname;
    await worker.evaluate(async config=>{await chrome.storage.local.set(config);},{portal:'http://127.0.0.1:18080',token:enrollment.token,requireNative:false});
    // Wait for the network gate to be installed and inspect startup errors through its API.
    await expect.poll(()=>worker.evaluate(async()=> (await chrome.declarativeNetRequest.getDynamicRules()).length)).toBeGreaterThan(0);
    const page=await context.newPage();
    const navigate=async path=>{await page.goto(origin+path).catch(error=>{if(!/ERR_ABORTED/.test(error.message))throw error;});};
    await navigate('/blocked/secret');
    await expect(page.getByRole('heading',{name:'This page is blocked.'})).toBeVisible();
    expect(hits.get('/blocked/secret') || 0).toBe(0);
    await page.getByRole('button',{name:'Check again'}).click();
    await expect(page.getByRole('heading',{name:'This page is blocked.'})).toBeVisible();
    await navigate('/allowed?utm_source=ad');
    await expect(page.getByRole('heading',{name:'Allowed destination'})).toBeVisible();
    expect(page.url()).toBe(origin+'/allowed');
    expect(hits.get('/allowed?utm_source=ad') || 0).toBe(0);
    await page.getByRole('link',{name:'Blocked click'}).click();
    await expect(page.getByRole('heading',{name:'This page is blocked.'})).toBeVisible();
    expect(hits.get('/blocked/secret') || 0).toBe(0);
    await navigate('/redirect');
    await expect(page.getByRole('heading',{name:'This page is blocked.'})).toBeVisible();
    expect(hits.get('/redirect')).toBe(1);expect(hits.get('/blocked/secret') || 0).toBe(0);
    await navigate('/content');
    await expect(page.getByRole('heading',{name:'This page is blocked.'})).toBeVisible();
    await expect(page.locator('#evidence')).toContainText('gambling');
    const contentHits=hits.get('/content');
    await page.getByRole('button',{name:'Check again'}).click();
    await expect(page.getByRole('heading',{name:'This page is blocked.'})).toBeVisible();
    expect(hits.get('/content')).toBe(contentHits);
    await navigate('/reader');
    await expect(page.locator('#reader')).toContainText('Useful article text');
    await expect(page.locator('#reader script,#reader img,#reader form')).toHaveCount(0);
    await expect(page.getByRole('link',{name:'Unsafe link'})).toHaveCount(0);
    expect(hits.get('/script-leaked') || 0).toBe(0);expect(hits.get('/image-leaked') || 0).toBe(0);
    await page.screenshot({path:'artifacts/browser-reader.png',fullPage:true});
    // A committed navigation must not retain a permit for subsequent requests.
    await navigate('/allowed');
    await expect(page.getByRole('heading',{name:'Allowed destination'})).toBeVisible();
    const sessionRules=await worker.evaluate(()=>chrome.declarativeNetRequest.getSessionRules());
    expect(sessionRules).toEqual([]);
    // Register the actual helper only in this disposable browser profile.
    const nativeDir=join(dir,'NativeMessagingHosts');mkdirSync(nativeDir,{recursive:true});
    writeFileSync(join(nativeDir,'org.whatsthepoint.identity.json'),JSON.stringify({name:'org.whatsthepoint.identity',description:'Test identity',path:resolve('target/debug/wtp-native'+(process.platform==='win32'?'.exe':'')),type:'stdio',allowed_origins:[`chrome-extension://${extensionId}/`]}));
    const native=await worker.evaluate(()=>chrome.runtime.sendNativeMessage('org.whatsthepoint.identity',{type:'identity'}));
    expect(native.identity.account_id).toBeTruthy();
    const nativeProfile={name:'Native profile test',group_name:'Students',os:native.identity.os,account_id:native.identity.account_id,require_native:true};
    expect((await request.post(`/api/browser/profiles/${enrollment.id}`,{headers,data:nativeProfile})).ok()).toBe(true);
    await worker.evaluate(()=>chrome.storage.local.set({requireNative:true}));
    await navigate('/native-account');
    await expect(page.getByRole('heading',{name:'Allowed destination'})).toBeVisible();
    await request.post(`/api/browser/profiles/${enrollment.id}`,{headers,data:{...nativeProfile,account_id:'different-account'}});
    await navigate('/wrong-account');
    await expect(page.getByRole('heading',{name:'This page is blocked.'})).toBeVisible();
    expect(hits.get('/wrong-account') || 0).toBe(0);
    await worker.evaluate(()=>chrome.storage.local.set({portal:'http://127.0.0.1:1'}));
    await navigate('/portal-offline');
    await expect(page.getByRole('heading',{name:'Navigation paused.'})).toBeVisible();
    expect(hits.get('/portal-offline') || 0).toBe(0);
    await worker.evaluate(()=>chrome.storage.local.set({portal:'http://127.0.0.1:18080'}));
    await request.post(`/api/browser/profiles/${enrollment.id}/revoke`,{headers});
    await navigate('/new-after-revoke');
    await expect(page.getByRole('heading',{name:'Navigation paused.'})).toBeVisible();
    expect(hits.get('/new-after-revoke') || 0).toBe(0);
    expect(page.url()).toContain(`chrome-extension://${extensionId}/gate.html`);
  } finally {
    if(context) await context.close();
    await new Promise(resolve=>server.close(resolve));
    rmSync(dir,{recursive:true,force:true});
  }
});
