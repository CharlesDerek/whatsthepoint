const {test,expect}=require('@playwright/test');
const {spawn,spawnSync}=require('node:child_process');
const {mkdtempSync,writeFileSync,readFileSync,rmSync}=require('node:fs');
const {join,resolve}=require('node:path');
const {tmpdir}=require('node:os');

test('paired desktop uses the real hybrid TLS server, encrypted vault, shared UI and revocation',async({page,request})=>{
  test.setTimeout(90000);
  const dir=mkdtempSync(join(tmpdir(),'wtp-desktop-test-'));
  const bin=resolve('target/debug/wtp');
  const desktop=resolve('target/debug/wtp-desktop');
  const config=join(dir,'tls.toml'),bundle=join(dir,'invite.json'),vault=join(dir,'vault.json');
  const children=[];
  const run=(program,args,extra={})=>{
    const result=spawnSync(program,args,{encoding:'utf8',...extra});
    if(result.status!==0)throw new Error(result.stderr || result.stdout);
  };
  try {
    run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(dir,'key.pem'),'-out',join(dir,'cert.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE']);
    writeFileSync(config,`dns_bind = "127.0.0.1:15355"\nhttp_bind = "127.0.0.1:18443"\npublic_origin = "https://127.0.0.1:18443"\ntls_certificate = ${JSON.stringify(join(dir,'cert.pem'))}\ntls_private_key = ${JSON.stringify(join(dir,'key.pem'))}\n`);
    const args=['--data-dir',dir,'--config',config];
    run(bin,[...args,'init'],{env:{...process.env,WTP_ADMIN_PASSWORD:'desktop-test-password'}});
    run(bin,[...args,'pair-console','--name','Browser fixture','--output',bundle]);
    const server=spawn(bin,[...args,'serve'],{stdio:'pipe'});children.push(server);
    let serverLog='';server.stderr.on('data',b=>serverLog+=b);
    const invitation=JSON.parse(readFileSync(bundle,'utf8'));
    const local=spawn(desktop,['--vault',vault,'open','--no-open'],{stdio:'pipe'});children.push(local);
    let output='';local.stdout.on('data',b=>output+=b);
    await expect.poll(()=>output.match(/http:\/\/127\.0\.0\.1:\d+\/desktop#[a-f0-9]+/)?.[0],{timeout:15000}).toBeTruthy();
    const url=output.match(/http:\/\/127\.0\.0\.1:\d+\/desktop#[a-f0-9]+/)[0];
    const origin=new URL(url).origin;
    // A different local browser session cannot use the broker as an admin proxy.
    expect((await request.get(origin+'/api/me')).status()).toBe(401);
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(url);
    await expect(page.locator('#desktop-status')).toContainText('Pair your first');
    await page.getByLabel('Pairing invitation JSON').setInputFiles(bundle);
    await page.locator('#desktop-pair input[name=password]').fill('local-vault-test-passphrase');
    await page.getByRole('button',{name:'Pair and open console'}).click();
    await expect(page.getByRole('heading',{name:'A clearer view of your network.'})).toBeVisible({timeout:30000});
    expect(readFileSync(vault,'utf8')).not.toContain(invitation.secret);
    expect(readFileSync(vault,'utf8')).not.toContain('principal_id');
    await page.getByRole('button',{name:'Your rules',exact:true}).click();
    await page.getByRole('button',{name:'Add a rule',exact:true}).click();
    await page.getByLabel('Domain',{exact:true}).fill('desktop.blocked.test');
    await page.getByRole('button',{name:'Save rule'}).click();
    await expect(page.getByRole('cell',{name:'desktop.blocked.test',exact:true})).toBeVisible();
    await page.getByRole('button',{name:'Paired consoles',exact:true}).click();
    await expect(page.getByRole('cell',{name:'Browser fixture',exact:true})).toBeVisible();
    await page.screenshot({path:'artifacts/paired-desktop.png',fullPage:true});
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await expect(page.locator('#desktop-status')).toContainText('Unlock');
    await page.locator('#vault-unlock input').fill('wrong-vault-passphrase');
    await page.getByRole('button',{name:'Unlock saved connections'}).click();
    await expect(page.locator('#desktop-error')).toContainText('Could not unlock',{timeout:30000});
    await page.locator('#vault-unlock input').fill('local-vault-test-passphrase');
    await page.getByRole('button',{name:'Unlock saved connections'}).click();
    await page.getByRole('button',{name:'Open console',exact:true}).click();
    await expect(page.getByRole('heading',{name:'A clearer view of your network.'})).toBeVisible();
    await page.getByRole('button',{name:'Paired consoles',exact:true}).click();
    await page.getByRole('button',{name:'Revoke',exact:true}).click();
    await page.getByRole('button',{name:'Confirm',exact:true}).click();
    await expect.poll(()=>page.evaluate(async()=>(await fetch('/api/me')).status)).toBe(502);
    expect(errors).toEqual([]);
    expect(serverLog).not.toContain('panicked');
  } finally {
    for(const child of children)child.kill('SIGTERM');
    await Promise.all(children.map(child=>child.exitCode!==null?Promise.resolve():new Promise(resolve=>child.once('exit',resolve))));
    rmSync(dir,{recursive:true,force:true});
  }
});
