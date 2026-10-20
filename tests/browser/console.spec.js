const {test,expect}=require('@playwright/test');
const dgram=require('node:dgram');

async function blockedQuery(domain) {
  const socket=dgram.createSocket('udp4');
  const labels=domain.split('.').flatMap(label=>[Buffer.from([label.length]),Buffer.from(label)]);
  const packet=Buffer.concat([Buffer.from('123401000001000000000000','hex'),...labels,Buffer.from('0000010001','hex')]);
  try {
    await new Promise((resolve,reject)=>{
      const timeout=setTimeout(()=>reject(new Error('DNS fixture timed out')),3000);
      socket.once('message',()=>{clearTimeout(timeout);resolve();});
      socket.once('error',error=>{clearTimeout(timeout);reject(error);});
      socket.send(packet,15354,'127.0.0.1');
    });
  } finally {socket.close();}
}

test('login, real policy changes, imports, diagnostics, and mobile navigation',async({page})=>{
  const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/');
  await page.getByLabel('Username',{exact:true}).fill('admin');
  await page.getByLabel('Password',{exact:true}).fill('browser-test-password');
  await page.getByRole('button',{name:'Sign in to your console'}).click();
  await expect(page.getByRole('heading',{name:'A clearer view of your network.'})).toBeVisible();
  for(const domain of ['blocked.test','ads.blocked.test','metrics.blocked.test','blocked.test']) await blockedQuery(domain);
  await expect.poll(async()=>page.evaluate(async()=>{const response=await fetch('/api/stats');return (await response.json()).total;})).toBe(4);
  await page.getByRole('button',{name:'Overview',exact:true}).click();
  await expect(page.getByRole('cell',{name:'metrics.blocked.test',exact:true})).toBeVisible();
  await page.screenshot({path:'artifacts/console-desktop.png',fullPage:true});
  await page.getByRole('button',{name:'Your rules',exact:true}).click();
  await page.getByRole('button',{name:'Add a rule',exact:true}).click();
  await page.getByLabel('Domain',{exact:true}).fill('example.com');
  await page.getByRole('button',{name:'Save rule'}).click();
  await expect(page.getByRole('cell',{name:'example.com',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Test a domain'}).click();
  await page.getByLabel('Domain',{exact:true}).fill('sub.example.com');
  await page.getByRole('button',{name:'Test policy'}).click();
  await expect(page.locator('#test-result')).toContainText('blocked');
  await page.getByRole('button',{name:'Close dialog'}).click();
  await page.getByRole('button',{name:'Blocklists',exact:true}).click();
  await page.getByRole('button',{name:'Import a list',exact:true}).click();
  await page.getByLabel('List name').fill('Browser test');
  await page.getByLabel('Domains or hosts file').fill('track.example.net\nads.example.net');
  await page.getByRole('button',{name:'Import list',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Browser test'})).toBeVisible();
  await expect(page.getByText('2 domains',{exact:true})).toBeVisible();
  for(const name of ['Query log','Clients','Settings']) {
    await page.getByRole('button',{name,exact:true}).click();
    await expect(page.locator('#page')).not.toContainText('The operation failed');
  }
  await page.setViewportSize({width:390,height:844});
  await page.getByRole('button',{name:'Overview',exact:true}).click();
  await expect(page.getByRole('heading',{name:'A clearer view of your network.'})).toBeVisible();
  await page.screenshot({path:'artifacts/console-mobile.png',fullPage:true});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.setViewportSize({width:1440,height:1000});
  await page.getByRole('button',{name:'Sign out',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  expect(errors).toEqual([]);
});
