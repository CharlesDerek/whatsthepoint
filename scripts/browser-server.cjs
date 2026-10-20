// Disposable test database and credentials; never touches a user's configuration.
const {spawn, spawnSync} = require('node:child_process');
const {mkdtempSync, writeFileSync, rmSync} = require('node:fs');
const {tmpdir} = require('node:os');
const {join, resolve} = require('node:path');
const dir = mkdtempSync(join(tmpdir(), 'wtp-browser-'));
const config = join(dir,'test.toml');
writeFileSync(config, 'dns_bind = "127.0.0.1:15354"\nhttp_bind = "127.0.0.1:18080"\npublic_origin = "http://127.0.0.1:18080"\n');
const binary = resolve('target/debug/wtp' + (process.platform==='win32'?'.exe':''));
const build = spawnSync('cargo',['build','--locked'],{stdio:'inherit'});
if(build.status !== 0) process.exit(1);
const init = spawnSync(binary,['--data-dir',dir,'init'],{env:{...process.env,WTP_ADMIN_PASSWORD:'browser-test-password'},stdio:'inherit'});
if(init.status !== 0) process.exit(1);
const child=spawn(binary,['--data-dir',dir,'--config',config,'serve'],{stdio:'inherit'});
for(const signal of ['SIGINT','SIGTERM']) process.on(signal,()=>child.kill('SIGTERM'));
child.on('exit',code=>{rmSync(dir,{recursive:true,force:true});process.exit(code||0);});
