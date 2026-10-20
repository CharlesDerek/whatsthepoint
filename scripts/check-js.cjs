const {readdirSync}=require('node:fs');
const {spawnSync}=require('node:child_process');
for(const file of ['web/app.js',...readdirSync('extension').filter(f=>f.endsWith('.js')).map(f=>`extension/${f}`)]) {
  const result=spawnSync(process.execPath,['--check',file],{stdio:'inherit'});
  if(result.status!==0) process.exit(result.status || 1);
}
