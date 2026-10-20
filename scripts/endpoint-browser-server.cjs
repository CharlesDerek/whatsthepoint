// Disposable TLS portal for endpoint enrollment tests. No host firewall changes.
const {spawn,spawnSync}=require('node:child_process');
const {mkdtempSync,writeFileSync,readFileSync,rmSync}=require('node:fs');
const {tmpdir}=require('node:os');const {join,resolve}=require('node:path');
const https=require('node:https'),http=require('node:http');
const dir=mkdtempSync(join(tmpdir(),'wtp-endpoint-ui-'));
const config=join(dir,'config.toml');
writeFileSync(config,'dns_bind = "127.0.0.1:15355"\nhttp_bind = "127.0.0.1:18081"\npublic_origin = "https://127.0.0.1:18443"\n');
const openssl=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(dir,'tls.key'),'-out',join(dir,'tls.crt'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});
if(openssl.status!==0) throw new Error('Test certificate generation failed');
const binary=resolve('target/debug/wtp');
if(spawnSync(binary,['--data-dir',dir,'init'],{env:{...process.env,WTP_ADMIN_PASSWORD:'endpoint-ui-test-password'},stdio:'ignore'}).status!==0)throw new Error('Test initialization failed');
const child=spawn(binary,['--data-dir',dir,'--config',config,'serve'],{stdio:'ignore'});
const server=https.createServer({key:readFileSync(join(dir,'tls.key')),cert:readFileSync(join(dir,'tls.crt'))},(req,res)=>{
  const upstream=http.request({hostname:'127.0.0.1',port:18081,path:req.url,method:req.method,headers:req.headers},response=>{res.writeHead(response.statusCode,response.headers);response.pipe(res);});
  upstream.on('error',()=>{res.writeHead(503);res.end();});req.pipe(upstream);
});
server.listen(18443,'127.0.0.1',()=>process.stdout.write('TLS fixture listening\n'));
const stop=()=>{server.close();child.kill('SIGTERM');};
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,stop);
child.on('exit',()=>{server.close();rmSync(dir,{recursive:true,force:true});process.exit(0);});
