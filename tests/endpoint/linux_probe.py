"""Runs ONLY inside the disposable NET_ADMIN container created by linux-integration.py."""
import json, os, pathlib, shutil, socket, subprocess, sys, time
root=pathlib.Path('/run/wtp-test');root.mkdir(mode=0o700)
shutil.copyfile('/source/wtp-agent','/usr/local/bin/wtp-agent');os.chmod('/usr/local/bin/wtp-agent',0o755)
agent='/usr/local/bin/wtp-agent'
def run(*args,input=None,ok=True):
    result=subprocess.run(args,input=input,text=True,capture_output=True)
    if ok and result.returncode:raise AssertionError(f'{args}: {result.stderr}')
    return result
peer4,peer6,other4,other6=sys.argv[1:]
def reachable(ip,port,udp=False):
    s=socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.settimeout(.35)
    try:
        if udp:s.sendto(b'probe',(ip,port));return s.recv(32)==b'probe'
        s.connect((ip,port));return s.recv(32)==b'ok'
    except OSError:return False
    finally:s.close()
for ip in [peer4,peer6,other4,other6]:assert reachable(ip,8080),f'Fixture unreachable: {ip}'
key=root/'signing.key';public=run(agent,'keygen','--output',str(key)).stdout.strip()
network={'dns_servers':[peer4,peer6],'allowed_tcp':[f'{peer4}:8443',f'{peer4}:8080',f'[{peer6}]:8080'],'allowed_udp':[],'interfaces':['eth0'],'dhcp':False}
config={'endpoint_id':'a'*32,'platform':'linux','portal':'https://portal.test:8443','control':f'{peer4}:8443','token':'b'*64,'public_key':public,'interfaces':['eth0'],'dhcp':False}
config_path=root/'config.json';config_path.write_text(json.dumps(config));config_path.chmod(0o600)
def signed(revision,ttl=300):
    p={'endpoint_id':config['endpoint_id'],'platform':'linux','revision':revision,'issued_at':int(time.time()),'expires_at':int(time.time())+ttl,'network':network}
    source=root/'source.json';source.write_text(json.dumps(p));out=root/f'policy-{revision}.json'
    run(agent,'sign-policy','--key',str(key),'--policy',str(source),'--output',str(out));return out
policy=signed(1)
run('nft','-f','-',input='table inet unrelated {\n chain output {\n type filter hook output priority 0; policy accept;\n }\n}\n')
plan=run(agent,'plan','--config',str(config_path),'--policy',str(policy)).stdout
run('nft','--check','-f','-',input=plan)
run(agent,'apply','--config',str(config_path),'--policy',str(policy),'--state-dir',str(root))
run('ip','-6','neigh','flush','all')
for ip in [peer4,peer6]:
    assert reachable(ip,8080),f'Approved TCP blocked: {ip}'
    assert reachable(ip,53,True),f'Approved UDP DNS blocked: {ip}'
    assert reachable(ip,53),f'Approved TCP DNS blocked: {ip}'
    assert not reachable(ip,853),f'DoT bypass: {ip}'
    assert not reachable(ip,8080,True),f'Unapproved UDP bypass: {ip}'
for ip in [other4,other6]:
    assert not reachable(ip,8080),f'Unapproved web/VPN destination bypass: {ip}'
    assert not reachable(ip,53,True),f'Alternative DNS bypass: {ip}'
# An unapproved tunnel-like route cannot use even an approved destination.
run('ip','link','set','eth0','name','tun-test')
assert not reachable(peer4,8443),'Tunnel interface bypass'
run('ip','link','set','tun-test','name','eth0')
# A corrupted signed payload must leave the active firewall untouched.
bad=root/'bad.json';envelope=json.loads(policy.read_text());envelope['payload']='00'+envelope['payload'][2:];bad.write_text(json.dumps(envelope))
assert run(agent,'apply','--config',str(config_path),'--policy',str(bad),'--state-dir',str(root),ok=False).returncode
assert not reachable(other4,8080)
# Supervisor repairs deletion and quarantines expired policy while portal is offline.
policy=signed(2,18)
run(agent,'apply','--config',str(config_path),'--policy',str(policy),'--state-dir',str(root))
log=(root/'supervisor.log').open('w')
child=subprocess.Popen([agent,'run','--config',str(config_path),'--state-dir',str(root)],stdout=log,stderr=log)
try:
    time.sleep(2);assert child.poll() is None,'Supervisor exited'
    assert run(agent,'run','--config',str(config_path),'--state-dir',str(root),ok=False).returncode,'Concurrent supervisor accepted'
    assert run(agent,'rollback','--state-dir',str(root),ok=False).returncode,'Rollback allowed while supervisor owns state'
    run('nft','delete','table','inet','wtp_endpoint')
    deadline=time.time()+8
    while time.time()<deadline:
        if run('nft','list','table','inet','wtp_endpoint',ok=False).returncode==0:break
        time.sleep(.2)
    assert not reachable(other4,8080),'Drift was not repaired'
    deadline=time.time()+25
    while time.time()<deadline:
        if not reachable(peer4,8080):break
        time.sleep(.5)
    assert not reachable(peer4,8080),'Expired policy retained web access'
    assert not reachable(peer4,53,True),'Expired policy retained DNS access'
    assert reachable(peer4,8443),'Quarantine disconnected management'
    assert child.poll() is None,'Supervisor exited during expiry test'
finally:
    child.terminate();child.wait(timeout=5);log.close()
# Corrupted local anti-rollback state must close a previously permissive policy.
policy=signed(3)
run(agent,'apply','--config',str(config_path),'--policy',str(policy),'--state-dir',str(root))
assert reachable(peer4,8080)
(root/'watermark.json').write_text('corrupt')
assert run(agent,'run','--config',str(config_path),'--state-dir',str(root),ok=False).returncode
assert not reachable(peer4,8080),'Corrupt state did not quarantine'
assert reachable(peer4,8443),'Corrupt-state quarantine lost management'
run(agent,'rollback','--state-dir',str(root))
assert reachable(other4,8080),'Rollback did not restore connectivity'
assert run('nft','list','table','inet','unrelated').returncode==0,'Unrelated firewall table changed'
# Real HTTPS transport: certificate checking, bearer request, signed response, preview.
import http.server, ssl, threading
cert=root/'tls.crt';tlskey=root/'tls.key'
run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(tlskey),'-out',str(cert),'-days','1','-subj','/CN=portal.test','-addext','subjectAltName=DNS:portal.test')
local=json.loads(run('ip','-j','-4','addr','show','eth0').stdout)[0]['addr_info'][0]['local']
live_config={**config,'portal':'https://portal.test:9443','control':f'{local}:9443'}
live_network={**network,'allowed_tcp':[f'{local}:9443',f'{peer4}:8080']}
source=root/'live-source.json';source.write_text(json.dumps({'endpoint_id':config['endpoint_id'],'platform':'linux','revision':3,'issued_at':int(time.time()),'expires_at':int(time.time())+300,'network':live_network}))
live_policy=root/'live-policy.json';run(agent,'sign-policy','--key',str(key),'--policy',str(source),'--output',str(live_policy))
live_path=root/'live-config.json';live_path.write_text(json.dumps(live_config))
reports=[]
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def handle(self):
        try:super().handle()
        except ConnectionResetError:pass
    def do_POST(self):
        if self.path!='/endpoint/policy' or self.headers.get('Authorization')!='Bearer '+config['token']:
            self.send_error(401);return
        reports.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
        body=live_policy.read_bytes();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
server=http.server.ThreadingHTTPServer(('0.0.0.0',9443),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,tlskey);server.socket=context.wrap_socket(server.socket,server_side=True)
threading.Thread(target=server.serve_forever,daemon=True).start()
try:
    args=[agent,'fetch','--config',str(live_path),'--output',str(root/'fetched.json')]
    assert run(*args,ok=False).returncode,'Untrusted TLS certificate accepted'
    os.environ['CURL_CA_BUNDLE']=str(cert)
    run(*args);assert reports[-1]['state']=='preview'
    assert json.loads((root/'fetched.json').read_text())==json.loads(live_policy.read_text())
    envelope=json.loads(live_policy.read_text());envelope['payload']='00'+envelope['payload'][2:];live_policy.write_text(json.dumps(envelope))
    assert run(*args,ok=False).returncode,'Tampered HTTPS policy accepted'
finally:
    server.shutdown();server.server_close();os.environ.pop('CURL_CA_BUNDLE',None)
print('PASS: real kernel IPv4/IPv6 allow/deny, UDP/TCP DNS, DoT/UDP/VPN-interface restrictions, signature rejection, drift repair, expiry quarantine, management continuity, scoped rollback, fresh IPv6 neighbor discovery, exclusive supervision, corrupt-state quarantine, and real TLS policy retrieval/signature validation')
