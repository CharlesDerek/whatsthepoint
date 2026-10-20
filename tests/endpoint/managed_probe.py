"""Runs only inside a disposable NET_ADMIN container, with its own master and agent."""
import json, os, pathlib, shutil, sqlite3, subprocess, time

root=pathlib.Path('/test-master'); root.mkdir(mode=0o700)
ip=json.loads(subprocess.check_output(['ip','-j','-4','addr','show','eth0']))[0]['addr_info'][0]['local']
binary='/source/wtp'; args=[binary,'--data-dir',str(root),'--config',str(root/'wtp.toml')]
subprocess.run([binary,'--data-dir',str(root),'lan-init','--address',ip,'--output',str(root/'wtp.toml')],check=True)
subprocess.run([*args,'init'],env={**os.environ,'WTP_ADMIN_PASSWORD':'managed-test-password'},check=True)
server=subprocess.Popen([*args,'serve'],stdout=open(root/'server.log','w'),stderr=subprocess.STDOUT)
origin=f'https://{ip}:8443'; cookie=str(root/'cookie'); csrf=''
def api(path,body=None):
    command=['curl','--silent','--show-error','--fail-with-body','--noproxy','*','--cacert',str(root/'master.crt'),'-b',cookie,'-c',cookie,'-H','X-WTP-Request: 1','-H',f'Origin: {origin}']
    if csrf: command+=['-H',f'X-CSRF-Token: {csrf}']
    if body is not None: command+=['-H','Content-Type: application/json','--data',json.dumps(body)]
    return json.loads(subprocess.check_output([*command,origin+path],stderr=subprocess.DEVNULL))
def wait(check,seconds=75):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            value=check()
            if value:return value
        except (subprocess.CalledProcessError,FileNotFoundError,KeyError,json.JSONDecodeError):pass
        time.sleep(.3)
    raise AssertionError('Timed out waiting for managed endpoint state')
agent=None
try:
    wait(lambda:api('/healthz'))
    api('/api/login',{'username':'admin','password':'managed-test-password'})
    csrf=api('/api/me')['csrf']
    enrollment=api('/api/endpoints',{'name':'Container agent','platform':'linux','control':f'{ip}:8443','allow_remote_uninstall':True,'network':{'dns_servers':[],'interfaces':['eth0'],'allowed_tcp':[f'{ip}:8443'],'allowed_udp':[],'dhcp':False}})
    config=pathlib.Path('/etc/wtp-endpoint/config.json'); state=pathlib.Path('/var/lib/wtp-endpoint'); exe=pathlib.Path('/usr/local/libexec/wtp/wtp-agent')
    for directory in [config.parent,state,exe.parent]: directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    shutil.copyfile('/source/wtp-agent',exe);exe.chmod(0o755)
    config.write_text(json.dumps(enrollment['config']));config.chmod(0o600)
    # An unrelated table must survive removal of WTP enforcement.
    subprocess.run(['nft','add','table','inet','fixture_other'],check=True)
    agent=subprocess.Popen([str(exe),'run','--config',str(config),'--state-dir',str(state)],stdout=open(root/'agent.log','w'),stderr=subprocess.STDOUT)
    endpoint=wait(lambda:next((d for d in api('/api/endpoints')['devices'] if d['reported_state']=='enforced'),None))
    stored=json.loads(config.read_text());assert stored['pairing'] is None and stored['token']=='' and stored['paired_master']
    assert 'principal_id' not in (state/'agent-vault.json').read_text()
    assert len(api('/api/principals')['principals'])==1
    assert subprocess.run(['nft','list','table','inet','wtp_endpoint'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    api(f"/api/endpoints/{endpoint['id']}/uninstall",{'revision':endpoint['revision']})
    wait(lambda:api('/api/principals')['commands'][0]['state']=='completed')
    assert agent.wait(timeout=10)==0
    assert not exe.exists() and not config.exists() and not (state/'agent-vault.key').exists() and not (state/'agent-vault.json').exists()
    assert subprocess.run(['nft','list','table','inet','wtp_endpoint'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
    subprocess.run(['nft','list','table','inet','fixture_other'],check=True,stdout=subprocess.DEVNULL)
    assert api('/api/principals')['principals'][0]['revoked']
    print('PASS: real hybrid TLS agent pairing, encrypted credentials, policy enforcement, signed remote uninstall, firewall rollback and credential revocation')
finally:
    for process in [agent,server]:
        if process and process.poll() is None:process.terminate();process.wait(timeout=10)
    for log in ['server.log','agent.log']:
        if (root/log).exists():print((root/log).read_text())
