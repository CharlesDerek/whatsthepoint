#!/usr/bin/env python3
"""Native compiler validation; never activates a firewall. macOS requires sudo for pfctl -n."""
import json, pathlib, platform, subprocess, tempfile, time
root=pathlib.Path(__file__).resolve().parents[1];system=platform.system();name={'Linux':'linux','Windows':'windows','Darwin':'macos'}[system]
agent=root/('target/debug/wtp-agent.exe' if name=='windows' else 'target/debug/wtp-agent')
with tempfile.TemporaryDirectory(prefix='wtp-plan-') as work:
    work=pathlib.Path(work);key=work/'signing.key'
    public=subprocess.check_output([str(agent),'keygen','--output',str(key)],text=True).strip()
    network={'interfaces':[{'linux':'eth0','windows':'Ethernet','macos':'en0'}[name]],'dhcp':True,'dns_servers':['192.0.2.53','2001:db8::53'],'allowed_tcp':['192.0.2.10:443','[2001:db8::10]:443'],'allowed_udp':['192.0.2.20:123']}
    config={'endpoint_id':'a'*32,'platform':name,'portal':'https://portal.test','control':'192.0.2.10:443','token':'b'*64,'public_key':public,'interfaces':network['interfaces'],'dhcp':True}
    policy={'endpoint_id':config['endpoint_id'],'platform':name,'revision':1,'issued_at':int(time.time()),'expires_at':int(time.time())+300,'network':network}
    for file,value in [('config.json',config),('policy.json',policy)]:work.joinpath(file).write_text(json.dumps(value))
    subprocess.run([str(agent),'sign-policy','--key',str(key),'--policy',str(work/'policy.json'),'--output',str(work/'signed.json')],check=True)
    plan=subprocess.check_output([str(agent),'plan','--config',str(work/'config.json'),'--policy',str(work/'signed.json')],text=True)
    target=work/('plan.ps1' if name=='windows' else 'plan.conf');target.write_text(plan)
    if name=='macos':subprocess.run(['sudo','-n','/sbin/pfctl','-nf',str(target)],check=True)
    elif name=='windows':
        for script in [target,*root.glob('deploy/endpoint/*.ps1'),*root.glob('scripts/release/*.ps1')]:
            escaped=str(script).replace("'","''")
            subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',f"$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('{escaped}',[ref]$tokens,[ref]$errors);if($errors.Count){{$errors | Out-String | Write-Error;exit 1}}"],check=True)
print(f'PASS: {name} signed policy compilation and available native parser checks (no activation)')
