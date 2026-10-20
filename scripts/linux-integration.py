#!/usr/bin/env python3
"""Validate nftables inside isolated Docker network namespaces; never uses host networking."""
import json, pathlib, subprocess, uuid
root=pathlib.Path(__file__).resolve().parents[1]
prefix='wtp-test-'+uuid.uuid4().hex[:10]
network=prefix+'-net';containers=[]
def run(*args,**kwargs):return subprocess.check_output(args,text=True,**kwargs).strip()
try:
    subprocess.run(['cargo','build','--locked','-p','wtp-endpoint'],cwd=root,check=True)
    subprocess.run(['docker','build','--quiet','-t','wtp-endpoint-validation','-f',str(root/'tests/endpoint/Dockerfile'),str(root/'tests/endpoint')],cwd=root,check=True)
    run('docker','network','create','--internal','--ipv6','--subnet',f'fd42:{uuid.uuid4().hex[:4]}::/64',network)
    peers=[]
    for number in range(2):
        name=f'{prefix}-peer{number}';containers.append(name)
        run('docker','run','-d','--name',name,'--network',network,'--mount',f'type=bind,src={root / "tests/endpoint/peer.py"},dst=/peer.py,readonly','wtp-endpoint-validation','python3','/peer.py')
        info=json.loads(run('docker','inspect',name))[0]['NetworkSettings']['Networks'][network]
        peers.extend([info['IPAddress'],info['GlobalIPv6Address']])
    name=prefix+'-client';containers.append(name)
    subprocess.run(['docker','run','--rm','--name',name,'--network',network,'--cap-add','NET_ADMIN','--mount',f'type=bind,src={root / "target/debug/wtp-agent"},dst=/source/wtp-agent,readonly','--mount',f'type=bind,src={root / "tests/endpoint/linux_probe.py"},dst=/probe.py,readonly','wtp-endpoint-validation','python3','/probe.py',*peers],check=True)
finally:
    for name in reversed(containers):subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
