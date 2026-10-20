#!/usr/bin/env python3
"""Activate the signed endpoint agent on a managed macOS desktop. Requires root."""
import argparse, os, pathlib, shutil, subprocess, sys
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',type=pathlib.Path,required=True)
p.add_argument('--config',type=pathlib.Path,required=True)
p.add_argument('--team-id',required=True)
p.add_argument('--activate',action='store_true')
a=p.parse_args()
if os.geteuid()!=0 or not a.activate:p.error('root and --activate are required')
if not a.team_id.isalnum() or len(a.team_id)!=10:p.error('invalid Apple Team ID')
# Validate a pinned Developer ID identity before copying/executing the agent.
subprocess.run(['/usr/bin/codesign','--verify','--strict','-R',f'anchor apple generic and certificate leaf[subject.OU] = "{a.team_id}"',str(a.binary)],check=True)
root=pathlib.Path('/Library/Application Support/WhatsThePoint/Endpoint')
subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('secure-path.py')),str(root/'config.json'),'/usr/local/libexec/wtp/wtp-agent','/Library/LaunchDaemons/org.whatsthepoint.endpoint.plist','/private/etc/pf.conf','/private/etc/pf.anchors/org.whatsthepoint'],check=True)
root.mkdir(parents=True,exist_ok=True);root.chmod(0o700)
backup=root/'pf.conf.before'
if backup.exists():p.error('already installed; use the preserved rollback procedure')
original=pathlib.Path('/etc/pf.conf').read_text()
# PF skip rules and included filter files can bypass an anchor. Reject unknown layouts.
lines=original.splitlines()
for line in lines:
    clean=line.split('#',1)[0].strip()
    if clean.startswith('include ') or (clean.startswith('set skip') and clean not in ['set skip on lo0','set skip on { lo0 }']):p.error('custom PF includes/skip rules require administrator integration')
index=next((i for i,line in enumerate(lines) if line.lstrip().startswith(('anchor ','pass ','block ','match ','antispoof '))),len(lines))
lines[index:index]=['anchor "org.whatsthepoint" quick','load anchor "org.whatsthepoint" from "/etc/pf.anchors/org.whatsthepoint"']
candidate=root/'pf.conf.candidate';candidate.write_text('\n'.join(lines)+'\n')
anchor=pathlib.Path('/etc/pf.anchors/org.whatsthepoint')
if anchor.exists():p.error('reserved PF anchor already exists')
anchor.write_text('block drop quick all\n');anchor.chmod(0o600)
try:subprocess.run(['/sbin/pfctl','-nf',str(candidate)],check=True)
except Exception:anchor.unlink();raise
backup.write_text(original);backup.chmod(0o600)
root.joinpath('pf-was-enabled').write_text('yes' if 'Status: Enabled' in subprocess.run(['/sbin/pfctl','-s','info'],capture_output=True,text=True,check=True).stdout else 'no')
bin_dir=pathlib.Path('/usr/local/libexec/wtp');bin_dir.mkdir(parents=True,exist_ok=True)
shutil.copyfile(a.binary,bin_dir/'wtp-agent');(bin_dir/'wtp-agent').chmod(0o755)
shutil.copyfile(a.config,root/'config.json');(root/'config.json').chmod(0o600)
shutil.copyfile(candidate,'/etc/pf.conf')
# Establish the restrictive anchor immediately, then let the agent load signed permits.
subprocess.run(['/sbin/pfctl','-f','/etc/pf.conf'],check=True)
if root.joinpath('pf-was-enabled').read_text()=='no':subprocess.run(['/sbin/pfctl','-e'],check=True)
subprocess.run(['/sbin/pfctl','-F','states'],check=True)
plist=pathlib.Path('/Library/LaunchDaemons/org.whatsthepoint.endpoint.plist')
shutil.copyfile(pathlib.Path(__file__).with_name(plist.name),plist);plist.chmod(0o644)
subprocess.run(['/bin/launchctl','bootstrap','system',str(plist)],check=True)
print('Endpoint agent activated. Verify the portal heartbeat and local status.')
