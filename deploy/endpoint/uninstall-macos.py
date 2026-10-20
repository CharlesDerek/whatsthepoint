#!/usr/bin/env python3
import os,pathlib,subprocess
if os.geteuid()!=0:raise SystemExit('Run as root')
root=pathlib.Path('/Library/Application Support/WhatsThePoint/Endpoint')
subprocess.run(['/bin/launchctl','bootout','system/org.whatsthepoint.endpoint'],check=True)
subprocess.run(['/usr/local/libexec/wtp/wtp-agent','rollback','--state-dir',str(root)],check=True)
# Remove only our anchor registration; preserve unrelated changes made since installation.
path=pathlib.Path('/etc/pf.conf')
lines=[line for line in path.read_text().splitlines() if line not in ['anchor "org.whatsthepoint" quick','load anchor "org.whatsthepoint" from "/etc/pf.anchors/org.whatsthepoint"']]
temp=root/'pf.conf.rollback';temp.write_text('\n'.join(lines)+'\n')
subprocess.run(['/sbin/pfctl','-nf',str(temp)],check=True)
path.write_text(temp.read_text());subprocess.run(['/sbin/pfctl','-f',str(path)],check=True)
pathlib.Path('/etc/pf.anchors/org.whatsthepoint').unlink()
pathlib.Path('/Library/LaunchDaemons/org.whatsthepoint.endpoint.plist').unlink()
# Keep PF enabled: disabling it could remove another administrator's protection.
print('WTP anchor removed; unrelated PF configuration and rollback snapshots retained.')
