#!/usr/bin/env python3
"""Install the paired console and application-menu launcher for the current user."""
import argparse, os, pathlib, shutil, sys

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary',type=pathlib.Path,required=True)
args=parser.parse_args()
if sys.platform!='linux':raise SystemExit('This launcher installer is for Linux.')
source=args.binary.resolve(strict=True)
base=pathlib.Path.home()/'.local'
target=base/'libexec/wtp/wtp-desktop'
target.parent.mkdir(parents=True,exist_ok=True)
temporary=target.with_suffix('.new')
shutil.copyfile(source,temporary);temporary.chmod(0o755);os.replace(temporary,target)
applications=base/'share/applications';applications.mkdir(parents=True,exist_ok=True)
icon=base/'share/icons/whatsthepoint.svg';icon.parent.mkdir(parents=True,exist_ok=True)
shutil.copyfile(pathlib.Path(__file__).resolve().parents[2]/'web/favicon.svg',icon)
def quote(value):
    return '"'+str(value).replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$').replace('%','%%')+'"'
launcher=applications/'whatsthepoint.desktop'
launcher.write_text(f'[Desktop Entry]\nType=Application\nName=What’s the Point\nComment=Paired web filtering console\nExec={quote(target)} open\nIcon={icon}\nTerminal=false\nCategories=Network;Settings;\nStartupNotify=true\n')
launcher.chmod(0o644)
print(f'Installed desktop console: {target}\nApplication launcher: {launcher}')
