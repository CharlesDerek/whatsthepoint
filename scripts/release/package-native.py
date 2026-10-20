#!/usr/bin/env python3
"""Create a platform-signed release on a dedicated signing runner, then sign its archive."""
import json, os, pathlib, platform, shutil, subprocess, sys, tempfile
root=pathlib.Path(__file__).resolve().parents[2];system=platform.system();suffix='.exe' if system=='Windows' else ''
private=os.environ.get('WTP_RELEASE_PRIVATE_KEY','');public=os.environ.get('WTP_RELEASE_PUBLIC_KEY','')
if len(private)!=64 or len(public)!=64:raise SystemExit('Configure the release signing secret and separately pinned public key')
output=root/'signed-dist'
if output.exists():raise SystemExit('Refusing to overwrite signed-dist')
output.mkdir()
with tempfile.TemporaryDirectory(prefix='wtp-package-') as work:
    work=pathlib.Path(work);package=work/'package';package.mkdir();binaries=work/'binaries';binaries.mkdir()
    for name in ['wtp','wtp-native','wtp-agent']:shutil.copy2(root/f'target/release/{name}{suffix}',binaries/f'{name}{suffix}')
    if system=='Windows':
        subprocess.run(['powershell','-NoProfile','-NonInteractive','-File',str(root/'scripts/release/sign-windows.ps1'),'-Directory',str(binaries),'-PublisherThumbprint',os.environ['WTP_WINDOWS_THUMBPRINT']],check=True)
    elif system=='Darwin':
        subprocess.run(['sh',str(root/'scripts/release/sign-macos.sh'),str(binaries),str(package/'whatsthepoint.pkg')],check=True)
    elif system!='Linux':raise SystemExit('Unsupported signing platform')
    for file in binaries.iterdir():shutil.copy2(file,package/file.name)
    for name in ['deploy','docs','extension']:
        shutil.copytree(root/name,package/name,ignore=shutil.ignore_patterns('_metadata','__pycache__','*.pem','*.key','*.pfx','*.p12'))
    for name in ['README.md','LICENSE','SECURITY.md','THIRD_PARTY.md']:shutil.copy2(root/name,package/name)
    (package/'BUILD.json').write_text(json.dumps({'platform':system,'architecture':platform.machine(),'revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'extension':'source; package and distribute separately','public_key':public},indent=2))
    archive=pathlib.Path(shutil.make_archive(str(output/f'wtp-{system.lower()}-{platform.machine()}'),'zip',package))
    key=work/'release.key';key.write_text(private);key.chmod(0o600)
    signature=archive.with_suffix('.zip.sig.json')
    subprocess.run([str(binaries/f'wtp-agent{suffix}'),'sign-file','--key',str(key),'--file',str(archive),'--output',str(signature)],check=True)
    # Independent verification does not execute a downloaded release.
    subprocess.run([sys.executable,str(root/'scripts/release/verify-artifact.py'),'--public-key',public,'--file',str(archive),'--signature',str(signature)],check=True)
print(f'Signed and verified artifacts: {output}')
