#!/usr/bin/env python3
"""Package a CRX3 using Chromium's signer and generate a managed update feed."""
import argparse, hashlib, json, pathlib, shutil, subprocess, tempfile, urllib.parse, xml.etree.ElementTree as ET
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--chrome',required=True,type=pathlib.Path)
p.add_argument('--key',required=True,type=pathlib.Path,help='Existing RSA PEM private key; keep stable across releases')
p.add_argument('--base-url',required=True,help='HTTPS directory that will host extension.crx and updates.xml')
p.add_argument('--output',required=True,type=pathlib.Path)
a=p.parse_args();url=urllib.parse.urlsplit(a.base_url)
if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment:p.error('base URL must be a public HTTPS directory without credentials/query/fragment')
root=pathlib.Path(__file__).resolve().parents[2]
public=subprocess.check_output(['openssl','pkey','-in',str(a.key.resolve()),'-pubout','-outform','DER'],stderr=subprocess.DEVNULL)
identifier=''.join(chr(97+int(c,16)) for c in hashlib.sha256(public).hexdigest()[:32])
a.output.mkdir(parents=True,exist_ok=True)
if any(a.output.iterdir()):p.error('output must be empty')
with tempfile.TemporaryDirectory(prefix='wtp-crx-') as work:
    work=pathlib.Path(work);source=work/'extension'
    shutil.copytree(root/'extension',source,ignore=shutil.ignore_patterns('_metadata','*.pem','*.key'))
    manifest=json.loads((source/'manifest.json').read_text());manifest['update_url']=a.base_url.rstrip('/')+'/updates.xml'
    (source/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    subprocess.run([str(a.chrome.resolve()),'--headless','--no-sandbox',f'--user-data-dir={work / "profile"}',f'--pack-extension={source}',f'--pack-extension-key={a.key.resolve()}'],check=True,capture_output=True,timeout=60)
    shutil.copyfile(work/'extension.crx',a.output/'extension.crx')
    subprocess.run(['python3',str(pathlib.Path(__file__).with_name('verify-crx.py')),'--id',identifier,str(a.output/'extension.crx')],check=True)
    # Unsigned source ZIP is only for submission to the browser store.
    shutil.make_archive(str(a.output/'store-upload'),'zip',source)
feed=ET.Element('gupdate',xmlns='http://www.google.com/update2/response',protocol='2.0')
app=ET.SubElement(feed,'app',appid=identifier)
ET.SubElement(app,'updatecheck',codebase=a.base_url.rstrip('/')+'/extension.crx',version=manifest['version'])
ET.ElementTree(feed).write(a.output/'updates.xml',encoding='utf-8',xml_declaration=True)
(a.output/'extension-id.txt').write_text(identifier+'\n')
print(f'Signed CRX3: {identifier}. Upload/publishing is a separate deployment step.')
