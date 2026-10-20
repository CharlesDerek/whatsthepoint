#!/usr/bin/env python3
"""Verify a release with independently installed Python + OpenSSL, before executing it."""
import argparse, hashlib, json, pathlib, subprocess, tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--public-key',required=True,help='Pinned Ed25519 public key hex, obtained through a trusted channel')
p.add_argument('--file',type=pathlib.Path,required=True)
p.add_argument('--signature',type=pathlib.Path,required=True)
a=p.parse_args()
if a.signature.stat().st_size>262144:p.error('signature exceeds limit')
envelope=json.loads(a.signature.read_text())
if envelope.get('domain')!='wtp.release.file.v1':p.error('incorrect signature domain')
try:key=bytes.fromhex(a.public_key);sig=bytes.fromhex(envelope['signature']);payload=bytes.fromhex(envelope['payload'])
except (ValueError,KeyError):p.error('invalid signature encoding')
if len(key)!=32 or len(sig)!=64 or len(payload)>65536:p.error('invalid signature size')
with tempfile.TemporaryDirectory(prefix='wtp-verify-') as work:
    work=pathlib.Path(work)
    # RFC 8410 SubjectPublicKeyInfo for an Ed25519 raw public key.
    (work/'key.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+key)
    (work/'signature').write_bytes(sig)
    (work/'message').write_bytes(b'wtp.release.file.v1\0'+payload)
    result=subprocess.run(['openssl','pkeyutl','-verify','-pubin','-keyform','DER','-inkey',str(work/'key.der'),'-rawin','-in',str(work/'message'),'-sigfile',str(work/'signature')],capture_output=True)
    if result.returncode:p.error('signature verification failed')
claim=json.loads(payload)
with a.file.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
if claim!={'name':a.file.name,'bytes':a.file.stat().st_size,'sha256':digest}:p.error('artifact differs from signed file claim')
print(f'Verified {a.file.name}: {digest}')
