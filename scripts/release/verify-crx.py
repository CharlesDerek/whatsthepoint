#!/usr/bin/env python3
"""Verify the pinned developer RSA proof in a locally packaged CRX3 (not a store publisher proof).
Wire format: chromium/src/components/crx_file/crx3.proto and crx_verifier.cc.
"""
import argparse, hashlib, pathlib, struct, subprocess, tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--id',required=True);p.add_argument('file',type=pathlib.Path);a=p.parse_args()
if len(a.id)!=32 or any(c not in 'abcdefghijklmnop' for c in a.id):p.error('invalid pinned extension ID')
if a.file.stat().st_size>32*1024*1024:p.error('CRX exceeds limit')
data=a.file.read_bytes()
def fields(data):
    pos=0;out={}
    def varint():
        nonlocal pos
        value=0
        for shift in range(0,64,7):
            if pos>=len(data):raise ValueError('truncated protobuf')
            b=data[pos];pos+=1;value|=(b&127)<<shift
            if b<128:return value
        raise ValueError('oversized varint')
    while pos<len(data):
        tag=varint()
        if tag&7!=2 or tag>>3==0:raise ValueError('unsupported protobuf field')
        size=varint()
        if size>len(data)-pos:raise ValueError('truncated field')
        out.setdefault(tag>>3,[]).append(data[pos:pos+size]);pos+=size
    return out
def one(data,key):
    values=data.get(key,[])
    if len(values)!=1:raise ValueError('missing/duplicate signed field')
    return values[0]
try:
    if len(data)<12 or data[:4]!=b'Cr24':raise ValueError('invalid magic')
    version,size=struct.unpack('<II',data[4:12])
    if version!=3 or size>65536 or size>len(data)-12:raise ValueError('invalid CRX3 header')
    header=fields(data[12:12+size]);signed=one(header,10000);identifier=one(fields(signed),1)
    if len(identifier)!=16:raise ValueError('invalid ID size')
    actual=''.join(chr(97+int(c,16)) for c in identifier.hex())
    if actual!=a.id:raise ValueError('extension identity mismatch')
    valid=False
    for proof in header.get(2,[]):
        proof=fields(proof);key=one(proof,1);sig=one(proof,2)
        if hashlib.sha256(key).digest()[:16]!=identifier:continue
        with tempfile.TemporaryDirectory(prefix='wtp-crx-verify-') as work:
            work=pathlib.Path(work);(work/'key.der').write_bytes(key);(work/'sig').write_bytes(sig)
            (work/'message').write_bytes(b'CRX3 SignedData\0'+struct.pack('<I',len(signed))+signed+data[12+size:])
            result=subprocess.run(['openssl','dgst','-sha256','-verify',str(work/'key.der'),'-keyform','DER','-signature',str(work/'sig'),str(work/'message')],capture_output=True)
            valid=result.returncode==0
        if valid:break
    if not valid:raise ValueError('developer signature failed')
except (ValueError,struct.error) as error:p.error(str(error))
print(f'Verified CRX3 developer signature: {a.id}')
