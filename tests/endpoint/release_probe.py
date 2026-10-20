"""Disposable signing keys: validate independent verification and corruption rejection."""
import argparse, json, pathlib, subprocess, sys, tempfile
p=argparse.ArgumentParser();p.add_argument('--chrome',type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[2];agent=root/'target/debug/wtp-agent'
def run(*args,ok=True):
    r=subprocess.run([str(x) for x in args],text=True,capture_output=True)
    if ok and r.returncode:raise AssertionError(r.stderr)
    if not ok and not r.returncode:raise AssertionError('corrupt or untrusted signature accepted')
    return r
with tempfile.TemporaryDirectory(prefix='wtp-signing-test-') as work:
    work=pathlib.Path(work);key=work/'release.key';public=run(agent,'keygen','--output',key).stdout.strip()
    file=work/'sample.zip';file.write_bytes(b'test artifact');signature=work/'signature.json'
    run(agent,'sign-file','--key',key,'--file',file,'--output',signature)
    verify=[sys.executable,root/'scripts/release/verify-artifact.py','--public-key',public,'--file',file,'--signature',signature]
    run(*verify)
    file.write_bytes(b'tampered artifact');run(*verify,ok=False)
    file.write_bytes(b'test artifact');envelope=json.loads(signature.read_text());envelope['domain']='wtp.endpoint.policy.v1';signature.write_text(json.dumps(envelope));run(*verify,ok=False)
    if a.chrome:
        rsa=work/'extension.pem';run('openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',rsa)
        output=work/'package'
        run(sys.executable,root/'scripts/release/package-extension.py','--chrome',a.chrome,'--key',rsa,'--base-url','https://updates.example.test/wtp','--output',output)
        identifier=(output/'extension-id.txt').read_text().strip();crx=output/'extension.crx'
        verify=[sys.executable,root/'scripts/release/verify-crx.py','--id',identifier,crx];run(*verify)
        data=bytearray(crx.read_bytes());data[-1]^=1;crx.write_bytes(data);run(*verify,ok=False)
print('PASS: independent Ed25519 artifact verification, changed bytes/domain rejection'+(', Chromium CRX3 packaging and corrupt archive rejection' if a.chrome else ''))
