"""Optional live-network verification. Disposable data; never changes OS DNS."""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--binary", default="target/release/wtp.exe" if os.name == "nt" else "target/release/wtp")
parser.add_argument("--feed", action="store_true", help="Also download and verify HaGeZi Light")
args = parser.parse_args()
binary = str(Path(args.binary).resolve())


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def dns(domain, port, tcp=False):
    ident = secrets.randbelow(65536)
    name = b"".join(bytes([len(part)]) + part.encode("ascii") for part in domain.split(".")) + b"\0"
    packet = struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + name + struct.pack("!2H", 1, 1)
    with socket.socket(type=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(15)
        sock.connect(("127.0.0.1", port))
        if tcp:
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            length = b""
            while len(length) < 2:
                chunk = sock.recv(2 - len(length))
                if not chunk:
                    raise RuntimeError("DNS TCP connection closed")
                length += chunk
            needed = struct.unpack("!H", length)[0]
            reply = b""
            while len(reply) < needed:
                chunk = sock.recv(needed - len(reply))
                if not chunk:
                    raise RuntimeError("DNS TCP connection closed")
                reply += chunk
        else:
            sock.send(packet)
            reply = sock.recv(4096)
    received_id, flags = struct.unpack("!2H", reply[:4])
    assert received_id == ident, "Mismatched DNS ID"
    return flags & 15


with tempfile.TemporaryDirectory(prefix="wtp-smoke-") as temp:
    root = Path(temp)
    dns_port, http_port = free_port(), free_port()
    config = root / "test.toml"
    config.write_text(
        f'dns_bind = "127.0.0.1:{dns_port}"\nhttp_bind = "127.0.0.1:{http_port}"\n'
        f'public_origin = "http://127.0.0.1:{http_port}"\n', encoding="utf-8"
    )
    password = secrets.token_urlsafe(32)
    subprocess.run([binary, "--data-dir", temp, "init"],
                   env={**os.environ, "WTP_ADMIN_PASSWORD": password}, check=True, capture_output=True)
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    csrf = ""

    def api(path, method="GET", data=None):
        headers = {"X-WTP-Request": "1", "Content-Type": "application/json", "X-CSRF-Token": csrf}
        req = urllib.request.Request(f"http://127.0.0.1:{http_port}{path}",
                                     data=json.dumps(data).encode() if data is not None else None,
                                     headers=headers, method=method)
        with client.open(req, timeout=60) as response:
            return json.load(response)

    with (root / "server.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen([binary, "--data-dir", temp, "--config", str(config), "serve"],
                                   stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                try:
                    api("/healthz")
                    break
                except (OSError, ValueError):
                    if process.poll() is not None:
                        raise RuntimeError("Server exited during startup")
                    time.sleep(0.1)
            else:
                raise RuntimeError("Server readiness timed out")
            csrf = api("/api/login", "POST", {"username": "admin", "password": password})["csrf"]
            assert dns("blocked.test", dns_port) == 3, "UDP block failed"
            assert dns("blocked.test", dns_port, tcp=True) == 3, "TCP block failed"
            assert dns("example.com", dns_port) == 0, "Real encrypted upstream failed"
            assert dns("example.com", dns_port, tcp=True) == 0, "Cached allowed answer failed"
            api("/api/rules", "POST", {"domain": "example.com", "action": "block", "note": "Smoke test"})
            assert dns("example.com", dns_port) == 3, "Policy update did not override cache"
            print("PASS: UDP, TCP, live encrypted resolution, caching, and immediate policy update")
            if args.feed:
                installed = api("/api/lists/preset", "POST", {"preset": "hagezi-light"})
                assert installed["count"] > 10000
                with sqlite3.connect(root / "wtp.db") as conn:
                    domain = conn.execute("SELECT domain FROM list_domains ORDER BY domain LIMIT 1").fetchone()[0]
                assert dns(domain, dns_port) == 3, "Downloaded feed was not enforced"
                print(f"PASS: live HaGeZi download, {installed['count']:,} domains, and DNS enforcement")
            for _ in range(50):
                stats = api("/api/stats")
                if stats["total"] >= 5:
                    break
                time.sleep(0.1)
            assert stats["cached"] >= 1, "Cache result was not logged"
            assert stats["errors"] == 0, "Unexpected resolution errors"
            print(f"PASS: authenticated dashboard reports {stats['total']} real queries")
        finally:
            process.terminate()
            try:
                process.wait(timeout=55)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    result = subprocess.run([binary, "--data-dir", temp, "check", "example.com"], check=True, capture_output=True, text=True)
    assert json.loads(result.stdout)["blocked"]
    print("PASS: policy persisted after process shutdown")
