#!/usr/bin/env python3
"""Register the read-only OS identity companion for Chrome, Chromium or Edge.

Default: current OS user. --system requires administrator rights and an executable
installed in an administrator-controlled location. No DNS/firewall changes occur.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

HOST = "org.whatsthepoint.identity"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", required=True, type=Path)
parser.add_argument("--extension-id", required=True)
parser.add_argument("--browser", choices=["chrome", "chromium", "edge"], default="chrome")
parser.add_argument("--system", action="store_true")
parser.add_argument("--uninstall", action="store_true")
parser.add_argument("--dry-run", action="store_true")
args = parser.parse_args()
if not re.fullmatch("[a-p]{32}", args.extension_id):
    parser.error("extension ID must contain 32 letters from a through p")
binary = args.binary.resolve(strict=True)
if not binary.is_file():
    parser.error("binary must be an existing executable file")

if sys.platform == "win32":
    root = Path(os.environ["ProgramData" if args.system else "LOCALAPPDATA"])
    directory = root / "WhatsThePoint" / "NativeMessagingHosts" / args.browser
elif sys.platform == "darwin":
    names = {"chrome": "Google/Chrome", "chromium": "Chromium", "edge": "Microsoft Edge"}
    if args.system:
        directory = {"chrome": Path("/Library/Google/Chrome/NativeMessagingHosts"),
                     "chromium": Path("/Library/Application Support/Chromium/NativeMessagingHosts"),
                     "edge": Path("/Library/Microsoft/Edge/NativeMessagingHosts")}[args.browser]
    else:
        directory = Path.home() / "Library/Application Support" / names[args.browser] / "NativeMessagingHosts"
else:
    names = {"chrome": "google-chrome", "chromium": "chromium", "edge": "microsoft-edge"}
    if args.system:
        directory = {"chrome": Path("/etc/opt/chrome/native-messaging-hosts"),
                     "chromium": Path("/etc/chromium/native-messaging-hosts"),
                     "edge": Path("/etc/opt/edge/native-messaging-hosts")}[args.browser]
    else:
        directory = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / names[args.browser] / "NativeMessagingHosts"
path = directory / f"{HOST}.json"
manifest = {"name": HOST, "description": "What's the Point desktop identity", "path": str(binary),
            "type": "stdio", "allowed_origins": [f"chrome-extension://{args.extension_id}/"]}
if args.dry_run:
    print(json.dumps({"path": str(path), "manifest": manifest, "uninstall": args.uninstall}, indent=2))
    sys.exit(0)
if args.uninstall:
    path.unlink(missing_ok=True)
else:
    directory.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
if sys.platform == "win32":
    import winreg
    vendor = {"chrome": "Google\\Chrome", "chromium": "Chromium", "edge": "Microsoft\\Edge"}[args.browser]
    key_path = f"Software\\{vendor}\\NativeMessagingHosts\\{HOST}"
    hive = winreg.HKEY_LOCAL_MACHINE if args.system else winreg.HKEY_CURRENT_USER
    if args.uninstall:
        try:
            winreg.DeleteKey(hive, key_path)
        except FileNotFoundError:
            pass
    else:
        with winreg.CreateKey(hive, key_path) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(path))
print(f"{'Removed' if args.uninstall else 'Registered'} {path}")
