"""Reject inactive-only audit exceptions if they become compiled dependencies."""
import subprocess

tree = subprocess.check_output(
    ["cargo", "tree", "--locked", "--edges", "normal,build", "--prefix", "none"],
    text=True,
)
for dependency in ("rsa", "sqlx-mysql"):
    if any(line.startswith(dependency + " ") for line in tree.splitlines()):
        raise SystemExit(f"{dependency} is active: remove the RSA audit exception and remediate.")
print("Verified: optional MySQL/RSA code is absent from the active dependency graph.")
