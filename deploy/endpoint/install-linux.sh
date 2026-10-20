#!/bin/sh
set -eu
# Run from a trusted, signature-verified release directory. This is device-wide.
if [ "$#" -ne 3 ] || [ "$3" != '--activate' ]; then
    echo 'Usage: install-linux.sh /absolute/wtp-agent /absolute/config.json --activate' >&2
    exit 2
fi
[ "$(id -u)" = 0 ] || { echo 'Run as root.' >&2; exit 1; }
command -v nft >/dev/null
[ -x /usr/bin/curl ]
agent_source=$1
config_source=$2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$script_dir/secure-path.py" /usr/local/libexec/wtp/wtp-agent /etc/wtp-endpoint/config.json /var/lib/wtp-endpoint /etc/systemd/system/wtp-endpoint.service
[ ! -e /etc/wtp-endpoint/config.json ] || { echo 'Already enrolled. Stop and uninstall before replacing the identity.' >&2; exit 1; }
install -d -o root -g root -m 0755 /usr/local/libexec/wtp
install -d -o root -g root -m 0700 /etc/wtp-endpoint /var/lib/wtp-endpoint
install -o root -g root -m 0755 "$agent_source" /usr/local/libexec/wtp/wtp-agent
install -o root -g root -m 0600 "$config_source" /etc/wtp-endpoint/config.json
install -o root -g root -m 0644 "$script_dir/wtp-endpoint.service" /etc/systemd/system/wtp-endpoint.service
systemctl daemon-reload
systemctl enable --now wtp-endpoint.service
systemctl is-active --quiet wtp-endpoint.service
echo 'Endpoint supervision started. Verify wtp-agent status and the portal heartbeat.'
