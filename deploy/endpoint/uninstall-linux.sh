#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root.' >&2; exit 1; }
systemctl disable --now wtp-endpoint.service
/usr/local/libexec/wtp/wtp-agent rollback --state-dir /var/lib/wtp-endpoint
rm -f /etc/systemd/system/wtp-endpoint.service
systemctl daemon-reload
echo 'Enforcement removed. Configuration, audit state and anti-rollback history remain for review.'
