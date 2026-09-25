#!/bin/sh
# Installs the gateway as a systemd service.
#
#   sudo ./install.sh [path/to/opcua-audit-gateway]
#
# Binary:  /usr/local/bin/opcua-audit-gateway
# Config:  /etc/opcua-audit-gateway/config.toml
# Data:    /var/lib/opcua-audit-gateway (certificates, audit trail, users)
#
# Running it again upgrades the binary and keeps config and data.
set -eu

BIN_SRC="${1:-./opcua-audit-gateway}"
BIN=/usr/local/bin/opcua-audit-gateway
ETC=/etc/opcua-audit-gateway
DATA=/var/lib/opcua-audit-gateway
UNIT=/etc/systemd/system/opcua-audit-gateway.service
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (sudo)" >&2
    exit 1
fi
if [ ! -x "$BIN_SRC" ]; then
    echo "binary not found: $BIN_SRC" >&2
    exit 1
fi

id opcua-gw >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin opcua-gw

# The service user owns $ETC and $DATA, so anything inside them may have been
# planted by it. Refuse links and never touch their contents as root.
for path in "$ETC" "$DATA" "$ETC/config.toml"; do
    if [ -L "$path" ]; then
        echo "refusing to continue: $path is a symbolic link" >&2
        exit 1
    fi
done

install -m 0755 "$BIN_SRC" "$BIN"
install -d -m 0750 -o opcua-gw -g opcua-gw "$ETC" "$DATA"

as_gateway() {
    runuser -u opcua-gw -- "$@"
}

if [ ! -e "$ETC/config.toml" ]; then
    (
        umask 077
        as_gateway "$BIN" --config "$ETC/config.toml" init >/dev/null
        # Keep certificates and data out of /etc.
        as_gateway sed -i "s|^pki_dir = .*|pki_dir = \"$DATA/pki\"|; s|^data_dir = .*|data_dir = \"$DATA\"|" "$ETC/config.toml"
        as_gateway rm -rf "$ETC/pki"
        as_gateway "$BIN" --config "$ETC/config.toml" init >/dev/null
    )
    echo "created $ETC/config.toml: add your targets, then restart the service"
fi

install -m 0644 "$HERE/opcua-audit-gateway.service" "$UNIT"
systemctl daemon-reload
systemctl enable opcua-audit-gateway >/dev/null
systemctl restart opcua-audit-gateway

echo "started. Status: systemctl status opcua-audit-gateway"
echo "first login on a new install: admin / admin (you must change the password)"
