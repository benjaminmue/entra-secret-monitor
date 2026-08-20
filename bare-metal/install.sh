#!/bin/bash
# Bare metal installer (no Docker) for Debian/Ubuntu.
# Run as root from the repository root:  sudo bash bare-metal/install.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="/opt/entra-secret-monitor"
CFG_DIR="/etc/entra-secret-monitor"
PRTG_DIR="/var/prtg/scriptsxml"
GROUP="prtgmon"

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root." >&2
    exit 1
fi

echo "== Packages =="
apt-get update -qq
apt-get install -y -qq python3 python3-cryptography openssl

echo "== Group =="
getent group "$GROUP" >/dev/null || groupadd --system "$GROUP"

echo "== Application =="
install -d -m 0755 "$APP_DIR"
install -m 0755 "$REPO_DIR/app/graph.py"  "$APP_DIR/graph.py"
install -m 0755 "$REPO_DIR/app/cli.py"    "$APP_DIR/cli.py"
install -m 0755 "$REPO_DIR/app/server.py" "$APP_DIR/server.py"

echo "== Configuration =="
install -d -m 0750 -o root -g "$GROUP" "$CFG_DIR"
if [ ! -f "$CFG_DIR/monitor.env" ]; then
    install -m 0640 -o root -g "$GROUP" "$REPO_DIR/.env.example" "$CFG_DIR/monitor.env"
    echo "   -> $CFG_DIR/monitor.env created, please fill in"
else
    echo "   -> existing monitor.env left untouched"
fi

echo "== PRTG wrapper =="
install -d -m 0755 "$PRTG_DIR"
install -m 0755 "$REPO_DIR/bare-metal/prtg-app-secrets.sh" "$PRTG_DIR/prtg-app-secrets.sh"

echo "== systemd unit for the web GUI (optional, not enabled) =="
cat > /etc/systemd/system/entra-secret-monitor.service <<'EOF'
[Unit]
Description=Entra ID Secret Monitor web service
After=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/entra-secret-monitor/monitor.env
ExecStart=/usr/bin/python3 /opt/entra-secret-monitor/server.py
DynamicUser=yes
SupplementaryGroups=prtgmon
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

cat <<'EOT'

Done. Next steps:

  1. Create a certificate (recommended over a client secret):
     openssl req -x509 -newkey rsa:2048 -nodes -days 1095 \
       -keyout /etc/entra-secret-monitor/tenant.key \
       -out    /etc/entra-secret-monitor/tenant.crt \
       -subj "/CN=entra-secret-monitor"
     chown root:prtgmon /etc/entra-secret-monitor/tenant.*
     chmod 640 /etc/entra-secret-monitor/tenant.*

  2. Upload tenant.crt to the app registration in the Entra portal
     (Certificates & secrets -> Certificates -> Upload certificate)

  3. Fill in /etc/entra-secret-monitor/monitor.env

  4. Add the PRTG SSH user to the group:
     usermod -aG prtgmon <prtg-ssh-user>

  5. Test:
     set -a; . /etc/entra-secret-monitor/monitor.env; set +a
     python3 /opt/entra-secret-monitor/cli.py --format text

  6. Optional web GUI:
     systemctl enable --now entra-secret-monitor

EOT
