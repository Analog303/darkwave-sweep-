#!/usr/bin/env bash
# Darkwave Sweep – Installer (Debian/Ubuntu, ein Host inkl. Artex)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OPT=/opt/dwsweep
VENV=/opt/dwvenv
DW=/var/lib/dw
[[ $EUID -eq 0 ]] || { echo "als root ausführen"; exit 1; }
. /etc/os-release
[[ "${ID:-}" =~ ^(debian|ubuntu)$ ]] || { echo "nur Debian/Ubuntu"; exit 1; }

echo "== Darkwave Sweep Installation =="
while :; do
  read -rsp "Web-Interface Passwort: " PW; echo
  read -rsp "Passwort wiederholen:   " PW2; echo
  [[ "$PW" == "$PW2" ]] || { echo "stimmt nicht überein"; continue; }
  (( ${#PW} >= 8 )) && break || echo "mindestens 8 Zeichen"
done

echo "[1/8] Pakete"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip masscan sqlmap git curl openssl ca-certificates docker.io docker-compose-v2 docker-buildx unzip >/dev/null 2>&1 || \
apt-get install -y -qq python3 python3-venv python3-pip masscan sqlmap git curl openssl ca-certificates docker.io docker-compose docker-buildx unzip >/dev/null

PUBIP=$(curl -sS -m 6 https://api.ipify.org || hostname -I | awk '{print $1}')
[[ -n "$PUBIP" ]] || { echo "öffentliche IP nicht ermittelbar"; exit 1; }

echo "[2/8] Dateien"
mkdir -p "$OPT" "$DW"
cp -a "$DIR/dwsweep/." "$OPT/"
install -m 0644 "$OPT/dash/../log4j.service" /etc/systemd/system/log4j.service
install -m 0644 "$OPT/sqlmap.service" /etc/systemd/system/sqlmap.service
sed -i "s/5\.230\.41\.44/$PUBIP/g" "$OPT"/dwscan/*.py

echo "[3/8] Python-Umgebung"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q flask gunicorn requests urllib3

echo "[4/8] Zugangsdaten"
printf '%s' "$PW" > "$DW/dash.pass"; chmod 600 "$DW/dash.pass"
[[ -f "$DW/secret" ]] || openssl rand -hex 32 > "$DW/secret"; chmod 600 "$DW/secret"
printf '%s\n' "$PW" > /root/darkwave-web-password.txt; chmod 600 /root/darkwave-web-password.txt

echo "[5/8] Dienste"
cat > /etc/systemd/system/dwdash.service <<U
[Unit]
Description=Darkwave dashboard
After=network.target
[Service]
WorkingDirectory=$OPT/dash
ExecStart=$VENV/bin/gunicorn -w 2 --threads 16 --worker-class gthread -b 0.0.0.0:9090 app:app
Restart=always
[Install]
WantedBy=multi-user.target
U
cat > /etc/systemd/system/dwsweep.service <<U
[Unit]
Description=Darkwave sweep lane1
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$OPT
Environment=DW_RANGES=1
ExecStart=$VENV/bin/python $OPT/run_sweep.py
Restart=on-failure
RestartSec=5
Nice=5
[Install]
WantedBy=multi-user.target
U
cat > /etc/systemd/system/dwsweep2.service <<U
[Unit]
Description=Darkwave sweep lane2
After=network-online.target
[Service]
Type=simple
WorkingDirectory=$OPT
Environment=DW_DIR=/var/lib/dw2
Environment=DW_CONF=$OPT/sweep2.conf
Environment=DW_RANGES=1
ExecStart=$VENV/bin/python $OPT/run_sweep.py
Restart=on-failure
RestartSec=5
Nice=6
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload
systemctl enable -q dwdash log4j sqlmap
systemctl restart dwdash
systemctl restart log4j sqlmap || true

echo "[6/8] Artex (Port 8787)"
bash "$OPT/artex_up.sh" || echo "Artex-Installation fehlgeschlagen, manuell: $OPT/artex_up.sh"

echo "[7/8] Firewall"
if command -v ufw >/dev/null; then ufw allow 9090/tcp >/dev/null 2>&1 || true; ufw allow 8787/tcp >/dev/null 2>&1 || true; fi

echo "[8/8] Fertig"
IP="$PUBIP"
sleep 3
TOK=$(docker logs artex-artex-1 2>&1 | grep -o 'Setup token.*: [a-f0-9]*' | tail -1 | awk '{print $NF}' || true)
cat <<EOT

Darkwave läuft.
  Web-Interface : http://$IP:9090   (Passwort: siehe /root/darkwave-web-password.txt)
  Artex          : http://$IP:8787
$( [[ -n "${TOK:-}" ]] && echo "  Artex Setup-Token: $TOK  (Seite /setup im Artex-UI)" )

Scan ist noch gestoppt: systemctl start dwsweep dwsweep2
Modus/Ranges/Ports: Web-Interface, Leiste oben.
EOT
