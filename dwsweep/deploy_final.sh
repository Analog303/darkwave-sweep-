#!/bin/bash
set -e
cd /opt/dwsweep
tar xzf /tmp/F1.tgz; tar xzf /tmp/F2.tgz; (cd dash && tar xzf /tmp/F3.tgz)
mkdir -p bin keys
[ -f keys/dw ] || ssh-keygen -t ed25519 -N "" -C dw@jump -f /opt/dwsweep/keys/dw >/dev/null
cp log4j.service sqlmap.service /etc/systemd/system/ 2>/dev/null || true
cp /tmp/ports.txt /opt/dwsweep/ports.txt
P=$(cat /opt/dwsweep/ports.txt)
printf '{"rate": 8000, "workers": 180, "ports": "%s", "batch": 1, "seed": 20261123, "timeout": 8, "mib": 0.8}\n' "$P" > /opt/dwsweep/sweep.conf
find . -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
systemctl daemon-reload
command -v sqlmap >/dev/null 2>&1 || (apt-get install -y -qq sqlmap >/dev/null 2>&1 || pip3 install -q sqlmap >/dev/null 2>&1)
systemctl enable --now log4j sqlmap >/dev/null 2>&1 || true
systemctl daemon-reload; systemctl restart log4j sqlmap 2>/dev/null || true
systemctl restart dwdash
systemctl stop dwsweep nuclei 2>/dev/null || true
cd /var/lib/dw && rm -f state.json state.json.tmp resume.txt paused.conf scan.lst targets.txt nuclei.jsonl nuc.idx STOP log4j.log
cd /opt/dwsweep/loot && rm -f audit.jsonl loot.txt loot.jsonl
systemctl start dwsweep nuclei
echo FINAL_DEPLOYED
