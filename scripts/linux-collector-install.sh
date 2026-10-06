#!/bin/bash
set -euo pipefail
# Installer only: collector executes as a restricted dynamic systemd user.
[[ $(id -u) == 0 ]] || { echo 'Execute o instalador como root (sudo bash linux-collector-install.sh).'; exit 1; }
command -v python3 >/dev/null || { echo 'Requer Python 3.8+.'; exit 1; }
command -v systemctl >/dev/null || { echo 'Requer Linux com systemd 247+.'; exit 1; }
systemd_version=$(systemctl --version | sed -n '1s/[^0-9]*\([0-9]*\).*/\1/p')
[[ $systemd_version -ge 247 ]] || { echo 'Requer systemd 247+ (Debian 12/13, Ubuntu 22.04/24.04).'; exit 1; }
if [[ ${1:-} == --uninstall ]]; then
 systemctl disable --now multipla-metrics.timer
 echo 'Coletor desativado. Revogue a chave no SIEM. Arquivos privados preservados para revisao/remocao pelo administrador.'
 exit 0
fi
read -r -p 'Origem HTTPS do SIEM (https://dominio:8443): ' collector_server
read -r -p 'IP exatamente como cadastrado no SIEM: ' collector_ip
python3 - "$collector_server" "$collector_ip" <<'VALIDATE'
import ipaddress, sys, urllib.parse
url = urllib.parse.urlsplit(sys.argv[1])
if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in {'', '/'} or url.query or url.fragment:
    raise SystemExit('Origem HTTPS invalida')
ipaddress.ip_address(sys.argv[2])
VALIDATE
collector_conf=/etc/multipla-siem-collector
collector_code=/usr/local/lib/multipla-siem-collector
[[ ! -e $collector_conf && ! -L $collector_conf && ! -e $collector_code && ! -L $collector_code ]] || { echo 'Instalacao existente: revise/remova as pastas como root antes de reinstalar.'; exit 1; }
[[ ! -e /etc/systemd/system/multipla-metrics.service && ! -L /etc/systemd/system/multipla-metrics.service && ! -e /etc/systemd/system/multipla-metrics.timer && ! -L /etc/systemd/system/multipla-metrics.timer ]] || { echo 'Unidades existentes: revise antes de instalar.'; exit 1; }
install -d -m 0700 -o root -g root "$collector_conf"
install -d -m 0755 -o root -g root "$collector_code"
umask 077
read -r -s -p 'Chave individual do coletor: ' collector_key
printf '\n'
[[ $collector_key =~ ^[a-zA-Z0-9_-]{32,128}$ ]] || { echo 'Chave invalida.'; unset collector_key; exit 1; }
printf '%s' "$collector_key" >"$collector_conf/token"
unset collector_key
python3 - "$collector_server" "$collector_ip" "$collector_conf/config.json" <<'CONFIG'
import json, sys
with open(sys.argv[3], 'x', encoding='utf-8') as file:
    json.dump({'server':sys.argv[1].rstrip('/'), 'ip':sys.argv[2]}, file)
CONFIG
cat >"$collector_code/collector.py" <<'COLLECTOR'
__COLLECTOR_BODY__
COLLECTOR
chmod 0644 "$collector_code/collector.py"
cat >/etc/systemd/system/multipla-metrics.service <<'SERVICE'
[Unit]
Description=Multipla SIEM - metricas locais por HTTPS
After=network-online.target
[Service]
Type=oneshot
DynamicUser=yes
LoadCredential=config:/etc/multipla-siem-collector/config.json
LoadCredential=token:/etc/multipla-siem-collector/token
ExecStart=/usr/bin/python3 -I /usr/local/lib/multipla-siem-collector/collector.py
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
TimeoutStartSec=25
MemoryMax=96M
TasksMax=16
SERVICE
cat >/etc/systemd/system/multipla-metrics.timer <<'TIMER'
[Unit]
Description=Multipla SIEM - coleta de metricas a cada minuto
[Timer]
OnBootSec=1min
OnUnitInactiveSec=1min
RandomizedDelaySec=5s
[Install]
WantedBy=timers.target
TIMER
chmod 0644 /etc/systemd/system/multipla-metrics.service /etc/systemd/system/multipla-metrics.timer
systemctl daemon-reload
systemctl enable --now multipla-metrics.timer
echo 'Coletor instalado. A chave nao aparece em argumentos, variaveis de ambiente ou logs. Verifique as metricas no SIEM apos a primeira coleta.'
