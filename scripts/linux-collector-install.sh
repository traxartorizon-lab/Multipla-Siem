#!/bin/bash
set -euo pipefail
# Installer only: collector executes as a restricted dynamic systemd user.
[[ $(id -u) == 0 ]] || { echo 'Execute o instalador como root (sudo bash linux-collector-install.sh).'; exit 1; }
mode=${1:-install}
case "$mode" in install|--repair|--verify|--uninstall) ;; *) echo 'Uso: sudo bash linux-collector-install.sh [--verify|--repair|--uninstall]'; exit 1;; esac
stage='verificacao inicial'
trap 'echo "Falha na etapa: $stage. A instalacao nao foi confirmada. Corrija a causa e execute --repair ou --verify." >&2' ERR
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || { echo 'Requer Linux iniciado com systemd; execute no host/VM, nao em container sem systemd.'; exit 1; }
systemd_version=$(systemctl --version | sed -n '1s/[^0-9]*\([0-9]*\).*/\1/p')
[[ $systemd_version -ge 247 ]] || { echo 'Requer systemd 247+. O instalador nao atualiza o sistema operacional.'; exit 1; }
if [[ $mode == --uninstall ]]; then
 systemctl disable --now multipla-metrics.timer
 echo 'Coletor desativado. Revogue a chave no SIEM. Arquivos privados preservados.'
 exit 0
fi
echo '[1/5] Verificando dependencias...'
stage='dependencias'
if ! command -v python3 >/dev/null || ! python3 -c 'import sys,ssl,json,urllib.request; assert sys.version_info >= (3,8); ssl.create_default_context()' || [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
 if [[ $mode == --verify ]]; then echo 'Dependencias ausentes. Execute novamente com --repair.'; exit 1; fi
 command -v apt-get >/dev/null || { echo 'Instale Python 3.8+ e certificados CA pelo gerenciador desta distribuicao.'; exit 1; }
 # Only required packages; never a distribution upgrade or third-party repository.
 apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update
 apt-get -o Acquire::Retries=2 install -y python3 ca-certificates
fi
python3 -c 'import sys,ssl,json,urllib.request; assert sys.version_info >= (3,8); ssl.create_default_context()'
collector_conf=/etc/multipla-siem-collector
collector_code=/usr/local/lib/multipla-siem-collector
if [[ $mode == --verify ]]; then
 echo '[2/5] Validando instalacao existente...'
 systemd-analyze verify /etc/systemd/system/multipla-metrics.service /etc/systemd/system/multipla-metrics.timer
 echo '[3/5] Enviando coleta de teste pelo servico restrito...'
 systemctl reset-failed multipla-metrics.service 2>/dev/null || true
 systemctl start multipla-metrics.service
 [[ $(systemctl show multipla-metrics.service -p Result --value) == success ]]
 echo '[4/5] Verificando agendamento...'
 systemctl is-enabled --quiet multipla-metrics.timer
 systemctl is-active --quiet multipla-metrics.timer
 echo '[5/5] Verificacao concluida: coleta aceita pelo SIEM e timer ativo.'
 exit 0
fi
if [[ $mode != --repair ]]; then
echo '[2/5] Configurando dispositivo e chave... '
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
[[ ! -e $collector_conf && ! -L $collector_conf && ! -e $collector_code && ! -L $collector_code ]] || { echo 'Instalacao existente: execute com --verify para testar ou --repair para reparar.'; exit 1; }
[[ ! -e /etc/systemd/system/multipla-metrics.service && ! -L /etc/systemd/system/multipla-metrics.service && ! -e /etc/systemd/system/multipla-metrics.timer && ! -L /etc/systemd/system/multipla-metrics.timer ]] || { echo 'Unidades existentes: revise antes de instalar.'; exit 1; }
umask 077
read -r -s -p 'Chave individual do coletor: ' collector_key
printf '\n'
[[ $collector_key =~ ^[a-zA-Z0-9_-]{32,128}$ ]] || { echo 'Chave invalida.'; unset collector_key; exit 1; }
install -d -m 0700 -o root -g root "$collector_conf"
install -d -m 0755 -o root -g root "$collector_code"
printf '%s' "$collector_key" >"$collector_conf/token"
unset collector_key
python3 - "$collector_server" "$collector_ip" "$collector_conf/config.json" <<'CONFIG'
import json, sys
with open(sys.argv[3], 'x', encoding='utf-8') as file:
    json.dump({'server':sys.argv[1].rstrip('/'), 'ip':sys.argv[2]}, file)
CONFIG
else
 echo '[2/5] Reparando somente os arquivos do coletor...'
 # Refuse symlinks and files owned by another user before any root write.
 for target in "$collector_conf" "$collector_code" "$collector_conf/config.json" "$collector_conf/token" "$collector_code/collector.py" /etc/systemd/system/multipla-metrics.service /etc/systemd/system/multipla-metrics.timer; do
  [[ ! -L $target ]] || { echo 'Reparo recusado: caminho simbolico.'; exit 1; }
  if [[ -e $target ]]; then [[ $(stat -c %u "$target") == 0 ]] || { echo 'Reparo recusado: arquivo nao pertence ao root.'; exit 1; }; fi
 done
 [[ -f $collector_conf/config.json && -f $collector_conf/token ]] || { echo 'Configuracao incompleta. Revise a instalacao antes de reparar.'; exit 1; }
 python3 - "$collector_conf" <<'CHECK_CONFIG'
import ipaddress,json,pathlib,re,sys,urllib.parse
p=pathlib.Path(sys.argv[1]);c=json.loads((p/'config.json').read_text());u=urllib.parse.urlsplit(c['server'])
assert u.scheme=='https' and u.hostname and not u.username and not u.password and u.path in ('','/') and not u.query and not u.fragment
ipaddress.ip_address(c['ip'])
assert re.fullmatch(r'[a-zA-Z0-9_-]{32,128}',(p/'token').read_text().strip())
CHECK_CONFIG
 systemctl stop multipla-metrics.timer || true
 systemctl stop multipla-metrics.service || true
 install -d -m 0755 -o root -g root "$collector_code"
 chmod 0700 "$collector_conf"
 chmod 0600 "$collector_conf/config.json" "$collector_conf/token"
fi
stage='arquivos e unidades do coletor'
echo '[3/5] Instalando e validando servico restrito...'
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
python3 - "$collector_code/collector.py" <<'SYNTAX'
import ast,pathlib,sys
ast.parse(pathlib.Path(sys.argv[1]).read_text())
SYNTAX
systemd-analyze verify /etc/systemd/system/multipla-metrics.service /etc/systemd/system/multipla-metrics.timer
systemctl daemon-reload
stage='primeira coleta HTTPS'
echo '[4/5] Enviando primeira coleta de teste ao SIEM...'
systemctl reset-failed multipla-metrics.service 2>/dev/null || true
accepted=false
for attempt in 1 2 3; do
 if systemctl start multipla-metrics.service && [[ $(systemctl show multipla-metrics.service -p Result --value) == success ]]; then accepted=true; break; fi
 echo "Tentativa $attempt falhou. Diagnostico do coletor:"
 journalctl -u multipla-metrics.service -n 8 --no-pager
 if [[ $attempt -lt 3 ]]; then sleep 3; systemctl reset-failed multipla-metrics.service 2>/dev/null || true; fi
done
[[ $accepted == true ]] || { echo 'Primeira coleta nao aceita. Arquivos preservados; timer nao ativado. Confira HTTPS 8443 no Tailscale, certificado, IP e chave. Apos corrigir, execute --repair.'; exit 1; }
stage='agendamento'
echo '[5/5] Ativando coleta automatica a cada minuto...'
systemctl enable --now multipla-metrics.timer
systemctl is-enabled --quiet multipla-metrics.timer
systemctl is-active --quiet multipla-metrics.timer
echo 'SUCESSO: primeira coleta aceita pelo SIEM; servico validado e timer ativo.'
echo 'Coletor instalado. A chave nao aparece em argumentos, variaveis de ambiente ou logs. Verifique as metricas no SIEM apos a primeira coleta.'
