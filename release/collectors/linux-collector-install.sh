#!/bin/bash
set -euo pipefail
# BEGIN RELEASE VERIFICATION
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v openssl >/dev/null && command -v sha256sum >/dev/null || { echo 'Requer OpenSSL e sha256sum do sistema para verificar o pacote antes de instalar.' >&2; exit 1; }
cd "$package_dir"
[ -f trusted-release-public.pem ] && [ "$(sha256sum trusted-release-public.pem | cut -d ' ' -f 1)" = 'ce744906a793bb377c33fdd791168a8ea2132ae378419b6caf7995866e7d7669' ] || { echo 'Use o pacote assinado completo; chave pública inválida ou ausente.' >&2; exit 1; }
openssl pkeyutl -verify -pubin -inkey trusted-release-public.pem -rawin -in collectors-manifest.json -sigfile collectors-manifest.sig >/dev/null
expected=$(sed -n 's/.*"collectors.sha256":{"sha256":"\([0-9a-f]*\)".*/\1/p' collectors-manifest.json)
[ "$expected" = "$(sha256sum collectors.sha256 | cut -d ' ' -f 1)" ] || { echo 'Checksum não autenticado.' >&2; exit 1; }
sha256sum -c collectors.sha256 >/dev/null
# END RELEASE VERIFICATION
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
"""One-shot metrics collector. No shell, inbound listener, commands or external dependencies."""
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
import urllib.error


def cpu_snapshot():
    with open('/proc/stat', encoding='ascii') as stream:
        fields = stream.readline().split()
    if not fields or fields[0] != 'cpu':
        raise ValueError('CPU counters unavailable')
    values = [int(value) for value in fields[1:9]]  # exclude guest counters (already counted)
    return sum(values), values[3] + values[4]


def network_snapshot():
    received = sent = 0
    with open('/proc/net/dev', encoding='ascii') as stream:
        for line in stream:
            if ':' not in line:
                continue
            name, data = line.split(':', 1)
            if name.strip() == 'lo':
                continue
            fields = data.split()
            received += int(fields[0])
            sent += int(fields[8])
    return received, sent


def memory_percent():
    with open('/proc/meminfo', encoding='ascii') as stream:
        values = {fields[0].rstrip(':'): int(fields[1]) for line in stream if len(fields := line.split()) >= 2}
    total = values['MemTotal']
    available = values.get('MemAvailable', values.get('MemFree', 0))
    return round(100 * max(0, min(total, total - available)) / total, 2)


def disk_metrics():
    disks, seen = [], set()
    with open('/proc/self/mountinfo', encoding='utf-8') as stream:
        for line in stream:
            left, right = line.rstrip().split(' - ', 1)
            fields, fs = left.split(), right.split()[0]
            if fs not in {'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'zfs', 'f2fs'}:
                continue
            mount = fields[4].replace('\\040', ' ').replace('\\134', '\\')
            if len(mount) > 120 or not re.fullmatch(r'/[a-zA-Z0-9_./ -]*', mount) or fields[2] in seen:
                continue
            try:
                stats = os.statvfs(mount)
            except OSError:
                continue
            if stats.f_blocks <= 0:
                continue
            seen.add(fields[2])
            disks.append({'drive': mount, 'used_percent': round(100 * (stats.f_blocks - stats.f_bfree) / stats.f_blocks, 2)})
            if len(disks) == 32:
                break
    return disks


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        raise ValueError('Redirect refused')


def collect():
    first_cpu, first_network, started = cpu_snapshot(), network_snapshot(), time.monotonic()
    time.sleep(1)
    last_cpu, last_network = cpu_snapshot(), network_snapshot()
    elapsed = max(.1, time.monotonic() - started)
    total = last_cpu[0] - first_cpu[0]
    idle = last_cpu[1] - first_cpu[1]
    cpu = 100 * (1 - idle / total) if total > 0 else 0
    return {'hostname': socket.gethostname(), 'cpu': round(max(0, min(100, cpu)), 2),
            'memory': memory_percent(), 'disks': disk_metrics(),
            'receive_bytes_per_second': max(0, last_network[0] - first_network[0]) / elapsed,
            'send_bytes_per_second': max(0, last_network[1] - first_network[1]) / elapsed}


def main():
    directory = os.environ['CREDENTIALS_DIRECTORY']
    with open(os.path.join(directory, 'config'), encoding='utf-8') as stream:
        config = json.load(stream)
    origin = urllib.parse.urlsplit(config['server'])
    if origin.scheme != 'https' or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment or origin.path not in {'', '/'}:
        raise ValueError('Invalid HTTPS origin')
    with open(os.path.join(directory, 'token'), encoding='ascii') as stream:
        key = stream.read(129).strip()
    if not re.fullmatch(r'[a-zA-Z0-9_-]{32,128}', key):
        raise ValueError('Invalid key')
    url = config['server'].rstrip('/') + '/api/device-metrics/' + urllib.parse.quote(config['ip'], safe='')
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, data=json.dumps(collect(), allow_nan=False).encode('utf-8'),
                                    headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}, method='POST')
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise ValueError('Metrics refused')
    key = None


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as error:
        explanations = {401: 'Chave recusada: gere/confira a chave individual do dispositivo.',
                        403: 'Envio proibido: confira chave, dispositivo e permissoes.',
                        404: 'Dispositivo ou endpoint nao encontrado: confira IP cadastrado e versao do SIEM.',
                        429: 'SIEM limitou as requisicoes: aguarde e tente novamente.'}
        print(explanations.get(error.code, 'SIEM recusou a coleta (HTTP %d).' % error.code), file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLCertVerificationError):
            print('Certificado HTTPS nao confiavel ou invalido: confira dominio, validade, relogio e certificados CA. A verificacao TLS permanece ativa.', file=sys.stderr)
        else:
            print('Conexao HTTPS indisponivel: confira DNS, Tailscale, firewall e porta 8443.', file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Never log exception content, request headers or bearer tokens.
        print('Coleta/envio indisponivel. Verifique HTTPS, chave e acesso ao SIEM.', file=sys.stderr)
        sys.exit(1)

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
