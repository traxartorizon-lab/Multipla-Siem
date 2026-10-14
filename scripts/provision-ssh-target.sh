#!/bin/bash
set -euo pipefail
# Run on the selected Linux target after verifying the signed bootstrap package.
# The public CA key is transferred over a separate verified administrative channel.
[[ $(id -u) == 0 ]] || { echo 'Requer root no destino Linux.'; exit 1; }
[[ $# == 2 ]] || { echo 'Uso: provision-ssh-target.sh IP_EXATO_DO_DESTINO ARQUIVO_CA_PUBLICA'; exit 1; }
target=$1
ca_file=$2
python3 - "$target" <<'PY'
import ipaddress,sys
assert str(ipaddress.ip_address(sys.argv[1]))==sys.argv[1]
PY
[[ -f $ca_file && ! -L $ca_file ]] || { echo 'CA pública regular obrigatória.'; exit 1; }
ssh-keygen -lf "$ca_file"
read -r -p 'Confira a impressão digital por outro canal. Digite CONFIRMAR para confiar na CA: ' approved
[[ $approved == CONFIRMAR ]] || exit 1
getent passwd multipla-ops >/dev/null || useradd --create-home --shell /bin/bash multipla-ops
# No sudo group or administrative privileges are added.
install -m 0644 -o root -g root "$ca_file" /etc/ssh/multipla-siem-ca.pub
install -d -m 0755 /etc/ssh/multipla-principals
printf 'multipla-ops@%s\n' "$target" >/etc/ssh/multipla-principals/multipla-ops
chmod 0644 /etc/ssh/multipla-principals/multipla-ops
install -d -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/45-multipla-delegated.conf <<'EOF'
TrustedUserCAKeys /etc/ssh/multipla-siem-ca.pub
LogLevel VERBOSE
Match User multipla-ops
    AuthorizedPrincipalsFile /etc/ssh/multipla-principals/%u
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserEnvironment no
Match all
EOF
sshd -t
systemctl reload ssh
echo 'Delegação configurada. Sessões usam certificados curtos e são registradas pelo sshd neste host.'
