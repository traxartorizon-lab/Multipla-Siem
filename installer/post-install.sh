#!/bin/sh
set -eu
# Executed by Debian Installer only inside its selected installation target.
[ -d /target/etc ] && [ -d /target/var ] || exit 1
mkdir -p /target/opt/multipla-siem
tar -xzf /cdrom/multipla/payload.tar.gz -C /target/opt/multipla-siem
cd /target/opt/multipla-siem
sha256sum -c manifest.sha256
in-target /bin/sh /opt/multipla-siem/scripts/install.sh
cat >/target/etc/motd <<'EOF'
MULTIPLA SIEM
Acesse https://IP-DO-SERVIDOR:8443.
O primeiro boot configura HTTPS automaticamente e mostra o código de cadastro no console.
Cadastre sua conta e os dispositivos pelo navegador. Google SSO é opcional.
EOF
chmod 0644 /target/etc/motd
mkdir -p /target/etc/ssh/sshd_config.d
cat >/target/etc/ssh/sshd_config.d/00-multipla.conf <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
EOF
in-target /bin/sh -c 'mkdir -p /run/sshd && chmod 0755 /run/sshd && /usr/sbin/sshd -t'
in-target systemctl enable ssh
in-target /bin/sh /opt/multipla-siem/scripts/install-updates.sh || true
