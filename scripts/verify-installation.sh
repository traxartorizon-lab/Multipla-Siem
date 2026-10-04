#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Execute como root.'; exit 1; }
[ "$(stat -c '%U:%G:%a' /etc/multipla-siem/secrets.env)" = 'root:root:600' ]
[ "$(stat -c '%U:%G:%a' /var/lib/multipla-siem/config.json)" = 'multipla-siem:multipla-siem:600' ]
[ "$(stat -c '%U:%G:%a' /var/lib/multipla-siem)" = 'multipla-siem:multipla-siem:700' ]
/usr/local/bin/multipla-siem -version
env CREDENTIALS_DIRECTORY=/etc/multipla-siem /usr/local/bin/multipla-siem -config /var/lib/multipla-siem/config.json -check
echo 'MULTIPLA_INSTALL_OK: binário, configuração, credenciais e permissões verificados'
