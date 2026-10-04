#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Execute com sudo.'; exit 1; }
cd "$(dirname "$0")/.."
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Arquitetura não suportada'; exit 1;; esac
binary="dist/multipla-siem-linux-$arch"
if [ ! -f "$binary" ]; then
 command -v go >/dev/null || { echo 'Instale Go 1.24 ou posterior (https://go.dev/dl/) e execute novamente.'; exit 1; }
 mkdir -p dist
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "$binary" .
fi
systemd_version=$(systemctl --version | sed -n '1s/[^0-9]*\([0-9]*\).*/\1/p')
if [ ! -f "dist/multipla-update-linux-$arch" ]; then
 command -v go >/dev/null || { echo 'Binario do atualizador ausente; requer Go 1.24+ para compilar.'; exit 1; }
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "dist/multipla-update-linux-$arch" ./cmd/multipla-update
fi
[ "$systemd_version" -ge 247 ] || { echo 'Requer systemd 247+: Debian 12/13 ou Ubuntu 22.04/24.04.'; exit 1; }
getent passwd multipla-siem >/dev/null || useradd --system --home /var/lib/multipla-siem --shell /usr/sbin/nologin multipla-siem
install -d -m 0700 -o multipla-siem -g multipla-siem /var/lib/multipla-siem
install -d -m 0750 -o root -g multipla-siem /etc/multipla-siem
if [ ! -f /etc/multipla-siem/update.json ]; then
 install -m 0600 -o root -g root update.example.json /etc/multipla-siem/update.json
fi
install -m 0755 "$binary" /usr/local/bin/multipla-siem
install -d -m 0755 /usr/local/lib/multipla-siem
install -m 0755 "dist/multipla-update-linux-$arch" /usr/local/lib/multipla-siem/updater
install -m 0755 scripts/multipla-update /usr/local/sbin/multipla-update
if [ ! -f /var/lib/multipla-siem/config.json ]; then
 sed 's|"data_dir": "./data"|"data_dir": "/var/lib/multipla-siem"|' config.example.json >/var/lib/multipla-siem/config.json
 chown multipla-siem:multipla-siem /var/lib/multipla-siem/config.json
 chmod 0600 /var/lib/multipla-siem/config.json
fi
if [ ! -f /etc/multipla-siem/secrets.env ]; then
 umask 077
 { printf 'BOOTSTRAP_TOKEN=%s\n' "$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
 printf 'INGEST_TOKEN=%s\n' "$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
 printf 'PFSENSE_FEED_TOKEN=%s\n' "$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
 printf 'GOOGLE_CLIENT_ID=\nGOOGLE_CLIENT_SECRET=\nGMAIL_USER=\nGMAIL_APP_PASSWORD=\n'
 } >/etc/multipla-siem/secrets.env
 chown root:root /etc/multipla-siem/secrets.env
 chmod 0600 /etc/multipla-siem/secrets.env
fi
if ! grep -q '^BACKUP_ENCRYPTION_KEY=' /etc/multipla-siem/secrets.env; then
 umask 077
 printf 'BACKUP_ENCRYPTION_KEY=%s\n' "$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')" >>/etc/multipla-siem/secrets.env
fi
install -m 0644 deploy/multipla-siem.service /etc/systemd/system/multipla-siem.service
install -m 0755 scripts/multipla-setup /usr/local/sbin/multipla-setup
install -m 0644 deploy/multipla-firstboot.service /etc/systemd/system/multipla-firstboot.service
systemctl daemon-reload
systemctl disable multipla-firstboot.service || true
if [ -f /etc/systemd/system/multipla-siem.service.d/firstboot.conf ]; then
 rm /etc/systemd/system/multipla-siem.service.d/firstboot.conf
 systemctl daemon-reload
fi
systemctl enable multipla-siem
printf '\n  MULTIPLA SIEM\n  Instalação concluída. Execute: sudo multipla-setup\n'
echo 'O assistente gera HTTPS local e não precisa de internet.'
