#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || exit 1
umask 077
sources=/etc/apt/sources.list.d/multipla-debian.sources
cat >"$sources" <<'EOF'
Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://security.debian.org/debian-security
Suites: trixie-security
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
# Remove stale CD sources after all required packages have been installed.
if [ -f /etc/apt/sources.list ]; then
 sed -i '/^[[:space:]]*deb[[:space:]]\+cdrom:/s/^/# /' /etc/apt/sources.list
fi
for f in /etc/apt/sources.list.d/*.sources; do
 [ -f "$f" ] || continue
 if grep -Eq '^URIs:[[:space:]]*cdrom:' "$f"; then
  mv "$f" "$f.disabled"
 fi
done
log=/var/log/multipla-install-updates.log
if timeout 120 apt-get -o Dir::Etc::sourcelist="$sources" -o Dir::Etc::sourceparts=- -o Acquire::Retries=0 -o Acquire::https::Timeout=10 -o APT::Update::Error-Mode=any update >"$log" 2>&1; then
 echo 'Instalando atualizacoes Debian...'
 if DEBIAN_FRONTEND=noninteractive apt-get -o Dir::Etc::sourcelist="$sources" -o Dir::Etc::sourceparts=- -o Acquire::Retries=0 -o Acquire::https::Timeout=15 -o Dpkg::Options::=--force-confold --with-new-pkgs -y upgrade >>"$log" 2>&1; then
  echo 'Atualizacoes concluidas.'
 else
  echo 'Atualizacoes incompletas. Consulte /var/log/multipla-install-updates.log.'
 fi
else
 echo 'Repositorios indisponiveis; continuando com os pacotes da ISO.'
fi
