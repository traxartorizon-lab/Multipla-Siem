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
echo 'Pacote autenticado. Linux: sudo bash ./linux-collector-install.sh'
