# Instalação — Multipla Siem 1.2.2

A ISO amd64 inclui Debian 13.7, o binário Multipla Siem e a configuração inicial. Não precisa baixar pacotes durante a instalação. É uma imagem personalizada, construída a partir da ISO oficial cuja assinatura e SHA512 foram verificados. Compare também a SHA256 da imagem entregue com o arquivo `.iso.sha256`.

## Instalar em VM ou servidor

1. Faça backup do servidor. Para homologação, crie uma VM com 2 GB de RAM, 2 vCPU, disco novo de pelo menos 16 GB e conecte a ISO. Esses valores são uma sugestão inicial, não um dimensionamento por volume de logs.
2. Inicie em BIOS ou UEFI e selecione a instalação Multipla Siem. Há instalador gráfico e opção de texto.
3. Escolha idioma, teclado, rede, nome da máquina, senha forte de root e um usuário normal no instalador Debian. Esse usuário normal será usado no SSH; depois use `su -` para administrar. A imagem não contém senha padrão, chaves privadas, credenciais Google ou seleção automática de disco.
4. Selecione cuidadosamente o disco e confirme o particionamento. A instalação pode apagar o disco escolhido. O produto não confirma a formatação por você.
5. Ao terminar, retire a ISO e reinicie. O primeiro boot detecta o IP e inicia o HTTPS automaticamente. O console mostra o endereço, certificado e código exclusivo de cadastro.
6. Abra `https://IP:8443`, confira a impressão digital do certificado mostrado no console e use o código exclusivo para cadastrar sua conta local.
7. Entre com sua conta local e cadastre os dispositivos pelo painel. Google SSO é opcional e pode ser configurado posteriormente. O assistente multipla-setup permanece disponível para manutenção e migração de instalações antigas.

O boot e o cabeçalho gráfico exibem **Multipla Siem**. As etapas de sistema usam o instalador Debian; o cadastro administrativo e de dispositivos é realizado pelo navegador.

## Internet e atualizações

A base e o SSH vêm da mídia local. Ao final, o instalador tenta buscar e aplicar atualizações Debian oficiais. Sem internet, continua com a base local; não pede confirmação de atualização. O APT fica configurado para os repositórios HTTPS oficiais, sem depender do CD-ROM removido. O log é /var/log/multipla-install-updates.log. Consulte UPDATES.md para atualizar versões do SIEM.

Google SSO e notificações Gmail precisam de internet durante o uso e de credenciais próprias configuradas pelo administrador. O recebimento de syslog e o dashboard funcionam na rede local sem esses serviços. O token de configuração permite o primeiro acesso offline; não existe senha administrativa permanente embutida.

## Instalação sobre Debian/Ubuntu existente

Extraia `multipla-siem.zip`, execute `sudo sh scripts/install.sh` e depois `sudo systemctl start multipla-siem`. Incluímos binários Linux amd64 e arm64. O serviço requer systemd 247 ou posterior. A instalação não instala Wazuh Manager; o conector opcional deve ser instalado em um Manager existente.

Configuração e dados ficam em `/var/lib/multipla-siem`; segredos e TLS em `/etc/multipla-siem`. Consulte README.md para Google, Gmail, Proxmox e pfSense. Proteja portas de administração e syslog na rede apropriada. Comece com a resposta automática em simulação e valide o alias do firewall antes de ativar bloqueios.

## Verificar

`sudo sh /opt/multipla-siem/scripts/verify-installation.sh` verifica versão, configuração e permissões após instalar pela ISO. Para instalação manual, execute o mesmo script a partir do pacote extraído. Verifique também `systemctl status multipla-siem` e `journalctl -u multipla-siem`.

A imagem é destinada à homologação inicial. BIOS e UEFI foram testados em QEMU sem interface de rede. O resultado da instalação completa está registrado em SECURITY-REVIEW.md. Testes em hardware físico e integrações com suas contas e dispositivos ainda precisam ser feitos.


## Versão 1.1.1: primeiro acesso pelo navegador

Na ISO 1.1.1, o primeiro boot detecta o primeiro IPv4 ativo, gera um certificado exclusivo e inicia HTTPS em 0.0.0.0:8443 automaticamente. Configure a rede no instalador Debian. No console de login aparece o endereço, a impressão digital do certificado e um código exclusivo de cadastro. Abra o endereço, informe o código e cadastre email e senha local de pelo menos 14 caracteres. Não é a senha do usuário Debian. Não há senha compartilhada nem necessidade de executar multipla-setup em uma instalação nova.

O código vale por até 24 horas de execução no modo de primeiro boot, só pode ser usado uma vez e exige acesso ao console físico/da VM. Ele não aparece no journal do serviço. Após o cadastro, entre com email e senha local mesmo offline e cadastre os dispositivos na página Dispositivos. As senhas são protegidas com PBKDF2-HMAC-SHA256, 600.000 iterações, sal aleatório e limite de verificações simultâneas. Não são incluídas nos backups de configuração.

Google SSO é opcional e exige credenciais de seu próprio projeto Google Cloud e domínio HTTPS aceito pelo Google. IPs privados não são aceitos como callback OAuth web. Em Configurações, use “Configurar Google SSO” para informar o Client ID e o Client Secret: ficam criptografados e não são devolvidos pela API nem exportados. O callback aparece no formulário. Para trocar o IP por domínio e certificado apropriado em uma instalação existente, o assistente multipla-setup continua disponível para manutenção.

Atualizar pelo pacote preserva configurações existentes: execute sh scripts/install.sh como root e systemctl restart multipla-siem. Para cadastrar a primeira conta local numa instalação já configurada, use o acesso inicial disponível; se já foi consumido/expirou, multipla-setup renova o token. Essa etapa de transição não se aplica às instalações novas pela ISO 1.1.1.
