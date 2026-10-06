# Testes de rede

Os testes partem do servidor SIEM e usam somente equipamentos cadastrados. Administradores podem executar; contas de visualização podem consultar os resultados.

Instale as ferramentas no Debian como root:

```sh
apt-get update
apt-get install -y iputils-ping traceroute nmap
```

Testes de portas usam Nmap TCP connect (-sT), sem exigir root ou capacidades de captura no serviço. Informe uma porta, uma lista ou intervalo de até 1024 portas; vazio verifica as 100 portas mais comuns. O tempo máximo é 120 segundos por equipamento. Não são executados scripts NSE, exploração ou detecção agressiva de versões. O resultado mostra os estados e motivos produzidos pelo Nmap; scans interrompidos ou expirados não comprovam ausência de portas abertas. Portas podem ser agrupadas no resumo da saída. O scan pode gerar registros de conexão no equipamento de destino.

Ping no serviço pode exigir configuração de net.ipv4.ping_group_range para o GID do usuário do serviço. Rotas e firewalls devem permitir alcançar os clientes. Classificar por cliente/unidade não cria isolamento de autorização ou rotas.

## Consulta guiada de servidores DHCP

Em Dispositivos → Avançado, use Consultar servidores DHCP. Escolha o cadastro por cliente/unidade, digite usuário/senha da conexão, confirme a impressão digital SSH por um canal confiável se solicitado e selecione a interface Ethernet LAN. A consulta usa uma sessão temporária e observa respostas DHCP IPv4 por até 120 segundos, sem gerar solicitações DHCP. Requer permissão para `/usr/sbin/tcpdump` no pfSense. Não enfraqueça permissões de captura para contornar uma falha.

A captura PCAP fica em memória, limitada a 1.000 pacotes e 2 MiB; nenhum pacote bruto vai para logs, backups ou modelo. São extraídos somente IP, Server-ID (quando presente), MAC Ethernet de origem, rede oferecida (quando máscara disponível) e contagem. VLAN Ethernet até duas tags é suportada; interfaces sem Ethernet e pacotes fragmentados/incompletos não são interpretados. DHCPv6 não está incluído. Sem respostas na janela não significa ausência de servidores. Em relay, MAC e IP de origem podem representar o intermediário.

O possível fabricante usa `/usr/share/nmap/nmap-mac-prefixes`, sem consulta externa. MAC administrado localmente não permite atribuir fabricante. OUI identifica um registro de fabricante, não modelo exato ou autorização. Referência: https://nmap.org/book/nmap-mac-prefixes.html.

A consulta DHCP guiada salva o resultado automaticamente no servidor antes da análise, sem depender da janela aberta. Consulte Relatórios → Relatórios temporários de testes. Capturas livres executadas no terminal não são importadas para o relatório. Ping, traceroute e portas também têm esta ação após o término. Cada conta administrativa vê suas próprias entradas, por 72 horas desde o teste; limpeza a cada minuto e ao iniciar. Máximo de 20 entradas por conta/64 no servidor; saída de rede limitada a 16 KiB por entrada. O modelo recebe amostra limitada e dados redigidos; sem modelo, resultados continuam disponíveis. Saída livre do terminal não é importada para evitar captura de segredos.

Exportar relatório para PDF abre a impressão do navegador: escolha Salvar como PDF. PDFs exportados e snapshots em backups completos têm retenção própria e não são apagados por esta rotina. Os relatórios ativos ficam no state.json protegido do SIEM e não integram o backup JSON de configurações. Ao restaurar backup completo, entradas já vencidas são novamente removidas.


## PCs e manutenção (1.2.14)
Administradores podem consultar somente IPs cadastrados. Wake-on-LAN usa MAC unicast e destino IPv4 explícito, UDP 9; configure BIOS/UEFI, energia e placa de rede. Em redes roteadas/Tailscale, normalmente é necessário um encaminhamento ou emissor na LAN. Não há confirmação de boot no envio. Cadastros incluem cliente/unidade e MAC; não incluem senhas.

Consulta de rede: DNS reverso, vizinhança IP local, TCP connect nas portas 22,80,135,139,443,445,3389,5985,5986 e listagem SMB anônima (SMB2/3). Compartilhamentos protegidos não serão enumerados. MAC remoto não pode ser obtido pela internet ou por uma rota apenas. Instale os utilitários no servidor, se ausentes: `apt install nmap smbclient iproute2`. Consultas têm limite de tempo, saída e duas execuções simultâneas; não usam shell ou credenciais.

Para habilitar o botão de reinício desta VM, após atualizar, execute como root: `multipla-siem -enable-server-reboot`. Requer polkit (`apt install polkitd` se ausente). O binário assinado instala uma regra fixa para a conta multipla-siem executar exclusivamente org.freedesktop.login1.reboot. SIEM continua sem root, sem sudo e com NoNewPrivileges. Nenhum comando arbitrário ou reinício de outras máquinas. Desabilite removendo `/etc/polkit-1/rules.d/49-multipla-reboot.rules` como root. A ação no painel exige administrador, CSRF, confirmação digitada e gravação prévia de auditoria.

A distribuição da dashboard usa logs originais das últimas 24h, com consulta cacheada por um minuto. A leitura é limitada a 64 MiB/20 segundos e informa dados parciais ou dias ausentes. O gráfico de atividade mantém a amostra dos últimos 30 minutos. Alertas ficam recolhidos em uma área com rolagem interna; nenhum log é descartado ao recolher.


## Coletor Windows e métricas
Cada PC cadastrado pode gerar sua própria chave em Dispositivos (somente administrador). A chave aparece uma vez, é armazenada no servidor somente como SHA-256 e autoriza apenas envio de métricas daquele IP cadastrado. Regenerar revoga a anterior; remover/renomear o cadastro também revoga. Revogação imediata está disponível no card. Chaves não podem abrir sessões ou alterar configuração. Métricas somente leitura estão disponíveis aos perfis autorizados; chaves não aparecem em snapshots nem relatórios.

Baixe windows-collector.ps1 pelo card. Abra PowerShell como administrador e execute: `powershell -NoProfile -File .\windows-collector.ps1 -Install -Server "https://DOMINIO:8443" -DeviceIP "IP_CADASTRADO"`. Cole a chave no prompt protegido. Requer certificado HTTPS confiável no Windows; nenhuma validação TLS é desabilitada. Quando o arquivo tiver marca de download, revise o código e desbloqueie somente esse arquivo se a política da organização permitir; não desabilite a política global. A tarefa executa como LocalService sem privilégios administrativos, a cada minuto, sem porta de entrada ou instruções remotas. A pasta em ProgramData permite escrita somente a Administradores/SYSTEM e leitura a LocalService. Token protegido por DPAPI LocalMachine, nunca em argumentos ou logs. Não é armazenada senha do Windows, domínio ou SSH.

São enviados hostname, CPU%, memória%, ocupação de discos locais e somas de bytes/s das interfaces. Rede é agregada e pode incluir interfaces virtuais; não há captura de conteúdo, inventário de arquivos ou senhas. Só o último conjunto é mantido; não é uma série histórica como Prometheus/Grafana. Após três minutos sem envio, o card indica métricas desatualizadas. O agente e CIM devem ser validados em um PC Windows piloto antes do rollout; políticas locais podem negar coleta à conta LocalService. Para parar: `powershell -NoProfile -File .\windows-collector.ps1 -Uninstall`, como administrador; revogue também no SIEM.


Coletor Linux: selecione Linux no cadastro e baixe o instalador no card do dispositivo. Execute `sudo bash ./linux-collector-install.sh`; informe HTTPS, IP cadastrado e chave individual. Requer Python 3.8+ e systemd 247+ (Debian 12/13, Ubuntu 22.04/24.04; outras distribuições precisam de validação). A coleta roda como usuário dinâmico restrito, sem portas de entrada, com credenciais temporárias do systemd, TLS validado e redirecionamentos bloqueados. CPU/memória/rede via /proc e discos locais de sistemas de arquivos suportados. Revogue a chave no SIEM; `sudo bash ./linux-collector-install.sh --uninstall` desativa o timer e preserva arquivos para revisão. Validar a primeira instalação em uma máquina piloto.
