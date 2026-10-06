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

Use Adicionar ao relatório temporário para salvar o resultado, depois Relatórios → Relatórios temporários de testes. Ping, traceroute e portas também têm esta ação após o término. Cada conta administrativa vê suas próprias entradas, por 72 horas desde o teste; limpeza a cada minuto e ao iniciar. Máximo de 20 entradas por conta/64 no servidor; saída de rede limitada a 16 KiB por entrada. O modelo recebe amostra limitada e dados redigidos; sem modelo, resultados continuam disponíveis. Saída livre do terminal não é importada para evitar captura de segredos.

Exportar relatório para PDF abre a impressão do navegador: escolha Salvar como PDF. PDFs exportados e snapshots em backups completos têm retenção própria e não são apagados por esta rotina. Os relatórios ativos ficam no state.json protegido do SIEM e não integram o backup JSON de configurações. Ao restaurar backup completo, entradas já vencidas são novamente removidas.
