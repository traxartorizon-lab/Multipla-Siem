# Testes de rede

Os testes partem do servidor SIEM e usam somente equipamentos cadastrados. Administradores podem executar; contas de visualização podem consultar os resultados.

Instale as ferramentas no Debian como root:

```sh
apt-get update
apt-get install -y iputils-ping traceroute nmap
```

Testes de portas usam Nmap TCP connect (-sT), sem exigir root ou capacidades de captura no serviço. Informe uma porta, uma lista ou intervalo de até 1024 portas; vazio verifica as 100 portas mais comuns. O tempo máximo é 120 segundos por equipamento. Não são executados scripts NSE, exploração ou detecção agressiva de versões. O resultado mostra os estados e motivos produzidos pelo Nmap; scans interrompidos ou expirados não comprovam ausência de portas abertas. Portas podem ser agrupadas no resumo da saída. O scan pode gerar registros de conexão no equipamento de destino.

Ping no serviço pode exigir configuração de net.ipv4.ping_group_range para o GID do usuário do serviço. Rotas e firewalls devem permitir alcançar os clientes. Classificar por cliente/unidade não cria isolamento de autorização ou rotas.
