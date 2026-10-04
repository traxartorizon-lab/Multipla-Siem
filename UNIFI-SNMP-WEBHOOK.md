# Multipla Siem 1.2 — UniFi, SNMP e webhooks

## Portas e atualização

| Uso | Porta padrão | Transporte |
|---|---:|---|
| Painel, login e API | 8443 | HTTPS |
| Syslog / UniFi CEF | 5514 | UDP ou TCP, mensagens por linha |
| Traps SNMP | 1162 | UDP |
| Webhook de entrada | 8443 | POST HTTPS /api/events/webhook |

No painel, abra **Syslog, SNMP e webhook**. Os endereços apresentados usam o host configurado para este servidor. Os receptores SNMP e webhook só aceitam origens habilitadas/cadastradas; por padrão suas configurações estão desativadas. O processo mantém a porta UDP SNMP disponível para ativação pelo painel. Restringa as portas de coleta aos equipamentos na rede de gerência. O receptor syslog não implementa TLS nem autenticação criptográfica: a autorização por IP não impede spoofing em uma rede comprometida. SNMPv3 authPriv oferece autenticação e criptografia.

Para atualizar sem reinstalar o Debian, extraia o pacote novo, entre na pasta multipla-siem e execute como root:

```sh
sh scripts/install.sh
systemctl restart multipla-siem
```

O script preserva dados e configurações e gera a chave de criptografia se estiver ausente. Instalação pela ISO usa binário pronto e funciona offline. O pacote de código inclui vendor/ com GoSNMP v1.45.0 para compilação offline com Go 1.24 ou posterior. Nenhum modelo, agente ou pacote precisa ser baixado para os novos receptores funcionarem.

## UniFi UDM Pro

1. Em **Dispositivos**, cadastre o IP real de origem do UDM Pro com tipo **UniFi / CEF**.
2. No UniFi, abra **Integration → System Logging / SIEM** e selecione **SIEM Server**.
3. Informe o IP do Multipla Siem e a porta **5514**, selecione as categorias e salve. Se houver NAT, cadastre no SIEM o IP que efetivamente chega ao servidor.
4. Confira os eventos no painel. CEF é reconhecido também em dispositivos cadastrados como syslog genérico.

O parser identifica fabricante, produto, ID, nome do evento, severidade, categoria UniFi e IPs src/dst. O log permanece disponível com redação dos formatos conhecidos de credenciais. Valores extraídos de logs são dados do equipamento, não uma prova de identidade do usuário descrito no log.

São gerados alertas para severidade CEF alta (7 a 10), ameaças/honeypot/intrusão na categoria Security, falhas de acesso administrativo e eventos reconhecidos de indisponibilidade de dispositivo, failover WAN e insuficiência PoE. A cobertura depende das categorias e mensagens exportadas pelo firmware; não representa suporte completo a todos os eventos existentes ou futuros. Mensagens CEF inválidas permanecem como logs genéricos, sem confiar na severidade do cabeçalho.

Alertas equivalentes por origem/classe são limitados a um a cada 30 segundos; os logs recebidos continuam gravados. O estado de classificação possui limite de 1.024 entradas. Você pode criar regras adicionais de correlação para UniFi. Esses alertas não publicam bloqueios no pfSense. A exportação de logs SIEM é diferente de NetFlow/IPFIX, que não foi implementado.

Referência oficial: https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration

## SNMP — traps, sem polling

Habilite SNMP e cadastre cada origem na página de receptores. Até 64 equipamentos podem ter credenciais próprias. Um equipamento pode enviar syslog e SNMP simultaneamente, usando cadastros separados. Eventos SNMP recebem o prefixo SNMP no nome da origem para separar seu histórico.

Para **SNMPv3**, use authPriv, autenticação **SHA-256**, privacidade **AES-128**, usuário e engine ID autoritativo do equipamento. O engine ID é hexadecimal de 5 a 32 bytes; o formulário aceita também separadores por dois-pontos. Cada senha precisa ter 12 a 128 caracteres. Configure no equipamento a mesma combinação de usuário, senhas e algoritmos e o destino IP-DO-SIEM:1162. Não são aceitos v3 sem autenticação, sem privacidade, SHA-1 ou outros algoritmos nesta versão.

Para **SNMPv2c**, configure uma community de 16 a 128 caracteres, o IP permitido e o destino UDP 1162. Esse modo transmite a community sem criptografia e não protege a origem contra quem obtiver essa credencial; prefira v3. A community não é gravada como parte do evento recebido.

São aceitos PDUs SNMPv2Trap em v2c/v3. Não há SNMPv1, respostas a informs, descoberta automática, consultas/polling de métricas, escrita SET ou resolução de MIBs de fabricantes. Se o equipamento só enviar traps para a porta 162, será necessário configurar seu destino para 1162 ou fornecer um redirecionamento de porta no ambiente. O processo roda sem privilégio para portas baixas.

Há alertas prontos de **linkDown**, **authenticationFailure**, **coldStart** e **warmStart**. Os demais OIDs e valores são armazenados para regras personalizadas; não se presume a interpretação de falhas de hardware de todos os fabricantes. Exemplo de padrão de uma regra SNMP para linkDown: `SNMP trap OID=\.1\.3\.6\.1\.6\.3\.1\.1\.5\.3 `.

Credenciais ficam criptografadas. Os IPs são conferidos antes da decodificação; há limite de 30 datagramas/minuto por origem e 120/minuto no total para limitar custo de processamento. Acima desses limites, datagramas são descartados. Pacotes têm no máximo 8 KiB e 128 variáveis; os valores individuais são limitados para exibição. A retenção e a quota de logs continuam aplicáveis.

V2c usa deduplicação em memória por 150 segundos. V3 também confere usuário/engine ID, autenticação, privacidade, boots/time com janela de 150 segundos e mantém o histórico dos últimos 128 hashes por origem para rejeitar repetições após reinício. A primeira mensagem autenticada estabelece a referência temporal. Se o equipamento for restaurado de fábrica e perder sua referência de engine boots, recadastre a origem após verificar o equipamento. A interface informa o último trap aceito ou a rejeição; não expõe senhas ou dados criptográficos.

## Webhook — receber alertas

Na página de receptores, habilite entrada, cadastre os IPs exatos dos sistemas emissores e gere o token. O token aparece uma única vez na resposta ao salvar; guarde-o no sistema emissor. Você pode renová-lo, invalidando o anterior. Não use o token de bootstrap, Wazuh, firewall ou Google.

Envie POST HTTPS para /api/events/webhook, com Content-Type application/json e Authorization: Bearer SEU-TOKEN. Exemplo de corpo:

```json
{
  "message": "Falha crítica reportada pelo sistema monitorado",
  "title": "Erro crítico de armazenamento",
  "level": 12,
  "source_ip": "192.168.10.20"
}
```

message é obrigatório, até 16 KiB; title é opcional, até 256 caracteres; level vai de 1 a 15; source_ip é opcional e deve ser IP válido. O servidor atribui o horário, ID e IP real do emissor. Outros campos são rejeitados. Um fornecedor que use outro esquema JSON precisa adaptar o payload para este formato. Emissões são tratadas como alertas e também podem participar de regras de correlação; não acionam bloqueio no pfSense.

O emissor precisa confiar no certificado HTTPS do servidor: instale sua CA/certificado verificado ou utilize certificado da sua infraestrutura. Não desative a verificação TLS do cliente. A autorização exige token e IP cadastrado; não depende de cookie de login ou de uma conta Google. Os limites existentes de API continuam ativos.

## Webhook — enviar notificações

Configure uma URL HTTPS, nível mínimo e segredo HMAC de 32 a 256 caracteres. O destino recebe um JSON com product, version, id, time, device, protocol, source_ip, level e title. Não é enviado o log bruto. O consumidor precisa aceitar esse formato; APIs que exigem esquema próprio, como mensagens de chat, podem precisar de um adaptador.

Cabeçalhos:

- X-Multipla-Event-ID: ID estável do alerta.
- X-Multipla-Timestamp: timestamp Unix em segundos.
- X-Multipla-Signature: sha256= seguido da assinatura hexadecimal.

A assinatura é **HMAC-SHA256(segredo, timestamp + ponto + corpo JSON bruto)**. O consumidor deve verificar a assinatura, conferir a janela temporal (por exemplo, cinco minutos) e deduplicar por ID antes de executar qualquer ação. Em uma repetição de envio, o ID permanece igual e a assinatura pode mudar porque o timestamp é renovado.

Os certificados TLS são verificados, não há proxy automático nem redirecionamentos. O DNS é resolvido antes da conexão e o IP é usado diretamente para evitar uma segunda resolução. Endereços locais, de metadados, multicast e reservados são recusados; um destino privado só é aceito se corresponder ao IP privado exato aprovado no formulário. Se o servidor privado usar certificado de CA interna, essa CA precisa estar no repositório de confiança do Debian/Ubuntu. URLs com usuário, query ou fragmento não são aceitas.

A fila tem 64 posições em memória e até três tentativas por alerta, com timeout por requisição. Resposta 2xx é considerada sucesso. Falhas e fila cheia aparecem no status/auditoria. Não há garantia de entrega exatamente uma vez ou fila persistente: reiniciar pode perder notificações pendentes, mas os alertas gravados continuam no SIEM. Desativar ou alterar o destino interrompe novas tentativas com a configuração anterior. Por padrão, notificações e recepção de webhooks estão desativadas; configurações são globais do servidor e exigem conta administrativa.

## Backups e testes

Backups incluem nomes/IPs e configurações não secretas dos receptores. Não exportam communities, senhas SNMP, tokens, segredo HMAC, URL do webhook de saída (que pode conter credencial no caminho) ou histórico antirreplay. Restaurar desativa os novos canais. Credenciais existentes compatíveis são preservadas na mesma instalação; em outro servidor, cadastre novamente os segredos e o destino. Backups de versões anteriores continuam aceitos pela versão 1.2.

A revisão automatizada usa eventos CEF oficiais de exemplo, traps gerados em v2c/v3, recepção UDP e respostas HTTP simuladas. Ela não substitui a homologação com o UDM Pro, firmware e equipamentos reais da sua rede.
