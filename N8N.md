# Integração Multipla SIEM → n8n

## Configuração guiada

Em **Syslog, SNMP e webhook → Integração com n8n**, escolha **n8n Cloud** ou **No meu servidor**. Não é necessária senha da conta n8n nem chave administrativa da API.

1. Baixe o fluxo pelo botão do painel. No editor n8n, importe o arquivo JSON. Cada download gera um caminho próprio para evitar colisões entre instalações.
2. Gere um token no SIEM. No nó **Receber alerta Multipla**, escolha a autenticação **Header Auth**, crie uma credencial com **Name = X-Multipla-Token** e **Value = token**, e selecione-a no nó. Não altere a autenticação para None. O token fica no armazenamento de credenciais do n8n e cifrado no estado do SIEM; não acompanha o fluxo exportado nem os backups de configuração.
3. Publique/ative o fluxo. Copie sua **Production URL** HTTPS do Webhook, contendo `/webhook/`. A URL `/webhook-test/` só funciona temporariamente e é rejeitada pelo SIEM.
4. Cole a URL no SIEM, selecione o nível mínimo e salve a configuração desativada. Teste a conexão e depois clique em **Ativar integração**.
5. Ligue seus nós de notificação/chamados após **Conectar sua automação aqui**. O fluxo fornecido recebe e valida o alerta; não cria chamados nem envia mensagens sozinho. O ramo de teste termina antes desse ponto.

## Servidor próprio e Tailscale

HTTPS e certificado confiável são obrigatórios nos dois modos. Para n8n próprio em LAN ou Tailscale, informe o **IP privado ou Tailscale autorizado** exato. A URL pode usar DNS, mas todos os IPs resolvidos precisam ser permitidos. A conexão fixa o IP validado e mantém a verificação de nome/certificado. Loopback, link-local, metadados conhecidos e destinos reservados não são aceitos; autorizar um IP não autoriza sua rede inteira. O webhook genérico mantém sua política anterior.

No Tailscale, permita apenas a origem SIEM → IP n8n na porta TCP HTTPS escolhida (normalmente 443). O SIEM não precisa de acesso a todas as máquinas de uma tag. CA interna precisa estar no repositório de confiança do servidor SIEM. Não desative TLS para resolver erros. Em proxy reverso, preserve os cabeçalhos e a URL pública de produção do n8n.

## Contrato e autenticação

POST JSON com `schema=1`, `product`, `version`, `kind` (`alert` ou `test`), `id`, `time`, `device`, `protocol`, `source_ip`, `level` e `title`. O log bruto fica local. Campos de texto são limitados e redigidos; são dados, nunca comandos ou instruções para execução.

Cabeçalhos: `X-Multipla-Token`, `X-Multipla-Timestamp` (segundos Unix do envio), `X-Multipla-Event-ID`. O nó Webhook valida a credencial antes de executar o fluxo. O nó Code verifica formato, campos, ID, nível e timestamp de envio com tolerância de cinco minutos, depois remove os cabeçalhos da saída. Mantenha relógios sincronizados. Esta integração usa Header Auth nativo sobre TLS; a assinatura HMAC do webhook genérico não é o mecanismo desta conexão.

Resposta exigida: `{"ok":true,"schema":1,"id":"ID recebido","kind":"alert ou test"}`. Um HTTP 200 genérico não conta como confirmação. A confirmação significa **recebimento validado**, e não conclusão dos nós de negócio posteriores. Não altere esses campos ao personalizar o fluxo.

## Entrega e deduplicação

Fila persistente limitada a 128 resumos, até seis tentativas com espera crescente. Timeout de dez segundos por envio. Falhas HTTP 4xx definitivas encerram o envio; 408, 429, 5xx, falhas de conexão e confirmação inválida podem ser repetidas. Notificações com mais de 24h são encerradas. O painel mostra pendências, confirmações, falhas e último sucesso; falhas definitivas aparecem na auditoria.

**Não há garantia de execução única.** Se o n8n recebeu um evento e a resposta se perdeu, o mesmo ID pode chegar novamente. Antes de ações irreversíveis, implemente deduplicação em armazenamento persistente com chave única por `id`; a validação do timestamp não substitui essa deduplicação. O fluxo não utiliza memória estática do n8n como falsa garantia de unicidade. Use as políticas de repetição/compensação do fluxo de negócio para falhas após a confirmação.

Eventos recebidos por webhook não voltam para esta integração, evitando ciclos. A fila cheia ou uma falha de gravação não remove o alerta do histórico local. Salvar uma configuração desativada, trocar URL/token/modo/IP ou desativar cancela os pendentes; uma requisição já em andamento pode concluir. Rotação de credencial ou mudança de destino exige novo teste. Restaurar backup de configuração desativa a integração, limpa a fila e exige teste; URL/token não são exportados por esse backup.

O fluxo fornecido desativa a gravação dos dados das execuções bem-sucedidas, com erro e manuais para evitar guardar cabeçalhos de autenticação. Não habilite gravação desses dados sem avaliar a exposição. Operadores com acesso ao runtime/proxy do n8n devem ser pessoas autorizadas; os dados transitam no sistema de automação escolhido.

## Referências oficiais

- Webhook, autenticação e produção: https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/
- Credenciais Header Auth: https://docs.n8n.io/integrations/builtin/credentials/webhook/
- Resposta ao webhook: https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.respondtowebhook/
- Configurações de execução: https://docs.n8n.io/workflows/settings/

Validação local inclui contratos HTTP, autorização administrativa/CSRF, isolamento de segredos, política de destinos, fila após reinício, repetição com ID estável e código de validação do fluxo. Homologação na instância real escolhida de n8n é necessária antes de conectar ações de negócio.
