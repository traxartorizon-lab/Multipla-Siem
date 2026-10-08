# Multipla Siem 1.2.19

Eventos com logs em destaque, filtro de cliente sincronizado às abas laterais em ordem alfabética, rolagem independente preservada nas atualizações e layout responsivo com quebra de textos longos. A consulta combina cliente, data/hora e palavra-chave/IP antes da paginação. A associação usa o cadastro atual dos dispositivos; origens não associadas aparecem separadamente.

Integração guiada com n8n Cloud e servidor próprio em Syslog, SNMP e webhook. Fluxo importável com autenticação Header Auth nativa, credencial exclusiva cifrada, contrato versionado, teste separado dos alertas e ativação condicionada à confirmação compatível. Destinos HTTPS com IP privado/Tailscale exato autorizado, resolução e conexão validadas, certificados verificados e redirecionamentos recusados.

Fila persistente limitada a 128 notificações, seis tentativas com espera crescente, confirmação por ID/tipo, status e auditoria. Resumos sem log bruto, prevenção de ciclos de webhook, controle administrativo e CSRF. Mudanças de destino/credencial exigem novo teste. Entregas podem repetir; deduplicação das ações de negócio deve usar armazenamento persistente no fluxo n8n.

Guia e limites em N8N.md. Integração desativada por padrão; a conexão real deve passar pelo teste do painel antes de ativar. Homologação das ações de negócio requer a instância n8n escolhida.

Validação concluída: suíte Go completa, go vet, testes do contrato/código do fluxo, autenticação/CSRF, destinos restritos, fila após reinício e falhas definitivas. Prévia desktop e móvel (390 e 320 px) sem transbordamento; builds Linux amd64 e arm64 do servidor e atualizador em outputs/releases/1.2.19/unsigned.
