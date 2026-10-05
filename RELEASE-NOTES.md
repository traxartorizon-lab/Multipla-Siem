Multipla Siem 1.2.4 melhora a investigação e a configuração pelo painel.

- Gráfico de eventos por dispositivo, com alertas críticos destacados (nível 12 a 15).
- Atividade recente separada por dispositivo, com seleção individual e legenda.
- Edição de dispositivos, regras e motivos de resposta, preservando a expiração dos bloqueios; edição SNMP com cancelamento.
- Exemplos de regras, criação de rascunhos a partir de eventos e teste de padrões Go/RE2 antes de salvar. Nenhum bloqueio é ativado automaticamente pelo rascunho.
- Instruções e exemplos nos campos técnicos; esclarecimento de que credenciais OAuth não são a senha Gmail.
- Correção da renderização de eventos quando existem alertas.

Os gráficos usam até 2.000 registros recentes e uma janela de até 30 minutos; não representam todo o histórico sob volume elevado. A atualização preserva dados, contas e configuração, incluindo o domínio e o certificado Tailscale já configurados.

Google SSO permanece disponível. A autorização unificada de Gmail e Drive ainda não faz parte desta versão; Gmail continua usando senha de aplicativo. A renovação do certificado Tailscale deve ser configurada separadamente no servidor.

Como root, execute /usr/local/sbin/multipla-update após a publicação da release assinada.


## Backup e rollback de atualização — 1.2.4

Antes de substituir a aplicação, o serviço é parado e o atualizador salva os binários, config.json e state.json em /var/backups/multipla-siem/update-ID. Contas, regras e preferências estão incluídas. Os backups novos incluem hashes SHA-256; snapshots privados completos da 1.2.3 também podem ser restaurados. Se o backup não puder ser concluído, a atualização é cancelada.

Como root:

```sh
multipla-update
multipla-update list-backups
multipla-update rollback
multipla-update rollback update-AAAAMMDDTHHMMSS.NNNNNNNNNZ
```

Em instalações anteriores cujo wrapper ainda não encaminha argumentos, use o comando direto (ele também adquire trava exclusiva):

```sh
/usr/local/lib/multipla-siem/updater list-backups
/usr/local/lib/multipla-siem/updater rollback
```

O rollback seleciona o backup completo mais recente, funciona sem internet e restaura aplicação, configuração e state.json. Mantém o atualizador atual para continuar oferecendo os comandos de recuperação. Antes de restaurar, grava um checkpoint privado before-rollback-ID. Se a partida ou a verificação HTTPS falhar, tenta recuperar esse checkpoint. Os logs históricos, certificados e secrets.env não são modificados. Mudanças de configuração posteriores ao backup serão revertidas. Não é rollback do Debian nem de seus pacotes. Backups não são apagados automaticamente; monitore o espaço de /var/backups.
