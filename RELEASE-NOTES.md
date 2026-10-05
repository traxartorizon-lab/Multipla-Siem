Multipla Siem 1.2.5 adiciona recuperação completa criptografada e contas com perfis de acesso.

- Backup completo AES-256-GCM em blocos autenticados, compressão e processamento em fluxo para limitar memória. Inclui dados e logs do SIEM, contas e hashes de senha, credenciais de integrações, certificados, identidade Tailscale e binários. Não é uma imagem do Debian e não inclui backups anteriores.
- Chave aleatória de recuperação de 256 bits separada, em /root/multipla-siem-recovery.key. Nunca é enviada ao Drive. É indispensável guardar uma cópia fora do servidor.
- Envio ao Drive da conta administrativa já autorizada, com validação do destino HTTPS, tamanho e checksum do envio. Falha de rede preserva a cópia local.
- Agendamento diário por systemd, com horário e fuso das preferências. Exige ativação uma vez como root.
- Restauração valida autenticação, conteúdo, caminhos e limites antes de alterar a instalação; cria checkpoint criptografado. Exige servidor original desligado, evitando duplicar a identidade Tailscale.
- Cadastro e edição de contas administrativas ou somente visualização, login local opcional e desativação de acesso. A conta administrativa principal é protegida.
- Perfil de visualização é limitado no servidor: não altera configurações, acessa backups/credenciais nem executa respostas. Mudanças de conta encerram sessões anteriores.

A atualização preserva o login Google, o domínio Tailscale e os cadastros existentes. Credenciais revogadas ou expiradas por provedores externos ainda exigem reconexão. A integração unificada para enviar Gmail por OAuth ainda não está incluída.

Consulte FULL-BACKUP.md para os comandos de criação, agendamento e restauração. Os backups completos .msbk são independentes dos backups simples JSON do painel. Não devem ser importados como JSON. Não há remoção automática de cópias completas; monitore o espaço local e no Drive.

Indicador de dispositivos separa Online e Offline. Para IPs encontrados no Tailscale, usa a presença informada pelo daemon, consultada a cada 15 segundos. Para outros dispositivos, usa atividade de eventos nos últimos cinco minutos, identificando essa referência no painel. Presença no Tailscale não confirma que todos os serviços do dispositivo respondem.

- Análise local permanentemente ativa, inclusive após atualização/importação/reinício. Cada log crítico recebe diagnóstico com causas possíveis, verificações e orientações da base local, sem supressão por cooldown. Eventos antigos da janela recebem diagnóstico ao consultar o painel.
- Integração generativa local pelo Ollama, com consulta contínua de disponibilidade, fila limitada e modelo instalado selecionável. A instalação e o download do modelo no Debian são uma etapa inicial separada; não há modelo incluído nos binários SIEM. Sem modelo disponível, a base local continua ativa.
- Alertas podem receber título de avaliação, nível avaliado, estado e observações auditadas; o evento original e sua classificação permanecem preservados. Edição de regras disponível na lista.
