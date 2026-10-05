# Recuperação completa do Multipla Siem

Como root, após atualizar para 1.2.5:

```sh
su -
/usr/local/bin/multipla-siem -full-backup -backup-drive SEU-EMAIL
/usr/local/bin/multipla-siem -full-backup-schedule SEU-EMAIL
systemctl list-timers multipla-full-backup.timer
```

Use a conta administrativa que já autorizou o Drive. Para uma cópia somente local, omita -backup-drive. O backup pausa somente o SIEM durante a captura; Tailscale permanece conectado. Cópias ficam em /var/backups/multipla-siem/full, com permissão privada. O arquivo .msbk enviado ao Drive é criptografado e separado da chave. O backup simples JSON continua disponível no painel e não inclui credenciais.

Guarde a chave /root/multipla-siem-recovery.key fora do servidor, em armazenamento seguro separado do Drive. Não envie seu conteúdo em mensagens ou capturas. Perder essa chave impede a recuperação. É uma chave aleatória, não a senha Gmail, e não deve ser colocada dentro do backup. A autorização Google para Drive precisa estar vigente (modo de teste expira em sete dias).

Para recuperar após perda do servidor, use Debian/Ubuntu com os serviços do Multipla Siem e Tailscale instalados e a mesma arquitetura. Copie o arquivo .msbk e a chave para arquivos privados no novo servidor. O backup não reinstala pacotes Debian, não restaura contas Linux/SSH ou rede do host. Mantenha o servidor original desligado. Execute a restauração pelo console ou por SSH na rede local: o processo reinicia Tailscale e interrompe conexões que dependem dele. Os binários e a configuração SIEM são restaurados do arquivo.

```sh
chmod 600 /root/chave-recuperacao.key
/usr/local/bin/multipla-siem -full-restore /root/backup.msbk -recovery-key /root/chave-recuperacao.key -replace-server
systemctl status multipla-siem tailscaled --no-pager
```

A restauração exige root, valida o arquivo inteiro em área privada antes de copiar arquivos, preserva um checkpoint criptografado do estado anterior e substitui arquivos atomicamente um a um. Não é uma transação atômica do sistema operacional: se houver erro de armazenamento, use o checkpoint informado para recuperar. Diretórios e arquivos especiais, links e caminhos externos são recusados. Arquivos de log extras existentes no destino não são apagados. Os dados SIEM são atribuídos ao usuário de serviço local, mesmo se seu UID mudou.

Contas, credenciais e certificados são recuperados junto à chave interna que protege os tokens. A chave de recuperação fornecida é instalada no novo servidor para as próximas cópias. O agendamento completo é reativado se estava habilitado no backup. A identidade Tailscale recuperada deve pertencer somente a esse servidor. Certificados vencidos, chaves Tailscale expiradas e autorizações revogadas pelo Google ainda precisam de renovação; o backup não contorna essas políticas.

Limites: 64 GiB de conteúdo e 100.000 arquivos; arquivos JSON de configuração/estado limitados a 16 MiB. A criação e restauração precisam de espaço livre. Não há retenção automática das cópias completas. Envios usam sessão de upload do Drive e streaming; uma interrupção preserva o arquivo local, mas a rotina não retoma automaticamente a sessão interrompida. O agendamento diário completo é independente do agendamento de backup JSON; para alterar horário/fuso, salve as preferências e execute novamente -full-backup-schedule.

Novas contas são cadastradas em Configurações > Contas de acesso. Perfis: Administrador e Somente visualização. Senha local é opcional; vazia em conta nova exige login Google. Vazia numa edição preserva a senha atual. A conta principal não pode ser desativada por esse formulário. Contas novas com acesso ao Drive precisam autorizá-lo separadamente; o papel de visualização não pode acessar backups ou integrações.

A seleção do modelo local, os diagnósticos e as avaliações de alertas integram o estado recuperado. Ollama e os pesos do modelo são dependências externas do servidor e não estão neste backup; consulte LOCAL-AI.md para reinstalá-los numa recuperação. Atualizações normais do SIEM preservam essa instalação externa.
