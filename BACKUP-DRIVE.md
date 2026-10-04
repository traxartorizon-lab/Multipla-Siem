# Multipla Siem 1.1 — backups e análise local

## Acesso e atualização

Acesse https://IP-DO-SERVIDOR:8443. Para atualizar uma instalação existente, preserve /var/lib/multipla-siem e /etc/multipla-siem, execute sudo sh scripts/install.sh a partir do pacote 1.1 e reinicie com sudo systemctl restart multipla-siem. O instalador cria a chave BACKUP_ENCRYPTION_KEY quando ausente e preserva os segredos existentes. Não reinstale o Debian para atualizar o aplicativo.

## Backups e preferências

Em “Backups e conta”, configure a página inicial, intervalo de atualização e nível mínimo de alertas. As preferências pertencem à conta autenticada. Exporte um JSON, importe um arquivo ou restaure uma cópia anterior. A restauração desativa o agendamento e a publicação de bloqueios até que você revise as configurações.

O backup inclui configurações operacionais, dispositivos, regras, emails autorizados e preferências da conta. Não inclui logs, sessões, certificados, chaves, senhas Gmail, segredos OAuth, tokens Drive nem parâmetros de endereço e caminhos do servidor. Proteja o arquivo: ele contém informações da rede. Guarde os segredos e certificados separadamente com acesso restrito.

O agendamento é diário, no horário e fuso escolhidos. São mantidas dez cópias locais por conta em /var/lib/multipla-siem/backups. Se o serviço estiver parado no horário, tenta ao voltar no mesmo dia. Cada dia tem uma tentativa automática; após falha, use “Criar backup agora”. Se o Drive falhar, a cópia local permanece.

## Google Drive

Use o mesmo projeto OAuth configurado para o login Google, habilite a Google Drive API e configure o consentimento para openid, email e https://www.googleapis.com/auth/drive.file. O redirect URI é o mesmo callback configurado para SSO. As credenciais ficam no arquivo root /etc/multipla-siem/secrets.env; nunca no painel.

Clique em “Conectar Google Drive” e autorize a mesma conta Google usada no login. A autorização é separada do SSO. A aplicação solicita acesso aos arquivos criados por ela, não a todo o Drive. Os tokens são criptografados com AES-GCM e vinculados à conta e à identidade Google. Nenhum backup exporta esses tokens.

Ative o envio ao Drive nas preferências. “Criar backup agora” e o agendamento criam primeiro a cópia local e depois enviam para o Drive. Liste as cópias e restaure a desejada pelo painel. São listadas as cem cópias remotas mais recentes; a aplicação não apaga cópias remotas automaticamente. Controle o espaço na sua conta.

Após reinstalar em outro servidor, configure novamente as credenciais do mesmo cliente OAuth e conecte a mesma conta para acessar as cópias remotas. Uma chave local nova exige reconectar o Drive. O backup não recria o login Google nem seus segredos. Revogue a autorização nas configurações da conta Google quando necessário. O Drive requer internet; instalação, análise e backups locais funcionam offline.

## Análise local

A análise usa estatística adaptativa e correlação em Go, sem LLM, GPU ou downloads de modelos. Foi projetada para 4 GB de RAM e quatro núcleos. Ative “Análise local” nas configurações ao atualizar; instalações novas já usam a opção padrão.

Há aquecimento de vinte minutos para desvios de volume por dispositivo. Correlação de cinco falhas de autenticação seguidas de sucesso em cinco minutos e indicadores explícitos de kernel panic, OOM, SMART, ECC não corrigível e I/O geram alertas imediatamente. A análise só interpreta o que chega nos logs: não consulta sensores nem executa testes de hardware.

O estado limita-se a 128 dispositivos e 1.024 origens de autenticação, com intervalo mínimo de dez minutos entre alertas equivalentes por dispositivo. O aprendizado reinicia após reinício ou desativação e pode reiniciar após longas pausas. Os alertas incluem explicação e evidência com redação de credenciais conhecidas. A análise local não cria bloqueios no pfSense. Revise possíveis falsos positivos; ausência de alerta não garante ausência de invasão.
