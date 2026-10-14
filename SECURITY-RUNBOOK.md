# Operação e recuperação segura — Multipla SIEM 1.2.35

Este documento descreve a política implementada e as etapas de infraestrutura que precisam ser executadas pelo administrador. Não contém chaves privadas, tokens, senhas nem valores reais de autenticação.

## Acesso e MFA

Produção exige TOTP nos acessos Google e locais. No primeiro acesso após a atualização, cadastre o autenticador e confirme um código. A configuração é cifrada com BACKUP_ENCRYPTION_KEY. Preserve essa chave: substituí-la inviabiliza os fatores existentes. O atualizador verifica a criptografia antes de trocar o executável. Códigos utilizados não podem ser reutilizados. Operações de maior impacto exigem MFA recente, com janela de cinco minutos.

O token inicial do console permite somente cadastrar a primeira conta. Depois do cadastro, esse caminho fica fechado. Não há desativação de MFA pela API de configuração.

Perda do autenticador: use seu acesso administrativo independente ao host. Pare o serviço antes de recuperar apenas a conta afetada:

```sh
sudo systemctl stop multipla-siem
sudo /usr/local/bin/multipla-siem -config /var/lib/multipla-siem/config.json -mfa-reset seu-email
sudo systemctl start multipla-siem
```

O comando exige root, invalida os vínculos Windows da conta e registra a ação. Entre com o primeiro fator, configure novo autenticador e gere nova chave na Central de notificações. Sessões antigas foram encerradas pela parada do serviço.

## Grupos e clientes

Somente alertas, Administrativo e Superadmin são autorizados no servidor. Administrativo pode receber separadamente as permissões de gestão de contas, backup e terminal, concedidas pelo Superadmin. Não pode promover contas para Superadmin ou conceder essas permissões.

Contas novas começam sem acesso global. Selecione explicitamente clientes ou marque acesso global para operadores internos. Contas antigas preservam o acesso interno até atribuição explícita. Revise-as antes de disponibilizar acesso a pessoas de clientes. Histórico legado sem identificação confiável de tenant permanece disponível somente para operadores globais; não é atribuído automaticamente com base em nomes presentes no texto do log.

Clientes são gravados na coleta e usados nas consultas, relatórios, exportações, IA, métricas e notificações. Operações globais não disponíveis para contas de clientes retornam 403. Mudar o cliente atual do dispositivo não relabela os eventos antigos. Agendamentos de backup deixam de executar quando o proprietário perde permissão ou acesso global.

## Capacidade e retenção

O limite diário reserva 20% para críticos. Logs normais têm cotas por origem; 200 eventos/s por origem e 2.000/s no conjunto são os limites de admissão normal, com orçamento separado para críticos reconhecidos na entrada. O spool preserva até 2.048 registros e 64 MiB, com reserva para críticos e limites por origem. Saturação e descarte são registrados também no journald, sem log bruto ou segredos. Ao perder a persistência do diário e do spool, não são tomadas ações automáticas a partir de evidência não gravada.

Dispositivos com problema têm arquivo separado, limitado a 16 MiB/dia. Agrupamento e ocultação alteram a apresentação, não desligam coleta/detecção/notificações. A retenção também se aplica a esse arquivo. Encerrar um agrupamento permite exibir novos registros normalmente; os arquivos anteriores permanecem até a expiração.

Emails usam fila durável de 128 registros, até 32 por origem, seis tentativas e fila de falhas de 128 registros. Entregas podem repetir depois de interrupção entre envio e confirmação persistida. n8n também exige deduplicação por ID. Dimensione disco com taxa × tamanho médio × retenção, mais spool, backups e margem operacional. Monitore ocupação e descarte fora da cota de eventos. A existência das filas não constitui alta disponibilidade nem comprova entrega ao destinatário.

## Isolamento adicional no próprio SIEM

Instale nftables pelos repositórios do sistema, se necessário. Confira os dispositivos registrados e proteja os IPs administrativos em protected_cidrs antes de habilitar:

```sh
sudo /usr/local/bin/multipla-siem -config /var/lib/multipla-siem/config.json -enable-isolation
sudo systemctl status multipla-isolation --no-pager
```

O agente root mantém somente a tabela nftables inet/multipla_guard. Observa SYNs reais recebidos em tailscale0, de dispositivos autorizados na política root para endereços locais do SIEM. Dez portas distintas ou vinte tentativas com portas de origem distintas na porta 22 em um minuto acionam isolamento. Portas 8443 e 5514 são excluídas. Logs encaminhados, IPs extraídos de mensagens e requisições externas ao túnel não acionam essa camada. O monitor tem orçamento próprio e registra falhas no journald.

Depois de alterar dispositivos ou endereços do SIEM, reaplique a habilitação para atualizar a política root. O isolamento persiste após reinício e interrompe também a comunicação normal do dispositivo isolado. Ler a notificação encerra a sirene e o destaque visual; não remove a regra. Superadmin pode solicitar a liberação pelo evento, com CSRF, MFA recente e auditoria. O agente remove apenas o IP correspondente da sua própria tabela.

O app Windows toca a sirene pela saída escolhida e mantém as notificações quando minimizado. No navegador, reprodução depende da permissão de áudio e da disponibilidade do dispositivo; não é garantia de entrega de segurança.

## SSH delegado

O SIEM não aceita chave pessoal nem senha SSH em requisições de terminal. Uma CA SSH exclusiva, acessível somente ao assinador root, emite certificados Ed25519 de cinco minutos. Principais e origens são fixados pela política root. O cliente usa chave efêmera em memória. Sessões têm limite de cinco minutos, revogação por alteração de conta/logout e quatro terminais simultâneos.

No SIEM, autorize cada destino e as origens exatas que o destino verá:

```sh
sudo /usr/local/bin/multipla-siem -enable-ssh-ca IP_DO_DESTINO -ssh-source IP_TAILSCALE_DO_SIEM,127.0.0.1
sudo ssh-keygen -lf /etc/multipla-siem/ssh-ca.pub
```

Transfira somente ssh-ca.pub por canal administrativo verificado. No destino Linux, execute o script assinado scripts/provision-ssh-target.sh e confirme a impressão digital. Cadastre SSHUser=multipla-ops no SIEM. A conta não recebe sudo. Captura DHCP pode exigir uma permissão de captura específica, aprovada no destino; não conceda acesso administrativo amplo como solução. pfSense/FreeBSD precisa de provisionamento equivalente suportado pela sua instalação; o script Linux não deve ser usado nele. Sem provisionamento, a conexão falha e não retorna ao modelo de chaves pessoais.

O sshd do destino registra autenticação/sessão/certificado com LogLevel VERBOSE, fora do host SIEM. O SIEM registra solicitação/encerramento e bloqueia abertura se a auditoria local falhar. Isso não grava todos os comandos nem oferece retenção externa imutável. Revoke acesso na conta, retire destinos da política root e mantenha plano de rotação da CA com atualização do trust nos destinos.

## Transporte dos eventos

Mantenha 5514 somente nas interfaces/redes privadas autorizadas. Não abra syslog UDP/TCP na internet. Prefira SNMPv3 authPriv. Para syslog autenticado, configure syslog_tls (por exemplo, 100.x.x.x:6514), syslog_client_ca e os certificados do servidor pelo administrador do host. O listener exige TLS 1.3 e certificado de cliente emitido para o IP cadastrado. Ele não substitui automaticamente o transporte já usado pelo pfSense/Proxmox; provisione certificados e regras de rede antes da migração. O texto encaminhado continua sendo evidência declarada pelo emissor, não prova de identidade de um atacante.

## Distribuição e chaves de release

Verifique assinatura Ed25519 e hashes com raiz pública obtida por canal independente antes de executar instaladores ou iniciar o app. Pacotes de coletores incluem manifesto, assinatura e ferramentas de conferência. Instalação Linux repete a verificação antes de alterar contas/serviços. A ISO deve ter seu arquivo inteiro autenticado pelo manifesto de distribuição antes do boot: conferir apenas SHA256 sem assinatura não autentica a origem.

A chave privada de release fica fora do checkout, não é enviada ao GitHub/CI e não é a CA SSH. Restrinja sua ACL ao operador de assinatura, guarde cópia offline cifrada e registre custódia. Para rotação: produza nova chave offline, divulgue a nova raiz por canal independente, atualize a configuração de confiança dos verificadores e ensaie uma release antes de desativar a chave anterior. Não troque a raiz apenas porque apareceu uma chave dentro de um ZIP baixado.

O pacote Windows usa manifesto Ed25519 e proveniência da compilação; assinatura Authenticode de editora requer certificado externo próprio e não é substituída por esse manifesto. Proteções de branch e 2FA do GitHub dependem de permissões administrativas/da conta: exigir revisão, checks de segurança/release, impedir force-push/deleção, separar mantenedores e exigir 2FA. A conexão usada nesta manutenção não tem permissão administrativa para alterar essas configurações. Não considere esses controles ativados apenas pela existência do workflow.

## Recuperação

Guarde a chave /root/multipla-siem-recovery.key offline, separada do backup. Sem ela não há recuperação do backup completo. O backup cobre configuração, dados, CA/políticas próprias, UFW, configuração SSH, polkit e unidades próprias. Não copia contas Linux/segredos de outros produtos, discos de VMs, modelos Ollama nem snapshots do provedor.

O restore padrão preserva a identidade Tailscale do destino e mantém o SIEM parado para configurar endereço/certificado e validar a infraestrutura. Vínculos Windows são revogados. Para reutilizar a identidade antiga, -replace-server exige desligar o original primeiro; o software não consegue comprovar que outra máquina fora do seu controle está desligada. Nunca inicie duas máquinas com a mesma identidade.

```sh
sudo multipla-siem -full-restore /caminho/backup.msbk -recovery-key /caminho/chave-offline
# Configure endereço/certificado e dependências da máquina nova:
sudo multipla-setup
# Valide antes de colocar em operação:
sudo sshd -t
sudo ufw status verbose
sudo systemctl cat multipla-siem multipla-app-update multipla-ssh-sign multipla-isolation
sudo tailscale status
sudo timedatectl show -p NTPSynchronized
sudo /usr/local/bin/multipla-siem -check -config /var/lib/multipla-siem/config.json
```

Confirme SSH por chave, root remoto desativado, firewall deny incoming com portas permitidas somente nas origens certas, polkit restrito a unidades/verbos fixos, Tailscale SSH desativado quando não usado e serviços em usuários restritos. Reprovisione o que não foi incluído. Valide o horário, coleta pfSense/Proxmox, uma notificação real e a recuperação MFA. Somente depois habilite o serviço. O RPO é o horário do último backup concluído; com agenda diária, a meta é até 24h enquanto backups estiverem saudáveis. RTO é o tempo medido no seu ensaio, não um prazo garantido por este software.

Armazenamento externo imutável permanece pendente por decisão do usuário. Logs ativos, auditoria local e backups não devem ser apresentados como WORM ou como proteção contra um administrador root comprometido.
