# Multipla Siem 1.2.20

Classificação persistente por descrição: marcar/desmarcar eventos críticos, escolha de áudio e ativação/desativação posterior. Cabeçalhos syslog são ignorados; em mensagens reconhecidas de ataque SSHguard o IP pode variar. As marcações aparecem na dashboard e no histórico. Evidências originais e bloqueios existentes permanecem preservados. Até 128 descrições; alterações futuras começam na primeira marcação, além dos eventos explicitamente selecionados.

Lista de IPs de origem dos críticos para visualização e download TXT, com períodos de 1h, 6h, 24h ou 7 dias. IP do remetente não é usado como substituto do atacante. Leitura limitada a 64 MiB, 10 segundos e 10.000 eventos críticos; resultado parcial é indicado e não permite download incompleto. Eventos derivados compartilham a contagem com seu evento de origem.

Até oito cards independentes de recursos, redimensionamento em quatro larguras e altura mínima ajustável de todos os cards. Disposição, dimensões e máquina selecionada salvas por conta. Conteúdo cresce/reorganiza e os cards de recursos se empilham no celular.

Histórico de recursos e ping por máquina nas últimas 24h, até 1.440 amostras por minuto persistidas no diretório de dados. Uso médio, pico e recursos livres; disponibilidade observada ao ping, latência média ponderada/máxima e perda de pacotes. Três pacotes ICMP por minuto a partir do SIEM para máquinas cadastradas. O histórico começa após a instalação desta versão; faltas de coleta são indicadas como lacunas, não como disponibilidade. ICMP bloqueado não comprova falha do equipamento. O coletor deve fornecer métricas atuais; Proxmox com somente syslog terá dados de ping, sem CPU/RAM.

Indicador superior da VM Linux: CPU, RAM e filesystem do diretório de dados. Alerta a partir de 90%, recuperação abaixo de 85%, estado indisponível explícito. Central com visão das 20 threads de maior consumo observado, sem expor argumentos de comandos, popup e até 200 notificações recentes. Limpar reconhece os avisos pendentes apenas da conta atual e preserva o histórico. Novos avisos posteriores à limpeza permanecem pendentes.

Validação local: suíte Go, parsing de métricas Linux, regras críticas, autenticação/CSRF, persistência e isolamento de preferências/limpeza; compilação Linux amd64 e arm64. Prévia com dados ilustrativos. A coleta real da VM Debian e seus pings será conferida após a atualização.

# 1.2.6 — 2026-10-05

- O atualizador e o rollback aguardam até dois minutos pela disponibilidade HTTPS do painel, consultando a cada dois segundos. A validação do certificado e a restauração automática permanecem obrigatórias.
- Dashboard em cards por assunto, reorganizáveis por arraste ou setas. A disposição é salva por conta no servidor, inclusive para visualização, e integra os backups. Há cancelamento e restauração do padrão.
- Relatórios históricos por período UTC de até 31 dias, dispositivo, origem (incluindo pfSense e Proxmox), tipo (logs/alertas), nível e IP de origem IPv4/IPv6.
- Atalho para relatório de segurança com críticos pfSense/Proxmox, resumo por dispositivo/nível e IPs de origem dos críticos. Logs sem origem identificável são indicados; não se usa o endereço do remetente como substituto.
- Exportação do relatório JSON, CSV dos registros exibidos e PDF pelo diálogo de impressão do navegador (Salvar como PDF), com filtros, resumo e tabelas.

A consulta percorre o histórico retido, limitado a 64 MiB e 20 segundos por execução, com duas consultas simultâneas. Resultados parciais e arquivos ausentes são indicados. Totais abrangem os registros lidos; detalhes/CSV/PDF incluem até 1.000 registros. Logs e alertas derivados são contados separadamente.

Na primeira transição de um atualizador 1.2.5 ou anterior, a espera antiga ainda é executada pelo processo já instalado. Em servidores cuja partida ultrapasse oito segundos, a espera temporária do systemd pode ser necessária mais uma vez para instalar o novo atualizador. A partir do atualizador 1.2.6, não será necessária nas atualizações seguintes.

# 1.2.5 — 2026-10-05

Multipla Siem 1.2.5 adiciona recuperação completa criptografada e contas com perfis de acesso.

- Backup completo AES-256-GCM em blocos autenticados, compressão e processamento em fluxo para limitar memória. Inclui dados e logs do SIEM, contas e hashes de senha, credenciais de integrações, certificados, identidade Tailscale e binários. Não é uma imagem do Debian e não inclui backups anteriores.
- Chave aleatória de recuperação de 256 bits separada, em /root/multipla-siem-recovery.key. Nunca é enviada ao Drive. É indispensável guardar uma cópia fora do servidor.
- Envio ao Drive da conta administrativa já autorizada, com validação do destino HTTPS, tamanho e checksum do envio. Falha de rede preserva a cópia local.
- Agendamento diário por systemd, com horário e fuso das preferências. Exige ativação uma vez como root.
- Restauração valida autenticação, conteúdo, caminhos e limites antes de alterar a instalação; cria checkpoint criptografado. Exige servidor original desligado, evitando duplicar a identidade Tailscale.
- Análise local permanente, diagnóstico imediato dos logs críticos e integração opcional com modelo Ollama instalado no servidor. A disponibilidade do modelo aparece separadamente no painel.
- Edição do acompanhamento de alertas (título, prioridade, situação e notas), preservando o evento original; edição das regras existentes.
- Contagem de dispositivos online e offline pelo estado Tailscale, com identificação explícita do fallback por atividade de logs.
- Cadastro e edição de contas administrativas ou somente visualização, login local opcional e desativação de acesso. A conta administrativa principal é protegida.
- Perfil de visualização é limitado no servidor: não altera configurações, acessa backups/credenciais nem executa respostas. Mudanças de conta encerram sessões anteriores.

A atualização preserva o login Google, o domínio Tailscale e os cadastros existentes. Credenciais revogadas ou expiradas por provedores externos ainda exigem reconexão. A integração unificada para enviar Gmail por OAuth ainda não está incluída.

Consulte FULL-BACKUP.md para os comandos de criação, agendamento e restauração. Os backups completos .msbk são independentes dos backups simples JSON do painel. Não devem ser importados como JSON. Não há remoção automática de cópias completas; monitore o espaço local e no Drive.


# 1.2.4 — 2026-10-05

- Gráfico de eventos por dispositivo, com alertas críticos destacados (nível 12 a 15).
- Atividade recente separada por dispositivo, com seleção individual e legenda.
- Edição de dispositivos, regras e motivos de resposta, preservando a expiração dos bloqueios; edição SNMP com cancelamento.
- Exemplos de regras, criação de rascunhos a partir de eventos e teste de padrões Go/RE2 antes de salvar. Nenhum bloqueio é ativado automaticamente pelo rascunho.
- Instruções e exemplos nos campos técnicos; esclarecimento de que credenciais OAuth não são a senha Gmail.
- Correção da renderização de eventos quando existem alertas.
- Backup pre-update com hashes e rollback manual offline, preservando logs e mantendo o atualizador atual.

# 1.2.3

Corrige Referrer-Policy dos formularios de acesso; preserva bloqueio de origem nula/externa.

# 1.2.2 — 2026-10-04

- Codigo de cadastro reutiliza o segredo aleatorio gerado na instalacao, evitando divergencia com LoadCredential no primeiro start.
- Checagem HTTPS usa a rota real de acesso /.
- Atualizador instala tambem sua propria versao, com hash/tamanho incluidos no manifesto assinado.
- Validacao SSH cria /run/sshd dentro do contexto in-target usado pelo instalador Debian.

# 1.2.1 — 2026-10-04

- Primeiro boot chamado pela partida do servidor, com nova tentativa automatica quando a rede fica disponivel.
- Remocao da dependencia que podia deixar o servidor parado apos falha do primeiro boot.
- SSH instalado da ISO e habilitado, com login root remoto e senha vazia proibidos.
- Repositorios oficiais HTTPS configurados apos instalar a base local; entradas CD-ROM desativadas.
- Atualizacoes Debian tentadas durante a instalacao; indisponibilidade de internet nao interrompe a instalacao local.
- Texto de instalacao offline removido dos menus e cabecalho.
- Atualizador GitHub Releases com assinatura Ed25519, integridade, backup e retorno a versao anterior em falha de partida.

# 1.2 — 2026-10-04

- Interpretação CEF/UniFi e alertas de ameaça, falha administrativa e indisponibilidade.
- Configuração separada de syslog, SNMP e webhook no painel.
- Recepção SNMPv2c e SNMPv3 authPriv SHA-256/AES-128, ACL por IP, deduplicação e janela temporal persistente.
- Webhook HTTPS de entrada com token próprio e ACL; saída JSON assinada HMAC-SHA256, fila limitada e três tentativas.
- Proteção contra SSRF, DNS com endereços não permitidos e redirecionamentos nos webhooks.
- Backups incluem metadados dos receptores, preservam credenciais locais e restauram canais desativados.

# Versão 1.1 — 2026-10-04

- Análise adaptativa local limitada em memória, correlação de login e detecção de falhas críticas; apenas alertas.
- Exportação/importação e restauração de configurações; dez backups locais por conta.
- Agendamento diário com fuso horário e preferências por conta Google.
- Google Drive com escopo drive.file, PKCE, vinculação à identidade e tokens criptografados.
- Fundo original do instalador escurecido e cores de menu com maior contraste.

# Histórico de versões

## 1.0 — 2026-10-03

Primeira versão de referência para testes, marcada como 1.0 a pedido do usuário. Inclui a aplicação, instalador offline Debian, assistente inicial, integrações e proteções documentadas na revisão de segurança. Esta marcação altera apenas a identificação da versão.

Correções futuras usarão 1.0.1, 1.0.2 e assim por diante; melhorias compatíveis usarão 1.1, 1.2; mudanças incompatíveis usarão 2.0. As limitações e os requisitos de homologação continuam descritos no README e no relatório de segurança.


## 1.1.1 — 2026-10-04

- Corrige o primeiro boot da ISO: HTTPS automático, código exclusivo no console e cadastro administrativo pelo navegador.
- Conta administrativa local persistente, sem dependência de Google ou internet, com senha derivada por PBKDF2.
- Configuração Google OAuth pelo painel, com segredos criptografados e excluídos de backups.
- Login informa quando Google SSO ainda não está configurado.
