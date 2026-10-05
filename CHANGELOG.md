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
