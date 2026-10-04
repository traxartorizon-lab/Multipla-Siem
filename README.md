# Multipla Siem 1.2.1

Servidor leve em **Go**, interface em português, binário único sem dependências externas de execução. Instalação para Debian/Ubuntu com systemd. Recebe logs de pfSense, Proxmox e dispositivos syslog, correlaciona eventos, importa alertas reais do Wazuh, envia notificações pelo Gmail e publica respostas para um alias do pfSense.

**Versão inicial funcional para homologação.** Não é um fork nem uma reimplementação completa do Wazuh. Usa conceitos de decodificação, correlação e resposta e inclui uma integração com o Wazuh Manager. O Manager continua responsável pelos agentes, regras Wazuh, inventário, FIM e detecção de vulnerabilidades. A aplicação não interpreta regras XML do Wazuh. Não há Wazuh Indexer/OpenSearch embutido.

## Início rápido

No Debian da ISO, entre como root com `su -` e execute os comandos administrativos sem `sudo`, caso ele não esteja instalado. Para SSH, use o usuário normal escolhido durante a instalação.

Arquiteturas incluídas em `dist/`: Linux amd64 e arm64. Se os binários não estiverem presentes, `install.sh` compila com Go 1.24 ou posterior. Não instala Go automaticamente.

```sh
unzip multipla-siem.zip
cd multipla-siem
sudo sh scripts/install.sh
sudo systemctl start multipla-siem
sudo nano /etc/multipla-siem/secrets.env
```

O assistente `multipla-setup` configura HTTPS nativo na porta 8443, os dispositivos e o email autorizado, sem downloads. Ele gera um certificado próprio exclusivo e mostra a impressão digital SHA256 no console. Confira essa impressão antes de confiar no certificado ou substitua-o por um certificado de sua CA. O exemplo original também permite proxy HTTPS local com backend em 127.0.0.1:8080; não publique o backend HTTP.

A ISO amd64 inclui Debian e o programa. Consulte [Instalação offline](INSTALLATION-ISO.md) e [Revisão de segurança](SECURITY-REVIEW.md).

Configuração: `/var/lib/multipla-siem/config.json`. Segredos: `/etc/multipla-siem/secrets.env`, root:root 0600, fornecidos ao serviço por `LoadCredential`; o processo roda como usuário dedicado. Não coloque credenciais no JSON ou no dashboard. Reinicie o serviço após alterar segredos.

O token inicial gerado pelo assistente vence em 15 minutos, aceita um único acesso e continua consumido após reiniciar. Para recuperar acesso local, execute `sudo multipla-setup`, que gera outro token preservando as credenciais das integrações. Sem internet, esse é o acesso inicial disponível; Google SSO e Gmail exigem conexão quando usados. Todos os emails autorizados têm privilégios de administrador nesta versão.

```sh
sudo systemctl status multipla-siem
sudo journalctl -u multipla-siem -f
```
### Teste local sem credenciais

Em Linux, copie a configuração e rode o binário da sua arquitetura:

```sh
cp config.example.json config.json
./dist/multipla-siem-linux-amd64 -config config.json -demo
```

Em Windows: `dist/multipla-siem-windows-amd64.exe -config config.json -demo`.

Abra `http://127.0.0.1:8787`, clique em **Acessar painel** com token vazio. Em **Gerar evento de teste**, são criadas seis falhas de SSH e um alerta correlacionado. Demo não envia email, não aceita integração Wazuh e não serve o feed do firewall. Utilize uma configuração e diretório de dados separados do ambiente real.

## Configuração do pfSense

1. Cadastre o **IP de origem efetivo** do firewall em **Dispositivos**, tipo pfSense. NAT altera o IP observado pelo coletor.
2. No pfSense: **Status → System Logs → Settings → Remote Logging**. Ative envio remoto, informe `IP_DO_SIEM:5514` e selecione logs de firewall, autenticação e sistema conforme necessidade.
3. Libere UDP 5514 **somente desses IPs**, na rede de gerenciamento ou VPN. Syslog UDP não autentica mensagens e pode sofrer perdas ou spoofing; não exponha a coleta à internet.
4. Habilite logging nas regras de firewall que deseja acompanhar. A regra de volume considera somente mensagens filterlog com ação `block`; não conta tráfego permitido.

### Bloqueio automático por URL Table

Não depende de pacote de API de terceiros nem de SSH administrativo no firewall.

1. Em **Firewall → Aliases → URLs**, crie um alias **URL Table (IPs)** chamado `MULTIPLA_BLOCKLIST`.
2. Informe `https://seu-dominio/feeds/pfsense/SEU_PFSENSE_FEED_TOKEN`. Use a origem HTTPS exata configurada, incluindo `:8443` quando houver HTTPS nativo. O feed também exige que a conexão venha do IP cadastrado como pfSense ou de uma rede autorizada em `feed_allowed_cidrs`; considere NAT e o IP usado pelo firewall para baixar a tabela. O token está em `secrets.env`; use segredo aleatório de 32 bytes ou mais e certificado confiável pelo pfSense. O URL é uma credencial: não o coloque em logs, tickets ou screenshots.
3. Crie uma regra **Block**, família IPv4+IPv6 quando aplicável, com **source = MULTIPLA_BLOCKLIST**, **destination = any**, nas interfaces que recebem o tráfego suspeito. Posicione-a acima das regras de passagem pertinentes. Revise o caminho do tráfego para sua topologia.
4. Configure a frequência de atualização do alias disponível na sua versão. O refresh de URL Table não é instantâneo e pode levar bastante tempo com os valores padrão. Para testar, atualize o alias pela interface do pfSense e confira a tabela em **Diagnostics → Tables** e os logs de firewall.
5. Inicialmente, mantenha **Publicar novos bloqueios** desligado. Examine as respostas simuladas e ajuste as regras. Depois ative a publicação no painel.

**Estados:** `Simulado` não vai para o feed. `Publicado` significa presente na lista servida pelo SIEM, não confirmação de execução pelo pfSense. Bloqueios simulados não são promovidos ao ligar a publicação; novos disparos ou inclusões manuais podem publicar. Não há confirmação de aplicação pelo firewall, cancelamento de states existentes ou garantia de bloqueio imediato. IPs já em conexão podem continuar até seus states expirarem. “Última consulta ao feed” confirma apenas que houve uma leitura autenticada, não a identidade ou aplicação pelo firewall.

A expiração exclui o IP do feed imediatamente na próxima leitura; o desbloqueio efetivo depende do refresh do pfSense. Se o SIEM estiver indisponível, o firewall poderá manter a tabela anterior. Um bloqueio com duração menor que o intervalo de atualização pode nunca ser aplicado. Desligar a publicação retorna uma lista vazia; force atualização do alias se precisar desfazer bloqueios imediatamente. Uma política de resposta que exija execução em segundos precisa de um conector específico para sua versão de pfSense; esse conector não está incluído.

Redes privadas, loopback, link-local, multicast, IPs cadastrados dos dispositivos e `protected_cidrs` são protegidos. Cadastre também os IPs públicos de administração, DNS, VPN, gateways e serviços essenciais nas redes protegidas. As regras automáticas usam o IP extraído do log; não o IP do remetente syslog. Um log forjado pode induzir falsos positivos: mantenha a coleta isolada.

## Configuração do Proxmox

No host Proxmox, instale `rsyslog` se necessário. Copie `deploy/proxmox-rsyslog.conf` para `/etc/rsyslog.d/60-multipla-siem.conf`, substituindo o endereço do SIEM. Cadastre o IP do host no painel.

```sh
sudo apt-get update
sudo apt-get install rsyslog
sudo rsyslogd -N1
sudo systemctl restart rsyslog
logger 'multipla-siem teste de coleta'
```

Confirme que o evento aparece no painel. A configuração usa TCP com framing por linha e fila rsyslog persistente. Não aceita framing RFC6587 por contagem de octetos. Verifique se journald, `pvedaemon`, `pveproxy`, SSH e logs desejados chegam ao rsyslog; não duplique módulos imjournal/imuxsock já configurados. VMs e containers precisam encaminhar seus próprios logs ou usar um agente Wazuh; logs do host não incluem automaticamente todos os convidados.

## Google SSO

1. No Google Cloud, configure a tela de consentimento OAuth e crie um **OAuth Client ID → Web application**.
2. Cadastre o retorno exato: `https://seu-dominio/auth/callback`, incluindo `:8443` se essa porta aparecer em `public_url`. O painel mostra a URI completa em Configurações.
3. Preencha `GOOGLE_CLIENT_ID` e `GOOGLE_CLIENT_SECRET` em `/etc/multipla-siem/secrets.env`.
4. Em modo de teste no Google, adicione os usuários de teste. Ajuste `allowed_emails` para os emails que podem administrar o SIEM.
5. Reinicie o serviço e valide **Entrar com Google** para os acessos seguintes; o token inicial é de uso único.

O fluxo usa authorization code, PKCE S256, state aleatório de uso único, cookie HttpOnly/Secure em HTTPS e consulta ao endpoint oficial UserInfo com o token obtido diretamente do Google. Requer email verificado e lista de emails autorizados. Não usa um JWT recebido do navegador como fonte de confiança. Sessões expiram após 15 minutos de inatividade ou oito horas de duração máxima, ficam em memória e são invalidadas ao reiniciar. Remover um email autorizado revoga seu acesso na próxima requisição.

## Notificações Gmail

Ative verificação em duas etapas e gere uma **senha de app**, se permitida pela sua conta ou administrador Workspace. Algumas contas/políticas não permitem esse mecanismo; nesse caso esta versão requer adaptação para Gmail OAuth/relay.

```ini
GMAIL_USER=seu-email@gmail.com
GMAIL_APP_PASSWORD=senha-de-app-sem-espacos
```

Não use a senha normal da conta. Em **Configurações**, escolha destinatário e nível mínimo. Reinicie após modificar segredos, use **Testar email** e confira o resultado na tela e auditoria. O teste entra numa fila e não confirma envio no clique. O serviço exige STARTTLS com validação do certificado em `smtp.gmail.com:587`. Limites da conta Google continuam aplicáveis.

Fila limitada a 64 emails, processamento sequencial, timeout de 20 segundos por envio. Falhas são registradas na auditoria, sem retry/spool durável. Se reiniciar, notificações pendentes podem ser perdidas. Dimensione o nível mínimo para evitar spam durante surtos.

## Integração com Wazuh real

No Wazuh Manager existente:

```sh
sudo install -o root -g wazuh -m 0750 integrations/custom-multipla-siem /var/ossec/integrations/custom-multipla-siem
```

Insira o trecho de `integrations/wazuh.xml` dentro de `<ossec_config>` em `/var/ossec/etc/ossec.conf`, substituindo `hook_url` e `api_key` pelo `INGEST_TOKEN`. Reinicie o manager após validar a configuração. O script usa Python 3 padrão; se o Python estiver em outro caminho, ajuste o shebang. O webhook exige HTTPS confiável, Bearer token e no máximo 64 KB por alerta.

Alertas preservam ID/regra, nível, nome do agente, `data.srcip` e `full_log`. Deduplicação em memória por uma hora; não sobrevive a restart. O limite é 10.000 IDs nessa janela. O script tenta três vezes com timeout, mas não mantém spool após falha; investigue `integrator.log` e reenvie eventos necessários. Integração Wazuh recebe alertas e notifica por Gmail; **as regras locais de bloqueio operam sobre syslog**. Para respostas a alertas Wazuh, use o active response do Wazuh ou um conector adicional validado para a sua topologia. Não habilitamos bloqueio indiscriminado por nível Wazuh.

## Regras e dados

Regras locais: regex Go/RE2, escopo por tipo, limiar de 1–1.000, janela de 1–3.600 segundos, nível 1–15 e opção de solicitar bloqueio. Configure em **Regras de detecção**. Um disparo por combinação regra/dispositivo/IP por janela reduz duplicações. Como a correlação usa o instante de recepção, um backlog entregue de uma vez pode causar alerta.

Configuração, regras, bloqueios e auditoria são persistidos. Logs são arquivos JSONL diários UTC, com retenção configurável (padrão 7 dias), rotação por data e exportação autenticada. A limpeza ocorre a cada minuto. O limite diário padrão é 256 MB; ao atingir a cota, a ingestão e as respostas automáticas falham de forma fechada e a condição aparece no painel. O painel mantém até 2.000 registros e entrega até 250 por consulta; pesquisa e gráfico cobrem essa janela em memória, e o gráfico pode subcontar em surtos acima de 2.000 registros. “Eventos recebidos hoje” conta registros originais do dia UTC, excluindo alertas locais derivados e incluindo alertas recebidos do Wazuh. O contador é recuperado do arquivo do dia no restart. Não há busca indexada de todo o histórico; exporte o dia desejado para análise.

O arquivo de logs é fechado após cada gravação, mas não há fsync por evento: falha de energia pode perder buffers recentes. Falha de gravação impede processamento e bloqueio daquele evento; verifique banner e journalctl. JSONL é texto sem criptografia em repouso; proteja disco, backups e permissões. Auditoria guarda 500 entradas e não é imutável/assinada. No restart, só o arquivo atual é reintroduzido na janela recente; correlação anterior não é recuperada.

## Operação e verificação

```sh
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o multipla-siem .
```

Testes cobrem parsing filterlog IPv4/IPv6 e SSH, limiar/cooldown/janela, proteção de IPs, modo de simulação, expiração no feed, autenticação, CSRF, OAuth state, ingestão Wazuh/deduplicação e falha de armazenamento. Isso não substitui teste no seu pfSense, Proxmox e Google.

Backup: copie `/var/lib/multipla-siem`, `/var/lib/multipla-siem/config.json` e segredos para local seguro. Para snapshot consistente de estado, pare o serviço durante a cópia. Após restore, confira IPs protegidos, origem HTTPS e credenciais. Os scripts não alteram firewall, não instalam Wazuh nem provisionam contas Google.

Recomendação inicial para homologação: 1 vCPU, 512 MB de RAM e disco conforme volume de logs; **estimativa, não benchmark**. Cada evento é escrito em disco e regexes são avaliadas sequencialmente. O limite systemd de 512 MB é proteção operacional, não garantia de capacidade. Esta versão foi desenhada para volume moderado; teste sua taxa de eventos antes de produção. Correlação: até 10.000 chaves; TCP: 32 conexões; mensagens syslog: até 16 KB. UDP não possui backpressure. Alta disponibilidade, TLS nativo de syslog, RBAC granular, busca indexada, fila durável e monitoramento de desempenho são evoluções necessárias para ambientes maiores.

## Documentação utilizada

- [Wazuh: coleta syslog](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html)
- [Wazuh: integrações customizadas](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
- [pfSense: logs remotos](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/remote.html)
- [pfSense: tipos de alias URL Table](https://docs.netgate.com/pfsense/en/latest/firewall/aliases-types.html)
- [Google: OAuth/OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [Gmail: SMTP com TLS](https://support.google.com/mail/answer/7104828)
- [Go: ferramentas de build](https://go.dev/cmd/go/)





## Novidades 1.1

Análise local adaptativa, correlação de autenticação e indicadores de falhas críticas, sem GPU nem envio de logs à nuvem. Backups exportáveis e restauráveis, preferências por conta, agendamento diário e Google Drive com consentimento separado. Consulte [Backups e análise local](BACKUP-DRIVE.md).

A ISO 1.2 inicia HTTPS automaticamente. Use o código exclusivo exibido no console para cadastrar uma conta local pelo navegador. Google SSO pode ser configurado depois no painel; consulte INSTALLATION-ISO.md.

## Integrações 1.2

UniFi/CEF com classificação de alertas, traps SNMPv2c/SNMPv3 authPriv e webhooks de entrada e saída. A página Syslog, SNMP e webhook separa as configurações. Consulte [Guia dos receptores](UNIFI-SNMP-WEBHOOK.md). A distribuição inclui GoSNMP v1.45.0 e seu código em vendor para compilação offline; a ISO usa binário pronto.

Atualizacao de versoes e publicacao assinada: consulte [UPDATES.md](UPDATES.md). A ISO 1.2.1 inclui SSH e tenta atualizacoes Debian sem exigir conectividade para concluir a base local.
