# Revisão de segurança — Multipla Siem 0.2.0

Revisão realizada em 3/4 de outubro de 2026. Escopo: código Go, endpoints HTTP, sessões, integração Google, armazenamento, coleta de logs, feed pfSense, serviço systemd e montagem da ISO. A revisão procurou caminhos para acesso sem autorização e exposição de credenciais. Não foi um pentest da infraestrutura do usuário.

## Proteções implementadas e verificadas

- Rotas privadas exigem sessão. Login Google usa authorization code, PKCE e state de uso único, consulta oficial de identidade, email verificado e lista explícita de emails autorizados. Remover um email revoga seu acesso na próxima requisição. Testes do fluxo usam servidor simulado, sem conta Google real.
- Sessões aleatórias em memória; cookies HttpOnly, Secure e prefixo __Host em HTTPS, expiração absoluta de oito horas e inatividade de quinze minutos. Cookies duplicados são rejeitados e login revoga a sessão anterior. Polling não prolonga a sessão.
- Token inicial forte, prazo de quinze minutos e consumo persistido entre reinícios. Tokens de login, ingestão e firewall são independentes. A imagem não contém tokens pré-gerados nem senha padrão.
- Mutação de API exige origem exata e CSRF; JSON exige tipo correto. Host inesperado e acesso sem TLS são rejeitados na produção. Cabeçalhos de proxy só são aceitos na topologia local configurada; HTTPS nativo não confia neles. Limites reduzem tentativas de login e abuso das APIs.
- Segredos root:root 0600, entregues ao usuário de serviço por systemd LoadCredential. Não aparecem no JSON do painel. Redação dos segredos conhecidos e padrões de credenciais antes da gravação e exportação, incluindo leitura de logs antigos. Essa redação é uma proteção auxiliar, não reconhece todos os possíveis formatos.
- Clientes HTTP das integrações não seguem redirecionamentos; SMTP exige STARTTLS com validação do certificado. Email contém resumo, sem o log bruto. Certificado local exclusivo, chave privada protegida e impressão digital no console.
- Coleta limitada a dispositivos cadastrados, revogação também em conexões TCP já abertas, tamanho e conexões limitados, regex RE2, validação dos objetos recebidos e cota diária. Falha de armazenamento impede processamento e resposta automática daquele evento.
- Feed do pfSense exige token forte e IP de origem autorizado. Endereços privados, locais, dos dispositivos e redes protegidas não podem entrar na lista de bloqueio. Simulação é o padrão. Importação Wazuh não dispara bloqueio local indiscriminado.
- Serviço sem login e sem capacidades, com restrições de sistema de arquivos, privilégios e memória. Segredos privados e dados de demonstração não integram a ISO ou o pacote.

## Verificação executada

`go test -count=1 ./...`: passou. A suíte contém 31 testes e sementes de fuzz; cobre autenticação, CSRF, sessão forjada/duplicada/inativa, consumo do token após restart, rejeição de Host/proxy TLS forjado, redirecionamento com credenciais, autorização Google, exportação redigida, caminhos de arquivos, limites e proteção de IPs.

`go vet ./...`: passou. `govulncheck ./...`, usando Go 1.27.1: **No vulnerabilities found**. Isso informa ausência de vulnerabilidades conhecidas detectadas pelo scanner no código alcançável; não demonstra ausência de falhas desconhecidas.

Fuzz do tratamento de entradas: 75.124 execuções na rodada inicial e 80.175 na rodada seguinte, sem panic. O teste de syslog real em loopback confirmou recebimento UDP/TCP, alerta de SSH, ocultação dos segredos no snapshot e recusa de uma conexão TCP após remoção do dispositivo. A revisão encontrou e corrigiu a ausência inicial de redação do campo genérico token=; a correção também está coberta pelo teste de regressão. Não foi executado teste com race detector. ISO base: assinatura OpenPGP do arquivo de checksums validada com fingerprints oficiais fixados, SHA512 conferida antes da personalização; SHA256 da imagem final entregue separadamente.

Boot BIOS e UEFI e abertura do instalador gráfico: passaram em QEMU com zero placas de rede e sem discos do host. Instalação completa em disco virtual novo sem rede: Debian instalado e reiniciado, programa instalado pelo hook da ISO e assistente aberto automaticamente no console local. No sistema instalado, o pacote final foi conferido por manifest SHA256 e instalado sem downloads; o assistente completou a configuração, o serviço systemd ficou ativo e a verificação de configuração/credenciais/permissões retornou MULTIPLA_INSTALL_OK. O marcador inicial não foi capturado na saída serial do instalador; essa limitação do teste foi resolvida verificando o sistema instalado diretamente. BIOS e UEFI foram testados no boot; a instalação completa e o primeiro boot foram testados em BIOS. Secure Boot e hardware físico não foram validados. Nenhum disco físico foi formatado nos testes.

## Limites e validação antes da produção

Não foram usados pfSense, Proxmox ou credenciais Google/Gmail reais. Ainda é necessário testar envio, autenticação, confiança no certificado e aplicação/expiração da tabela no seu firewall. Um URL Table depende do refresh do pfSense e de estados existentes; publicar um IP não confirma bloqueio instantâneo.

Syslog UDP/TCP não tem autenticação criptográfica nem TLS nativo. Um atacante na rede de coleta pode forjar eventos/IP de origem, especialmente UDP; restrinja a rede/ACL e use túnel autenticado quando necessário. Bloqueio automático deve começar em simulação. Root e administradores autorizados podem acessar os dados; todos os emails autorizados têm papel administrativo. Não há RBAC granular nem MFA própria; configure MFA e políticas de acesso na conta Google.

Logs e backups não têm criptografia em repouso aplicada pela aplicação; use disco criptografado se necessário. Auditoria tem retenção limitada e não é imutável. Fila de email e deduplicação não são duráveis, não há alta disponibilidade e a correlação recente é limitada em memória. O certificado gerado pelo assistente requer conferência e confiança explícita. Google SSO/Gmail não funcionam sem internet.

Nenhum caminho de acesso sem autorização ou vazamento de segredos foi encontrado nos cenários testados após as correções. Esse resultado não garante uma plataforma sem vulnerabilidades; reavalie após mudanças e valide a implantação real.




## Marcação da versão 1.0

A entrega revisada como 0.2.0 foi marcada como 1.0 a pedido do usuário em 2026-10-03. A alteração é de identificação e documentação. Os binários foram recompilados e a ISO e o pacote foram regenerados com novos checksums. Os resultados de instalação completa acima correspondem à implementação anterior a essa alteração de identificação.


## Validação da versão 1.1 — 4 de outubro de 2026

Cinquenta testes Go passaram e go vet não apontou problemas. govulncheck consultou a base oficial e não encontrou vulnerabilidades conhecidas no código/dependências. Os novos testes cobrem isolamento de backups por conta, rejeição de arquivos inválidos e caminhos perigosos, preservação de segredos e endereços na restauração, falha de gravação, agendamento com fuso e persistência, autenticação/CSRF das rotas, criptografia autenticada dos tokens Drive, rejeição de metadados de outra conta e mudança de identidade Google. O fluxo Drive foi testado com respostas simuladas; não foi autorizado numa conta Google real.

Os backups excluem credenciais e tokens. Restaurar pausa agendamento e publicação de bloqueios. O Drive usa drive.file, PKCE e consentimento separado; tokens locais usam AES-256-GCM com chave root exclusiva da instalação. A análise local possui limites de memória e não aciona o firewall. Esta revisão não garante ausência de falhas e não substitui homologação na rede de destino.

A instalação offline completa foi validada na versão 1.0. A versão 1.1 reutiliza o instalador e atualiza o payload e o contraste dos menus; a inicialização BIOS/UEFI e a integridade do payload são verificadas novamente. Nenhuma senha padrão, sessão ou credencial Google é distribuída na ISO.

A verificação dinâmica do executável 1.1 confirmou coleta TCP/UDP, correlação de SSH, redação de credenciais e revogação de origem. Também passou a sequência autenticada de exportação, criação, listagem e importação de backup pela API HTTP local. Nenhuma conta Google real foi usada.

## 1.1.1 — cadastro e primeiro boot

Passaram 53 testes Go, go vet e a validação sintática dos três scripts JavaScript. Os novos testes verificam cadastro protegido por sessão e CSRF, revogação da sessão inicial após cadastro, login local persistente após reinício, rejeição de senha incorreta, ausência de senha/hash nos backups e criptografia/redação das credenciais OAuth configuradas pelo painel.

A rotina automática de primeiro boot foi executada como root dentro do Debian instalado na VM de teste, offline, com um endereço de interface virtual. Foram verificados HTTPS em 8443, serviço systemd ativo, configuração e permissões, certificado exclusivo e aviso de cadastro no console. Essa verificação reaproveitou o Debian previamente instalado; não representa uma nova instalação completa desta ISO. A imagem foi remontada e o payload comparado ao projeto entregue.

O código inicial exige posse do console, é aleatório e de uso único. Na instalação automática vale até 24 horas de execução enquanto a conta local não existe; reinícios não reabilitam um código já consumido. Nenhuma senha padrão ou credencial é embutida na mídia. O login local usa PBKDF2-HMAC-SHA256 com 600.000 iterações e no máximo duas verificações simultâneas, além dos limites existentes de autenticação. O cadastro exige senha de pelo menos 14 caracteres. O administrador pode configurar OAuth pelo painel; as credenciais são cifradas com a chave exclusiva da instalação, excluídas de snapshots/backups e redigidas dos logs quando reconhecidas. Google SSO real depende do projeto OAuth e domínio do usuário e não foi testado com uma conta Google real.

## Versão 1.2 — protocolos e notificações

68 testes Go passaram, incluindo CEF estruturado, classificação UniFi sem bloqueio, community/IP SNMPv2c, traps SNMPv3 authPriv, recepção UDP, rejeição de tamper, downgrade, engine boots/time antigos e replay após reinício. Também foram verificadas as novas rotas privadas/CSRF, token/IP de webhook de entrada, assinatura HMAC e payload mínimo, rejeição de URLs inseguras e resultados DNS mistos, redirecionamentos, exclusão de segredos nos GET/backups e ausência de notificação após falha de armazenamento. go vet e a sintaxe JavaScript passaram. Fuzzing executou 468.000 entradas nos parsers CEF/SNMP sem falhas. govulncheck consultou a base oficial e não encontrou vulnerabilidades conhecidas; a dependência GoSNMP v1.45.0 está fixada e vendorizada.

SNMPv2c e syslog continuam dependentes da segurança da rede, conforme explicado no guia. SNMPv3 aceita somente SHA-256/AES-128 authPriv e possui controles de identidade, tempo e repetição; esses controles não provam que um equipamento autorizado não esteja comprometido. Traps não produzem respostas, e novos protocolos/CEF/webhook não publicam bloqueios no pfSense. O receptor limita origem, taxa, tamanho de pacote, variáveis e estado. Credenciais novas são cifradas com AES-GCM usando a chave exclusiva já instalada e namespaces separados; não são retornadas em consultas ou backups.

Webhook de saída exige HTTPS, valida certificados, recusa proxy automático e redirecionamentos, confere todos os endereços DNS retornados e conecta ao IP conferido. IPs privados exigem autorização explícita por endereço; localhost, link-local, metadados e faixas reservadas são recusados. Notificações enviam resumo sem log bruto e assinatura HMAC. A fila é limitada e não persistente. Testes usam tráfego local e respostas simuladas, sem credenciais Google reais ou equipamentos físicos. A análise não é uma garantia de ausência de falhas nem um pentest da rede do usuário.


## Validação da versão 1.2.2

70 testes Go e go vet passaram. A instalação Debian completa foi exercitada sem placa de rede em QEMU; o fluxo de instalação corrigido foi concluído. No sistema instalado, o payload 1.2.2 foi validado com SSH ativo, fontes APT oficiais, HTTPS com certificado local validado e recuperação automática após atraso de rede. O código de primeiro acesso foi aceito e permitiu consultar a API autenticada, confirmando a correspondência da credencial systemd. Não foram realizados testes com credenciais Google reais ou equipamentos físicos UniFi/pfSense. A verificação de partida do atualizador não substitui a validação funcional após atualização.


## 1.2.3

Referrer-Policy same-origin preserva a origem de formularios locais, sem enviar Referer a sites externos. Verificacao estrita de Origin e CSRF mantida. Teste de regressao cobre origem correta, ausente, null e externa no cadastro e login. Cadastro por navegador exercitado em demonstracao local; persistencia de conta e senha correta/incorreta cobertas por testes Go. Erros de login exibidos como texto na propria tela, sem HTML injetado.
