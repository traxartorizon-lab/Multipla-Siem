# Multipla Siem 1.2.14

Corrige a expansão do terminal SSH: a grade do xterm passa a acompanhar largura/altura do painel, mudança de fonte, recolhimento e redimensionamento da janela. Linhas e colunas são sincronizadas com o PTY remoto via SSH window-change. O PTY inicial também usa as mesmas 28 linhas da grade inicial.

O ajuste envia somente dimensões numéricas validadas (20–400 colunas, 6–200 linhas), com autenticação, vínculo à conta da sessão, CSRF e limite de tempo. Não envia comandos ou novas credenciais. Observadores são removidos ao encerrar o terminal. A política CSP, a confirmação da identidade e a autenticação SSH permanecem ativas.

Validação: testes Go e vet, limites e isolamento do endpoint de resize, cálculo de dimensões, expansão/recolhimento/fonte no xterm real em navegador com CSP. Prévia com fonte de 14 px: 104 para 140 colunas ao expandir; 20 px: 98 colunas expandido e 72 recolhido no viewport de teste. Reflow visual confirmado. A validação no pfSense real ocorre após atualizar; quebras explícitas de linha emitidas pelo equipamento são preservadas.

Consultas DHCP guiadas passam a salvar evidências automaticamente no servidor assim que a captura termina, antes da interpretação do Ollama, mantendo a retenção original de 72 horas. A conclusão atualiza a mesma entrada; falhas de gravação são informadas na tela. Capturas executadas livremente no terminal não são importadas. A gravação independe de manter o navegador aberto e não armazena senhas ou pacotes brutos.

Realce técnico opcional da saída ASCII sem formatação nativa: IPs em ciano, MACs em magenta e protocolos ARP/DHCP em verde. As cores não classificam ameaças ou autorização. Saída com sequências ANSI/controle mantém seus bytes originais; sequências divididas entre leituras e estilos nativos ativos são preservados; o realce volta somente em texto ASCII neutro. Não há HTML de origem remota ou alteração dos comandos enviados.



Dashboard compacta: gráfico em rosca com logs originais por dispositivo nas últimas 24 horas, leitura do histórico com cache de um minuto e indicação de dados parciais. Atividade recente mantém os últimos 30 minutos. Alertas resumidos têm área de rolagem interna limitada e detalhes expansíveis; expansão e posição de leitura são mantidas nas atualizações. Cards continuam móveis por conta.

Dispositivos: tipo PC Windows, cliente/unidade, MAC e destino Wake-on-LAN. Ação manual administrativa UDP 9 sem confirmação fictícia de boot. Consultas limitadas de DNS reverso, vizinhança local, portas TCP selecionadas e compartilhamentos SMB anônimos (SMB2/3); sem senha, shell ou destino arbitrário. Utilitários opcionais: nmap, smbclient e iproute2.

Reinício desta VM exclusivo de administrador, confirmação digitada, CSRF e auditoria. Continua sem root/sudo; política restrita login1 exige habilitação explícita como root após atualizar: multipla-siem -enable-server-reboot. Requer polkit instalado. Não reinicia outras máquinas.

Coletor Windows: métricas atuais de CPU, memória, discos e bytes/s de rede, envio HTTPS a cada minuto, validação TLS e sem redirects. Chave individual revogável e somente para ingestão daquele PC; servidor armazena hash, PC usa DPAPI e ACL restrita. Tarefa LocalService sem privilégios administrativos, sem portas de entrada, execução remota ou alteração de antivírus. Arquivo PowerShell legível, sem bypass/obfuscação. Download autenticado pelo card; instalação exige administrador. A assinatura Ed25519 da versão não é assinatura Authenticode do script.

Validação: testes Go/vet e casos de privilégio, TLS obrigatório, isolamento de chaves, revogação, retenção, janela do gráfico e validação de MAC/percentuais. Sintaxe PowerShell validada sem instalar o coletor nesta estação. UI integrada conferida com dados fictícios. O coletor ainda exige teste piloto em Windows com a política Bitdefender da organização; compatibilidade universal e ausência de falhas não são garantidas. CPU/memória/IO de outras plataformas via SNMP não fazem parte deste coletor Windows; não há série histórica longa de métricas nesta versão.

Nomes de novos backups no Drive passam a usar a versão do arquivo VERSION, com indicação config/full. Documentos JSON e saída -version usam a mesma origem. Backups existentes não são renomeados; schema de restauração permanece compatível. Ajuda de Gmail ampliada em Configurações.


Coletor Linux: selecione Linux no cadastro e baixe o instalador no card do dispositivo. Execute `sudo bash ./linux-collector-install.sh`; informe HTTPS, IP cadastrado e chave individual. Requer Python 3.8+ e systemd 247+ (Debian 12/13, Ubuntu 22.04/24.04; outras distribuições precisam de validação). A coleta roda como usuário dinâmico restrito, sem portas de entrada, com credenciais temporárias do systemd, TLS validado e redirecionamentos bloqueados. CPU/memória/rede via /proc e discos locais de sistemas de arquivos suportados. Revogue a chave no SIEM; `sudo bash ./linux-collector-install.sh --uninstall` desativa o timer e preserva arquivos para revisão. Validar a primeira instalação em uma máquina piloto.

1.2.15: corrige disponibilização do JavaScript de dashboard, dispositivos, métricas e reinício. Verifica todos os scripts e estilos referenciados na página por meio das rotas HTTP reais. Disposição anterior preservada; use Organizar cards > Restaurar padrão > Salvar disposição para aplicar o arranjo novo.

1.2.16: corrige versão interna do atualizador e adiciona teste que exige igualdade com VERSION do produto. Inclui correções de dashboard e confirmação de reboot da 1.2.15.

1.2.17: atalhos explícitos Cadastrar Windows e Cadastrar Linux em Equipamentos de rede, abrindo formulário canônico de Dispositivos com tipo e filtros de cliente/unidade preenchidos, com acesso à chave e download do coletor. Sem cadastro duplicado ou credenciais SSH.
