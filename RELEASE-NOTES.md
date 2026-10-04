Multipla Siem 1.2.1 corrige a partida automatica apos uma falha inicial de rede. O servidor passa a chamar o primeiro boot em sua propria sequencia de partida e tenta novamente quando necessario.

A ISO instala SSH e configura os repositorios Debian oficiais sem depender do CD-ROM removido. Atualizacoes Debian sao tentadas durante a instalacao; sem conectividade, a base local permanece utilizavel. O instalador prepara o diretorio temporario necessario para validar o SSH. Os menus preservam a identidade Multipla Siem sem o texto instalacao offline.

O atualizador manual multipla-update usa manifests assinados Ed25519, verifica arquitetura, versao, tamanho e SHA256, guarda copia do executavel/configuracao/estado e restaura a versao anterior se a partida ou o login HTTPS falhar. A chave privada permanece fora do GitHub. O canal atualiza o executavel e a interface nele embutida; nao instala migracoes arbitrarias de sistema.

Este release disponibiliza executaveis Linux amd64/arm64 e seus manifests/assinaturas. Instalacao nova pela ISO inclui o atualizador preconfigurado. Instalacoes anteriores precisam do pacote 1.2.1 para receber os novos arquivos de servico e o atualizador.
