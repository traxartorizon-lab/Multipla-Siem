Multipla Siem 1.2.2 corrige a inicialização automática, incluindo recuperação quando a rede demora a ficar disponível. O código exclusivo de cadastro do primeiro boot corresponde à credencial carregada pelo systemd, permitindo o primeiro acesso sem configuração manual adicional.

A ISO inclui SSH na porta 22 e configura repositórios Debian oficiais HTTPS. Tenta atualizações durante a instalação e continua com os pacotes locais quando não há internet. A validação do SSH ocorre dentro do ambiente de instalação correto. Os menus mantêm o fundo escurecido e removem o texto instalação offline.

O comando multipla-update verifica assinaturas Ed25519, arquitetura, versão, tamanho e SHA256 do servidor e do próprio atualizador. Guarda cópias dos executáveis, configuração e estado; verifica a página real de acesso em HTTPS e restaura os arquivos anteriores se a partida falhar. A chave privada permanece fora do GitHub.

Esta release contém executáveis amd64/arm64 e manifests assinados. A ISO nova inclui o canal pré-configurado. Instalações antigas precisam do pacote completo para receber também as correções dos serviços e do instalador.
