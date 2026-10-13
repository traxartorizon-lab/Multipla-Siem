# Multipla Siem 1.2.30

## 1.2.30

Instalador Linux/Proxmox assistido: verifica systemd 247+, Python 3.8+ e certificados CA; instala apenas dependências ausentes via APT em Debian/Ubuntu/Proxmox. Mostra etapas, valida sintaxe e unidades systemd, envia a primeira coleta pelo serviço restrito e confirma aceitação HTTP pelo SIEM antes de habilitar o timer. Faz até três tentativas; falha não é apresentada como sucesso e preserva arquivos para revisão.

Modos --verify para testar envio e agendamento e --repair para reconstruir código, unidades e permissões mantendo configuração e chave. Reparo recusa links simbólicos e arquivos de outro proprietário. Não muda o firewall, políticas Tailscale, chave ou verificação TLS. Diagnósticos seguros distinguem chave recusada, certificado inválido e falha de conexão, sem registrar tokens.

Instruções de download atualizadas. CI valida sintaxe Bash e simula instalação aceita, falha nas três tentativas sem ativação do timer e reparo de instalação existente. Validação do coletor e testes gerais executados; execução real em systemd/hardware do usuário ocorre no teste inicial do instalador.

