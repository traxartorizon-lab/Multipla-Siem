# Multipla Siem 1.2.25

## 1.2.25

Dispositivos Proxmox oferecem o coletor Linux e as instruções corretas, mantendo a classificação e as regras específicas de Proxmox. Instalador Linux distribuído com quebras de linha compatíveis com Bash.

Guia Dispositivos com cards compactos: nome, presença e resumo de CPU/memória; identificação, monitoramento, rede e gerenciamento em Ver mais. Cadastro e acesso avançado recolhidos, acionados pelos botões + add dispositivo e avançado no topo. A edição abre o cadastro automaticamente. Os painéis mantêm o estado durante a atualização e continuam restritos a administradores.

Botão Baixar coletor abre uma janela com downloads Windows e Linux/Proxmox, seleção do dispositivo, geração da chave individual e instruções de instalação, ativação, verificação e diagnóstico. Chaves não são colocadas em comandos e são apagadas da janela ao fechá-la.

Configurações → Manutenção do servidor oferece terminal integrado para o próprio SIEM via SSH em 127.0.0.1:22. Exige usuário Linux explícito, identificação do host confirmada e credencial aceita pelo SSH; não altera a autenticação do sistema. Credenciais não são persistidas. Reutiliza terminal interativo, isolamento por conta, limite global de quatro sessões e prazos existentes. Suporta chave OpenSSH e sua frase-senha; .ppk deve ser exportada pelo PuTTYgen.

Validação: autenticação SSH por chave e canal interativo em servidor de teste, restrições de usuário/destino/permissão, testes gerais, Go vet, sintaxe JavaScript e revisão visual em desktop e celular.

