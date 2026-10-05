# Multipla Siem 1.2.5 — instalação e atualização

O instalador inclui SSH e instala primeiro os pacotes locais. Depois tenta atualizar o Debian pelos repositórios oficiais HTTPS, validando as assinaturas APT. Sem conectividade, continua com os pacotes da ISO. Falhas ficam em /var/log/multipla-install-updates.log. Não há download de nova versão do SIEM durante a instalação: o SIEM incluído é o desta imagem.

SSH é habilitado em TCP 22. Use o usuário normal e a senha escolhidos no instalador; login root remoto e senhas vazias são recusados. Não existe senha padrão. O painel é HTTPS 8443. Sem IPv4 válido, o primeiro boot tenta novamente automaticamente; é necessário configurar a rede no instalador.

## Publicar versões no GitHub

O repositório público confirmado é https://github.com/traxartorizon-lab/Multipla-Siem. A origem e a chave pública já são instaladas automaticamente; as versões assinadas são publicadas em GitHub Releases. A chave privada desta distribuição foi gerada e permanece fora dos arquivos entregues. Preserve-a para assinar versões futuras; não gere outra chave para o mesmo canal sem planejar a troca de confiança nos servidores.

No computador responsável pelas releases, a ferramenta permite gerar uma chave para um NOVO canal (não substitui a chave já fixada nesta ISO):

```powershell
.\dist\release-sign-windows-amd64.exe keygen C:\CAMINHO-PRIVADO\multipla-signing.key
```

Substitua CAMINHO-PRIVADO por uma pasta privada existente fora do projeto. Guarde a chave privada e uma cópia segura: não envie ao GitHub, não inclua na ISO, nem compartilhe no chat. A ferramenta mostra apenas a chave pública, que deve ser configurada nos servidores por canal confiável. No Windows, limite as permissões da pasta ao seu usuário.

Para cada arquitetura, assine o executável da versão desejada, por exemplo:

```powershell
.\dist\release-sign-windows-amd64.exe sign C:\CAMINHO-PRIVADO\multipla-signing.key 1.2.5 amd64 .\dist\multipla-siem-linux-amd64 .\release .\dist\multipla-update-linux-amd64
```

Crie uma GitHub Release com tag v1.2.5 e anexe multipla-siem-linux-amd64, multipla-update-linux-amd64, manifest-amd64.json e manifest-amd64.sig. Repita para arm64 se necessário. Marque a release estável como Latest. As versões futuras usam o mesmo formato e a mesma chave. A chave pública não deve ser obtida de um download não autenticado durante a atualização.

## Configurar uma vez no servidor

Como root, crie /etc/multipla-siem/update.json:

```json
{"repository":"traxartorizon-lab/Multipla-Siem","public_key":"sAMAsxkPlps6yyq2RHPRWpXfqDeCzA6n/58Z28ShzvI="}
```

Proteja o arquivo com chmod 600. Na ISO 1.2.5 essa configuração já vem instalada. Basta executar:

```sh
su -
multipla-update
```

O atualizador recusa assinatura inválida, arquitetura diferente, versão antiga e hash/tamanho incorretos. Baixa somente via HTTPS e aceita redirecionamentos para os domínios de distribuição GitHub previstos. Nunca executa scripts baixados. A troca é atômica, exige root e usa bloqueio para impedir atualizações simultâneas.

Antes da troca, para o serviço e guarda o executável, config.json e state.json em /var/backups/multipla-siem. Reinicia, verifica se o serviço permanece ativo e se o login responde em HTTPS com o certificado local validado; em caso de falha restaura os arquivos anteriores. Esse teste de partida não valida todas as funções do painel. Logs, certificados e credenciais permanecem no servidor. As cópias locais podem conter dados privados e devem permanecer protegidas; não são os backups exportáveis do painel.

Este canal atualiza o servidor, a interface nele embutida e o próprio atualizador. Mudanças futuras em dependências do sistema, serviços ou instalador precisam de uma migração própria ou atualização pelo pacote/ISO. O script não instala essas mudanças silenciosamente. Não há agendamento de atualização: a execução é manual.


## Backup e rollback de atualização — 1.2.5

Antes de substituir a aplicação, o serviço é parado e o atualizador salva os binários, config.json e state.json em /var/backups/multipla-siem/update-ID. Contas, regras e preferências estão incluídas. Os backups novos incluem hashes SHA-256; snapshots privados completos da 1.2.3 também podem ser restaurados. Se o backup não puder ser concluído, a atualização é cancelada.

Como root:

```sh
multipla-update
multipla-update list-backups
multipla-update rollback
multipla-update rollback update-AAAAMMDDTHHMMSS.NNNNNNNNNZ
```

Em instalações anteriores cujo wrapper ainda não encaminha argumentos, use o comando direto (ele também adquire trava exclusiva):

```sh
/usr/local/lib/multipla-siem/updater list-backups
/usr/local/lib/multipla-siem/updater rollback
```

O rollback seleciona o backup completo mais recente, funciona sem internet e restaura aplicação, configuração e state.json. Mantém o atualizador atual para continuar oferecendo os comandos de recuperação. Antes de restaurar, grava um checkpoint privado before-rollback-ID. Se a partida ou a verificação HTTPS falhar, tenta recuperar esse checkpoint. Os logs históricos, certificados e secrets.env não são modificados. Mudanças de configuração posteriores ao backup serão revertidas. Não é rollback do Debian nem de seus pacotes. Backups não são apagados automaticamente; monitore o espaço de /var/backups.
