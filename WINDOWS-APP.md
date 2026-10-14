# Aplicativo Windows, grupos e atualização restrita

Código do app em `desktop/`, C#/.NET 10 e WinForms/WebView2. Execução como usuário normal, sem serviço Windows ou credenciais root/SSH. A janela usa a interface HTTPS existente e fechar mantém o app na bandeja; Sair encerra o recebimento. O computador precisa estar ligado, acordado e conectado à tailnet.

## Grupos

Em Configurações → Contas de acesso, o Superadmin atribui:

* **Somente alertas:** consulta alertas, notificações e marca leitura. Não consulta logs comuns, configurações, exportações, terminal ou credenciais.
* **Administrativo:** administra a operação (dispositivos, regras, respostas e coleta). Contas, identidade Google, backup/restore, terminal, reinício e atualização são exclusivos do Superadmin. Alterar configuração não permite modificar a lista de contas autorizadas.
* **Superadmin:** administração completa. A conta administrativa principal é protegida contra alteração pelo cadastro de contas.

Contas antigas conservam as permissões anteriores até receberem um grupo explicitamente. Isso não implementa isolamento multiempresa; os grupos continuam no ambiente compartilhado. Não adicionar clientes externos enquanto o isolamento por tenant estiver pendente.

## Vincular e usar

1. No painel atualizado, abra Central de notificações → Aplicativo Windows. Gere uma chave com o nome do computador. Ela aparece por 60 segundos e vence em sete dias.
2. Execute `Multipla.Siem.exe` e abra Servidor, vínculo e áudio. Informe a origem HTTPS (por exemplo, `https://siemserver.tail4ac2e7.ts.net:8443`) e a chave.
3. Escolha a saída de áudio nativa e habilite o som se desejar. A sirene permanece enquanto houver notificações críticas pendentes; marque as notificações como lidas pelo app ou painel. Uma saída ausente não provoca troca silenciosa para outro dispositivo.
4. O menu da bandeja permite abrir painel/notificações, configurar início com Windows e sair. Início automático é opcional e por usuário.

O vínculo permite exclusivamente receber os resumos de notificações e marcar leitura da própria conta. Não permite usar APIs de administração nem criar uma sessão web. Só o hash fica no servidor; a chave no Windows é protegida por DPAPI CurrentUser. Mudança de grupo, credenciais/identidade, desativação, remoção da conta, expiração ou revogação invalida o vínculo. Desvincular localmente apaga a chave; use Revogar no painel para invalidá-la no servidor.

O login do painel é separado. O botão Entrar com Google abre o navegador padrão, usando o OAuth do servidor com PKCE. Compare o código exibido no app e no navegador, confirme o consentimento e depois a identidade no app. Uma prova PKCE é enviada por POST ao WebView2; o servidor cria ali uma sessão HttpOnly de uso normal. A solicitação vence em cinco minutos e é consumida uma única vez. Não há callback HTTP local, protocolo personalizado, cópia de cookies do Chrome ou envio de tokens Google ao app. O vínculo de notificações continua separado.

O app recusa HTTP, certificados inválidos, navegação fora da origem e APIs nativas expostas ao conteúdo web. Não ignora certificados. Downloads da própria origem pedem destino ao usuário e não são executados. A sessão web usa perfil separado por execução; a exclusão é tentada ao sair, mas arquivos podem permanecer após falha/encerramento abrupto até os cookies expirarem. A chave de notificações nunca é passada ao WebView2. O áudio da página é silenciado para evitar duplicação; alertas do app usam a saída nativa selecionada. Notificações visuais dependem das permissões e do modo de concentração do Windows.

## Botão multipla-update — habilitação única no servidor

Depois de instalar a versão que contém esta funcionalidade, execute uma única vez como administrador Linux:

```sh
sudo /usr/local/bin/multipla-siem -enable-app-update
```

Isso instala unidade root e política polkit restrita. O serviço SIEM continua sem privilégios e só pode iniciar `multipla-app-update.service`, que executa o atualizador fixo `/usr/local/bin/multipla-update`. Não concede sudo ou controle de outras unidades. A chave pública e o repositório em `/etc/multipla-siem/update.json`, os executáveis e os arquivos da política/unidade devem permanecer de propriedade root e não graváveis por `multipla-siem`.

Em Configurações → Atualização do servidor: Consultar estado → Executar multipla-update. Exige Superadmin, sessão válida, HTTPS, CSRF, senha local da própria conta e confirmação `ATUALIZAR`. Conta somente Google não pode usar esse botão até existir step-up compatível com sua identidade; não há fallback automático. A reautenticação por senha não é MFA. Existe limite de tentativas, bloqueio de concorrência e intervalo entre solicitações. A solicitação precisa ser persistida em auditoria antes de iniciar.

O atualizador preserva a validação Ed25519, hashes/tamanhos, restrição de origem, backup, verificação de saúde e tentativa de retorno à versão anterior. A atualização acontece em unidade independente e sobrevive à parada do SIEM. Consulte o estado após reconectar; `success` com `ExecMainStatus=0` significa que o processo terminou sem erro, inclusive quando não existe versão mais recente. A auditoria registra a solicitação; o resultado detalhado fica no journal root:

```sh
sudo journalctl -u multipla-app-update.service --no-pager -n 80
```

Não atualizar automaticamente em cada abertura do app. O botão atualiza o SIEM no servidor, não o Windows nem o app. Desabilitar a funcionalidade consiste em remover a política polkit e a unidade root, depois executar `systemctl daemon-reload` como root.

## Construção e verificação

```powershell
dotnet restore desktop/Multipla.Siem.Desktop.csproj --locked-mode
dotnet build desktop/Multipla.Siem.Desktop.csproj -c Release --no-restore
dotnet publish desktop/Multipla.Siem.Desktop.csproj -c Release -r win-x64 --self-contained true -o desktop-package
desktop-package/Multipla.Siem.exe --self-test
```

Dependências fixadas e lockfile; fontes NuGet restritas ao registro oficial. Auditoria de vulnerabilidades de todos os pacotes com NU1901–NU1904 tratados como erro. O pacote gerado ainda requer WebView2 Evergreen Runtime instalado. O app portátil local não recebe assinatura Authenticode nesta etapa; não é uma release publicada. A assinatura Windows depende de certificado de assinatura de código próprio, distinto da chave SSH e da chave Ed25519 de release do servidor.

Validação local não substitui ensaio em Debian/systemd/polkit e na estação do usuário. Testar atualização em máquina de homologação antes de habilitar em produção; nenhum update/reboot foi executado no servidor real durante o desenvolvimento.
