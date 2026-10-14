# Multipla SIEM 1.2.36

## 1.2.36

Cadastro MFA com QR code gerado localmente, compatível com TOTP SHA-1, seis dígitos e período de 30 segundos. Nenhuma chave é enviada a geradores externos de QR. A chave manual continua disponível como alternativa.

Recarregar o cadastro preserva a chave e o prazo da sessão. Sessões simultâneas não sobrescrevem a configuração pendente umas das outras. O QR exige a sessão do primeiro fator, não é armazenado em cache e deixa de ser acessível após ativação ou expiração. Mensagens de expiração e retorno ao login ficaram mais claras.

Após atualizar, abra um novo login, no Authy adicione a conta escaneando o QR exibido e confirme o código atual. Contas com MFA já ativado mantêm o fator existente. Não é preciso substituir o autenticador dessas contas.

Nome, ícone e versão continuam padronizados no aplicativo e nos pacotes. Testes cobrem estabilidade ao recarregar, isolamento entre sessões, bloqueio de QR sem sessão/cross-site/expirado, ativação, replay e formato do URI; um decodificador independente também confere um QR fictício. Demais controles e pendências operacionais permanecem descritos em SECURITY-RUNBOOK.md, incluindo armazenamento externo imutável adiado.

