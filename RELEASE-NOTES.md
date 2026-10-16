# Multipla SIEM 1.2.37

## 1.2.37

Repetições equivalentes são contadas por recebimento e dia UTC: os primeiros 19
entram no fluxo global; a partir do vigésimo ficam em grupo dedicado com janela
persistida dos últimos 20, contadores e exportação. Falha de persistência ou
cota retorna ao fluxo global com sinalização. Detecção e notificações continuam.
O botão compacto Dispositivos com problema fica em Eventos e alertas; o título
da lista passa a Logs ao vivo, com contexto de filtro e pausa separado.

Cards do dashboard podem ser movidos e redimensionados por conta, sem reflow
contínuo. O alinhamento opcional ocorre uma vez ao soltar, permite desfazer
exatamente e pode ser desativado. Configurações e Contas passam ao menu M;
manutenção, reinício, atualização do servidor e terminal local ficam restritos
a superadmin, mantendo confirmações e MFA existentes.

O aplicativo Windows corrige a ponte de áudio nativo e a perda de comandos em
sequência, usa ícones oficiais e identificação com versão, e avisa sobre outra
instância já aberta. A saída nativa não pede permissão de microfone. Novos testes
isolados exercitam WebView2 e persistência DPAPI temporária sem acessar perfis
ou credenciais reais.

Esta é a primeira versão com atualização local do aplicativo por usuário:
instale-a uma vez e mantenha o lançador original. Downloads futuros ficam em
segundo plano, verificam assinatura Ed25519 e hashes, e só são extraídos e
aplicados após confirmação nativa de reinício. Health check detecta falhas antes
da ativação; crash antes da confirmação de inicialização reverte na próxima
abertura do lançador. Não há atualização de servidor por esse fluxo, serviço
privilegiado ou substituição de credenciais. Veja WINDOWS-AUTO-UPDATE.md.

O receptor UDP passa a usar fila limitada com quotas por origem cadastrada e
sinalização independente de sobrecarga. Isso não garante entrega UDP nem elimina
descarte na rede. O agrupamento limita retenção, sem prometer menor escrita por
recebimento. Limites e fallback estão em REPETITION-LAYOUT.md.

Pacotes incluem inventário das dependências NuGet e licenças de verificação
Ed25519. A preparação Authenticode está documentada, mas não há certificado de
publicador contratado: SmartScreen pode continuar exibindo avisos. Armazenamento
externo imutável permanece adiado por decisão do usuário. Não há alteração no
autenticador MFA já cadastrado.

## 1.2.36

Cadastro MFA com QR code gerado localmente, compatível com TOTP SHA-1, seis dígitos e período de 30 segundos. Nenhuma chave é enviada a geradores externos de QR. A chave manual continua disponível como alternativa.

Recarregar o cadastro preserva a chave e o prazo da sessão. Sessões simultâneas não sobrescrevem a configuração pendente umas das outras. O QR exige a sessão do primeiro fator, não é armazenado em cache e deixa de ser acessível após ativação ou expiração. Mensagens de expiração e retorno ao login ficaram mais claras.

Após atualizar, abra um novo login, no Authy adicione a conta escaneando o QR exibido e confirme o código atual. Contas com MFA já ativado mantêm o fator existente. Não é preciso substituir o autenticador dessas contas.

Nome, ícone e versão continuam padronizados no aplicativo e nos pacotes. Testes cobrem estabilidade ao recarregar, isolamento entre sessões, bloqueio de QR sem sessão/cross-site/expirado, ativação, replay e formato do URI; um decodificador independente também confere um QR fictício. Demais controles e pendências operacionais permanecem descritos em SECURITY-RUNBOOK.md, incluindo armazenamento externo imutável adiado.

