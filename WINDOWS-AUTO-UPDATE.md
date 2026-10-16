# Atualização do aplicativo Windows por usuário

Esta primeira versão com lançador precisa ser instalada uma vez. Preserve o
executável e os arquivos do pacote original; os atalhos e a inicialização com
Windows apontam para esse lançador estável. A versão vem de VERSION.

O menu nativo da bandeja **Atualizar aplicativo Windows** verifica o canal
estável e informa versão instalada e nova. A checagem automática inicia com
atraso aleatório, ocorre a cada seis horas e usa recuo em falhas. A checagem
manual respeita intervalo mínimo de um minuto. Não requer função de manutenção
no SIEM. **Aplicar atualizações**, no menu M do painel, continua sendo atualização
do servidor e exclusiva de superadmin.

O download fica em segundo plano como `package.download`. Antes da confirmação
nativa não há extração nem execução do aplicativo novo. O usuário decide quando
reiniciar; configurações, vínculo DPAPI e sessão não são enviados ao GitHub.

## Verificação e limites

- Repositório fixo `traxartorizon-lab/Multipla-Siem`, HTTPS normal e até quatro
  redirecionamentos restritos a GitHub e seus hosts de assets. Sem token GitHub,
  credencial SIEM ou URL fornecida pela página do painel.
- Manifesto Windows schema 1 e assinatura Ed25519 existentes; chave pública
  fixada no aplicativo. BouncyCastle.Cryptography 2.7.0 gerenciado, dependência
  travada por hash, auditada no restore e com licenças no pacote.
- Versão estrita, produto, arquitetura PE x64, conjunto exato de arquivos,
  SHA-256 e tamanhos. ZIP com no máximo 192 MiB de download, 512 MiB expandidos,
  1.024 arquivos assinados, manifesto de 256 KiB. Pré-verificação do diretório
  central recusa ZIP64, excesso de entradas e estruturas inconsistentes antes
  de materializar o arquivo ZIP. Recusa links, junctions, travessia e duplicatas.
- Cache por usuário em `%LocalAppData%/Multipla/SIEM/updates`, até 1 GiB,
  protegida por ACL do usuário e SYSTEM. Mantém versões ativa e anterior.
  Staging interrompido de nome semver.pending é recuperável. Limpeza nunca
  recebe destino pela linha de comando e recusa árvores com reparse points.

## Aplicação e recuperação

Após confirmação, o arquivo é revalidado, extraído para `<versão>.pending` e
promovido por rename local. O estado de seleção e tickets fica em DPAPI
CurrentUser com entropia exclusiva de atualização, gravação atômica e lock.
O ticket tem finalidade, versão, valor aleatório, validade de dois minutos e
uso único. Argumentos de execução são flags fixas, sem caminhos ou credenciais.

O health check, somente após consentimento, valida novamente o payload e a
disponibilidade do WebView2 em processo limitado a 15 segundos; não abre sessão
SIEM nem executa controles do servidor. Falha antes da ativação preserva a
versão ativa. O handoff espera o mutex da instância anterior por até 30 segundos;
a versão nova confirma inicialização quando sua janela é exibida.

Se o novo processo falhar antes dessa confirmação, o rollback é feito **na
próxima abertura do lançador**; não há supervisor permanente nem promessa de
reversão imediata após crash. A versão anterior só é selecionada pelo rollback
da transação autenticada. Um lançador instalado manualmente mais novo prevalece
sobre cache antigo. A versão mais alta conhecida impede downgrade de download.

Cada abertura verifica assinatura, árvore exata e hashes; handles de leitura e
diretório são mantidos até iniciar o processo para impedir sobrescrita/rename
dos arquivos validados. Isso não transforma a conta Windows comprometida em
um ambiente confiável.

Se a seleção DPAPI estiver corrompida, somente a cópia base oferece confirmação
para guardar `selection.invalid.backup` e recriar o estado de atualizações.
Preferências e credenciais permanecem intactas. A cópia do cache não aceita
reset próprio e orienta abrir o lançador original. Links ou permissões inválidas
continuam falhando de forma fechada.

Não existe certificado Authenticode contratado: o mecanismo não remove nem
contorna SmartScreen. Assinatura Ed25519 do pacote e reputação do publicador
Windows são controles diferentes.

## Testes

`scripts/run-update-self-test.ps1 -Application <exe> -Repository <repo>` usa
TEMP próprio, DPAPI exclusivo e rede/processos falsos. Não lê preferências reais,
não executa payload sintético e não grava recibos dentro do pacote publicado.
A suíte independente deve também exercitar ZIP hostil, corrupção, staging,
ticket/replay, health, mutex/handoff, rollback e consentimento da interface.
