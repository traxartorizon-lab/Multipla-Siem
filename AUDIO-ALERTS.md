# Controle de áudio

A severidade crítica de uma notificação não autoriza áudio por si só. Avisos
operacionais, incluindo capacidade da coleta, permanecem visíveis e silenciosos.
Eventos comuns dependem de regra individual de som atualmente habilitada.
Invasão SSH e isolamento direto têm políticas explícitas separadas.

Desativar alerta sonoro ou Parar som desabilita o áudio neste navegador/app e
interrompe os players atuais, inclusive sirene contínua. Novas sincronizações
não reativam o áudio. Notificações, leitura e regras individuais são preservadas.
Habilitar ou testar é uma ação explícita; o teste pode reabilitar a reprodução.

O app recebe autorização de som calculada pelo servidor a cada consulta. Áudio
comum toca por até quatro segundos somente para novas notificações autorizadas;
consultas repetidas de pendências não o reproduzem novamente. Isolamento direto
autêntico pode manter sirene até a leitura, sempre sujeito ao controle geral.

A correção exige atualizar servidor e app Windows; versões antigas do app não
interpretam os novos campos de autorização de som. A preferência é local ao
navegador/app, não um controle global de todos os computadores da conta.
