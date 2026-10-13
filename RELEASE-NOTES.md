# Multipla Siem 1.2.28

## 1.2.28

Ollama exclusivamente sob demanda para eventos. Remove a fila de diagnósticos generativos, o enfileiramento na ingestão/classificação/revisão e o reprocessamento periódico do histórico. A verificação de disponibilidade consulta apenas os modelos instalados, sem carregar ou gerar texto. Mantém coleta, regras, correlação, notificações e diagnóstico imediato da base local; interpretações antigas são preservadas.

Rodapé de cada evento oferece Pergunte à IA. Abre o assistente com uma pergunta sugerida e somente o log escolhido como contexto, com limite e indicação de truncamento. Abrir a janela não inicia inferência: é preciso clicar Enviar. Permite perguntar novamente sobre o evento e desmarcar a inclusão do contexto. O assistente geral continua disponível. Conversas são temporárias e não executam ações.

Configurações informa o modo sob demanda, sem indicadores de uma fila automática inexistente. Pesquisa externa automática fica indisponível neste modo. Consultas e relatórios solicitados pelo usuário continuam usando suas interpretações explícitas. Apenas uma inferência por vez, mantendo limites de CPU, contexto, prazo e permissões.

Validação inclui ingestão de crítico sem chamada ao Ollama, análise local preservada, contexto limitado ao evento escolhido, sintaxe JavaScript, testes gerais e revisão visual.

