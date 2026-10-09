# Multipla Siem 1.2.21

- Painel Pergunte à IA com Ollama local, contexto estruturado da página, seleção do modelo visível e conversa temporária.
- Busca de logs e relatórios por cliente, palavra/IP e período: filtros revisáveis antes da execução, paginação e exportação JSON/PDF via impressão.
- Ditado pt-BR no navegador com consentimento, transcrição editável, duração máxima de 30 segundos e envio manual. A disponibilidade depende do navegador; o provedor pode receber o áudio. O SIEM não armazena áudio.
- Histórico persistente de CPU, RAM e disco da VM nas últimas 24h, com médias de 15 minutos e lacunas sem coleta. Gráfico no popup e na central de notificações.
- Capacidade total e espaço disponível do filesystem do SIEM em GiB; notificação de pouco espaço (até 10% disponível ou até 1 GiB), sem repetição, e recuperação acima de 12% e 1,25 GiB.

O assistente usa somente consultas autenticadas e limitadas, com CSRF, validação de filtros, redação de segredos e loopback fixo para o Ollama. Não aceita SQL, ferramentas, URLs externas ou comandos do modelo. Respostas são hipóteses para revisão. Nenhuma alteração é executada.

Consultas cobrem até 31 dias dentro da retenção, com limite de leitura de 64 MiB/10 segundos. Buscas mostram 100 registros por página, até offset 10.000; relatórios consultam até 10.000 registros e identificam resultados parciais. A IA recebe uma amostra explícita de até 12 registros; totais são calculados pelo SIEM. Tela/PDF mostram até 100 registros, e JSON preserva os registros consultados. Arquivos ausentes podem representar ausência de coleta ou retenção expirada, nunca confirmação de segurança.

Ollama é opcional e externo à atualização. Se falhar, o relatório factual continua disponível. A qualidade e o tempo de respostas precisam ser conferidos com o modelo instalado no servidor. Histórico da VM começa após instalar a versão; não há preenchimento retroativo.
