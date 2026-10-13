# Multipla Siem 1.2.27

## 1.2.27

Diagnóstico automático do Ollama com até 180 segundos de geração e cliente HTTP de 185 segundos, corrigindo cancelamentos aos 90 segundos em modelos executados na CPU. Espera pela vaga de inferência separada, até 20 segundos; mantém apenas uma inferência por vez e a fila limitada. Modelo ocupado não é tratado como serviço indisponível.

Geração usa até quatro threads, conforme CPUs disponíveis. Contexto mantido em 3072 tokens e teto de 600 tokens de saída; prompt solicita JSON conciso, até três verificações e três sugestões. Não altera o modelo selecionado, não instala pesos e não executa ações sugeridas.

Configurações mostra a última falha de geração, mesmo quando o modelo instalado é reconhecido. A indicação é limpa após uma geração bem-sucedida ou mudança de modelo. Erros HTTP são identificados sem exibir o corpo bruto da resposta. Diagnóstico imediato pela base local permanece disponível.

Testes cobrem início do prazo após espera, opções de CPU/contexto, cancelamento, liberação da vaga, isolamento do cliente HTTP e indicação de erro HTTP.

