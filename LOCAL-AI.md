# Diagnósticos por regras e IA sob demanda



A análise local sempre roda no SIEM: padrões, estatística adaptativa e base de conhecimento produzem diagnóstico de eventos críticos. Ela não pode ser desligada pelo cadastro de configuração ou por importação. Diagnósticos são hipóteses verificáveis e não executam comandos. Logs sem causa conhecida recebem orientação de investigação, sem afirmar uma correção desconhecida.



A geração de texto por modelo usa Ollama somente em http://127.0.0.1:11434. O SIEM não instala Ollama nem baixa pesos automaticamente. Após atualizar para 1.2.5, confira no Debian:



```sh

command -v ollama

free -h

curl --max-time 3 http://127.0.0.1:11434/api/tags

```



Se Ollama não estiver instalado, siga https://docs.ollama.com/linux. A instalação padrão oficial permite:



```sh

curl -fsSL https://ollama.com/install.sh -o /root/multipla-ollama-install.sh

sh /root/multipla-ollama-install.sh

install -d -m 0755 /etc/systemd/system/ollama.service.d

cat > /etc/systemd/system/ollama.service.d/multipla-local.conf <<'EOF'

[Service]

Environment="OLLAMA_HOST=127.0.0.1:11434"

Environment="OLLAMA_NO_CLOUD=1"

Environment="OLLAMA_NUM_PARALLEL=1"

Environment="OLLAMA_MAX_LOADED_MODELS=1"

EOF

systemctl daemon-reload

systemctl enable --now ollama

systemctl restart ollama

ollama pull qwen3:0.6b

```



O modelo padrão qwen3:0.6b tem download de aproximadamente 523 MB (https://ollama.com/library/qwen3:0.6b); o consumo em execução é maior e depende do contexto. Confira RAM livre e disco antes de instalar. Modelos pequenos podem errar diagnósticos; um modelo local maior pode ser selecionado em Configurações > Diagnósticos e IA local se a capacidade do servidor permitir. Não abra a porta 11434 para a rede. A conexão local não exige alterar Google SSO ou Drive.



O SIEM verifica apenas a disponibilidade dos modelos a cada 30 segundos. Receber, classificar ou revisar logs não gera texto nem cria fila de inferência. Use Pergunte à IA no rodapé do evento: a janela inclui somente o log escolhido, limitado e com indicação de truncamento. A geração começa apenas em Enviar, com uma inferência por vez. Perguntas e respostas do assistente são temporárias; interpretações antigas e avaliações já persistidas são preservadas. A base local continua funcionando sem Ollama.



O modelo recebe logs com a redação de segredos aplicada pelo SIEM. O log é dado não confiável, não uma instrução; o modelo não recebe ferramentas. A saída é texto para revisão, não é executada e não determina bloqueios. Respostas inválidas são descartadas. Modelos cloud e entradas remotas anunciadas pelo Ollama são recusados; o modo OLLAMA_NO_CLOUD=1 protege também o serviço Ollama.



O backup completo recupera a seleção de modelo, os diagnósticos e as avaliações. Ollama e seus pesos são dependências externas e não estão incluídos no backup do SIEM; reinstale-os no servidor de recuperação. A base local funciona mesmo sem essa reinstalação. O SIEM não preserva um histórico ilimitado de inferências ou acompanhamentos.



Referências da base: https://cdn.kernel.org/doc/html/latest/admin-guide/sysctl/vm.html, https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Operations/Troubleshooting.html e https://docs.netgate.com/pfsense/en/latest/troubleshooting/authentication.html. Referência da API: https://docs.ollama.com/api/chat e https://docs.ollama.com/faq.





## Pesquisa externa

A pesquisa automática complementar está desativada no modo sob demanda. Pergunte à IA usa somente o contexto fornecido ao modelo local; não navega na internet nem executa ferramentas. Configurações e credenciais anteriores são preservadas para compatibilidade, sem consulta automática.

## VM com 8 GiB / 4 CPUs

Para testar um modelo maior, execute `ollama pull qwen3:4b` no Debian e selecione qwen3:4b em Configurações → Diagnósticos e IA local → Salvar modelo. Mantenha o 0.6b como alternativa. A qualidade e o tempo devem ser comparados com dados reais; memória/CPU variam com contexto e carga. As inferências do SIEM são serializadas, contexto de 3.072 tokens, geração até 600 tokens e prazo de 180 segundos. O qwen3:4b não é baixado ou selecionado automaticamente.

Consultas DHCP e relatórios temporários usam somente o Ollama local, sem pesquisa externa. A captura e os comandos não são controlados pelo modelo. Em muitos servidores, a interpretação usa uma amostra explícita de até quatro registros; a lista completa permanece na tela/relatório. A IA não determina autorização dos servidores DHCP e não substitui revisão técnica.


## Pergunte à IA (1.2.21)

O botão no cabeçalho abre uma conversa temporária com o modelo selecionado nas Configurações. A opção de contexto usa dados estruturados da seção atual: amostra de logs em eventos, indicadores/recursos na visão geral, resumo do relatório, inventário em dispositivos e saúde da VM em notificações. Não lê formulários, senhas, tokens, terminal ou a página inteira. Equipamentos de rede incluem uma amostra dos testes e inventário; regras, respostas e auditoria incluem resumos limitados. Configurações, integrações e backups incluem somente indicadores selecionados, sem credenciais. Desmarque a opção para perguntar sem contexto.

Pedidos de busca e relatório produzem filtros para confirmação, com cliente, trecho literal, data/hora local e somente críticos. O servidor valida cliente e período; consultas usam as mesmas permissões de leitura do histórico. A IA não recebe ferramentas nem acesso ao banco/terminal. O modelo recebe os dois últimos pares de conversa, limitados; ao fechar/limpar, a conversa é descartada. Conteúdo redigido, saídas exibidas por textContent. Filtros desconhecidos ou respostas malformadas são recusados.

O JSON conserva registros consultados; o PDF é gerado pela opção PDF/imprimir do navegador e inclui até 100 evidências. Resultados parciais são identificados. Totais abrangem registros lidos, incluindo logs e alertas derivados como entradas distintas. IPs críticos são deduplicados por evento de origem.

Ditado usa Web Speech API quando disponível, com aviso/consentimento por sessão da página. O serviço do navegador pode enviar áudio ao provedor; não é uma transcrição local garantida. O SIEM recebe apenas texto após revisão e Enviar. O microfone para ao fechar, trocar de aba ou atingir 30 segundos. Sem suporte/permissão, a entrada por texto continua funcionando. Documentação: https://developer.mozilla.org/en-US/docs/Web/API/SpeechRecognition.

Inferências são serializadas com as demais análises, com prazo de 180 segundos, contexto de 8.192 tokens e geração até 1.200 tokens. Duas solicitações de interpretação podem aguardar; excesso recebe resposta de ocupado. Nenhuma pergunta/resposta do painel é persistida pelo SIEM, embora Ollama/provedor do navegador possam ter seus próprios registros. Modelos existentes não são substituídos automaticamente.


## Ajustes 1.2.22

Selecione o modelo local qwen3:4b-instruct instalado e teste Pergunte à IA. A disponibilidade em /api/tags não comprova que uma resposta foi concluída. A interface informa o modelo e as falhas; a interpretação do log não executa ações.

O assistente aguarda vaga por até 20 segundos e gera por até 180 segundos, com contexto 4096 e até quatro threads. A análise automática continua limitada a 180 segundos. Reduzir o contexto visível e o histórico evita sobrecarga; dados omitidos são indicados como contexto parcial.

Após uma resposta validada pelo assistente ou diagnóstico usando qwen3:4b-instruct, o SIEM remove uma única vez os modelos antigos qwen3:0.6b e qwen3:4b via API local do Ollama. A limpeza preserva o selecionado e qualquer outro modelo, registra auditoria e não apaga diretórios diretamente. Para voltar a usar os antigos, baixe-os novamente com ollama pull. Camadas compartilhadas podem reduzir o espaço efetivamente liberado.


## 1.2.27

Diagnóstico automático do Ollama com até 180 segundos de geração e cliente HTTP de 185 segundos, corrigindo cancelamentos aos 90 segundos em modelos executados na CPU. Espera pela vaga de inferência separada, até 20 segundos; mantém apenas uma inferência por vez e a fila limitada. Modelo ocupado não é tratado como serviço indisponível.

Geração usa até quatro threads, conforme CPUs disponíveis. Contexto mantido em 3072 tokens e teto de 600 tokens de saída; prompt solicita JSON conciso, até três verificações e três sugestões. Não altera o modelo selecionado, não instala pesos e não executa ações sugeridas.

Configurações mostra a última falha de geração, mesmo quando o modelo instalado é reconhecido. A indicação é limpa após uma geração bem-sucedida ou mudança de modelo. Erros HTTP são identificados sem exibir o corpo bruto da resposta. Diagnóstico imediato pela base local permanece disponível.

Testes cobrem início do prazo após espera, opções de CPU/contexto, cancelamento, liberação da vaga, isolamento do cliente HTTP e indicação de erro HTTP.



## 1.2.28

Ollama exclusivamente sob demanda para eventos. Remove a fila de diagnósticos generativos, o enfileiramento na ingestão/classificação/revisão e o reprocessamento periódico do histórico. A verificação de disponibilidade consulta apenas os modelos instalados, sem carregar ou gerar texto. Mantém coleta, regras, correlação, notificações e diagnóstico imediato da base local; interpretações antigas são preservadas.

Rodapé de cada evento oferece Pergunte à IA. Abre o assistente com uma pergunta sugerida e somente o log escolhido como contexto, com limite e indicação de truncamento. Abrir a janela não inicia inferência: é preciso clicar Enviar. Permite perguntar novamente sobre o evento e desmarcar a inclusão do contexto. O assistente geral continua disponível. Conversas são temporárias e não executam ações.

Configurações informa o modo sob demanda, sem indicadores de uma fila automática inexistente. Pesquisa externa automática fica indisponível neste modo. Consultas e relatórios solicitados pelo usuário continuam usando suas interpretações explícitas. Apenas uma inferência por vez, mantendo limites de CPU, contexto, prazo e permissões.

Validação inclui ingestão de crítico sem chamada ao Ollama, análise local preservada, contexto limitado ao evento escolhido, sintaxe JavaScript, testes gerais e revisão visual.

