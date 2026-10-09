# Multipla Siem 1.2.22

## 1.2.22

Cards da dashboard redimensionados continuamente pelas bordas e pelo canto inferior, com dimensões proporcionais à área e altura mínima que preserva o conteúdo. Preferências anteriores compatíveis; visualização móvel empilhada.

Central de notificações prioriza a lista, com saúde da VM em coluna compacta à direita e processos recolhidos. Em telas menores, notificações aparecem primeiro.

Reconhecimento dos registros SSH RFC5424 do pfSense; atividade SSH suspeita classificada como crítica. Captura dos IPs de origem de Attack from, sshguard Blocking e Invalid user, inclusive no histórico, IPv4/IPv6 e sem substituir pelo IP do remetente. Card de IPs conta origens únicas nas últimas 24h e permite consulta/download; consultas parciais são identificadas.

Críticos manuais e automáticos encaminhados à interpretação do Ollama, com evidência original e indicação distinta de diagnóstico por regras. Pergunte à IA usa contexto reduzido, até quatro threads, espera por vaga de até 20s e inferência de até 180s. Erros identificam modelo, conexão, HTTP e truncamento. Respostas são hipóteses para revisão.

Limpeza única dos modelos substituídos qwen3:0.6b e qwen3:4b após resposta validada do qwen3:4b-instruct, somente enquanto este permanece selecionado. Mantém modelos personalizados e registra remoções na auditoria. Não instala modelos automaticamente.

