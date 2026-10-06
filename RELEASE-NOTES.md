# Multipla Siem 1.2.13

Consulta guiada de servidores DHCP por cliente/unidade/pfSense: autenticação SSH por conexão, identidade do servidor confirmada antes da senha, escolha da interface e captura passiva de 15 a 120 segundos. Cards mostram Server-ID/IP observado, origem Ethernet, MAC, possível fabricante OUI local, rede oferecida e quantidade de respostas. O operador decide quais servidores são autorizados; a IA não executa comandos nem aplica bloqueios.

Relatórios temporários: adicione resultados de DHCP, ping, traceroute e testes de portas; interpretação pelo Ollama local quando disponível, retenção de 72 horas desde o teste e limpeza automática a cada minuto, inclusive ao iniciar o serviço. Exportação PDF pela impressão do navegador. Relatórios pertencem à conta administrativa que os adicionou. Senhas, chaves SSH, pacotes brutos e saída arbitrária do terminal não são armazenados nos relatórios.

Captura limitada a 1.000 pacotes, 2 MiB, duas consultas simultâneas e interface validada. Interrupção fecha a conexão da consulta; watchdog remoto limita a captura. Inferências locais são serializadas, com contexto e prazo limitados, preservando resultados quando o modelo estiver indisponível. Não há pesquisa externa nestas consultas.

Pré-requisitos: acesso SSH e permissão tcpdump no pfSense; interface Ethernet IPv4 correta. Nmap instalado no SIEM fornece a base OUI local. Modelo escolhido em Configurações; qwen3:4b deve ser baixado no servidor antes da seleção. O serviço não baixa modelos automaticamente.

Validação: testes Go, vet, testes de captura por SSH com servidor sintético, retenção/isolamento de contas/remoção de dados expirados, rejeição de injeção e fuzz do parser; fluxo visual e inclusão no relatório conferidos em navegador com CSP e dados fictícios. A consulta em seu pfSense e o desempenho real do qwen3:4b dependem de validação após atualização.

A retenção remove entradas do armazenamento ativo; PDFs exportados e cópias existentes de backups completos preservam seus próprios arquivos.
