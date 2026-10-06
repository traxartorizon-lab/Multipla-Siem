# 1.2.6 — 2026-10-05

- O atualizador e o rollback aguardam até dois minutos pela disponibilidade HTTPS do painel, consultando a cada dois segundos. A validação do certificado e a restauração automática permanecem obrigatórias.
- Dashboard em cards por assunto, reorganizáveis por arraste ou setas. A disposição é salva por conta no servidor, inclusive para visualização, e integra os backups. Há cancelamento e restauração do padrão.
- Relatórios históricos por período UTC de até 31 dias, dispositivo, origem (incluindo pfSense e Proxmox), tipo (logs/alertas), nível e IP de origem IPv4/IPv6.
- Atalho para relatório de segurança com críticos pfSense/Proxmox, resumo por dispositivo/nível e IPs de origem dos críticos. Logs sem origem identificável são indicados; não se usa o endereço do remetente como substituto.
- Exportação do relatório JSON, CSV dos registros exibidos e PDF pelo diálogo de impressão do navegador (Salvar como PDF), com filtros, resumo e tabelas.

- Atualizador espera a disponibilidade HTTPS por até 120 segundos e preserva rollback automático.
- Dashboard organizado por assunto, com cards móveis e preferência por conta.
- Relatórios por período, equipamento, severidade e IP de origem; JSON, CSV e impressão para salvar em PDF.
- Equipamentos por cliente/unidade; ping rápido, contínuo, traceroute e scans TCP com Nmap.
- Terminais SSH internos para pfSense/Proxmox, validação de identificação do servidor e credenciais solicitadas a cada conexão, sem armazenamento.
- Botões de diagnóstico com comando editável, execução explícita e balões informativos.
- Pesquisa complementar opcional para o Ollama local, com fontes. Requer BRAVE_SEARCH_API_KEY; consultas contêm somente termos técnicos constantes reconhecidos.
- Marcação manual de eventos críticos, destaque vermelho e preservação do log original.
- pfSense: extração ampliada de origem SSH/sshguard; regra dedicada com 5 eventos Invalid user/Failed password for invalid user do mesmo IP em 60 segundos. Simulação/publicação e redes protegidas continuam respeitadas.
- Eventos das últimas 24 horas em disco, paginação de 100 registros e pausa da atualização visual, sem parar a coleta.
- Cadastro de rede incluído em backup JSON; recuperação completa preserva o estado do SIEM.

A consulta percorre o histórico retido, limitado a 64 MiB e 20 segundos por execução, com duas consultas simultâneas. Resultados parciais e arquivos ausentes são indicados. Totais abrangem os registros lidos; detalhes/CSV/PDF incluem até 1.000 registros. Logs e alertas derivados são contados separadamente.

Na primeira transição de um atualizador 1.2.5 ou anterior, a espera antiga ainda é executada pelo processo já instalado. Em servidores cuja partida ultrapasse oito segundos, a espera temporária do systemd pode ser necessária mais uma vez para instalar o novo atualizador. A partir do atualizador 1.2.6, não será necessária nas atualizações seguintes.
