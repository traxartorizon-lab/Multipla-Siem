# Multipla Siem 1.2.20

Classificação persistente por descrição: marcar/desmarcar eventos críticos, escolha de áudio e ativação/desativação posterior. Cabeçalhos syslog são ignorados; em mensagens reconhecidas de ataque SSHguard o IP pode variar. As marcações aparecem na dashboard e no histórico. Evidências originais e bloqueios existentes permanecem preservados. Até 128 descrições; alterações futuras começam na primeira marcação, além dos eventos explicitamente selecionados.

Lista de IPs de origem dos críticos para visualização e download TXT, com períodos de 1h, 6h, 24h ou 7 dias. IP do remetente não é usado como substituto do atacante. Leitura limitada a 64 MiB, 10 segundos e 10.000 eventos críticos; resultado parcial é indicado e não permite download incompleto. Eventos derivados compartilham a contagem com seu evento de origem.

Até oito cards independentes de recursos, redimensionamento em quatro larguras e altura mínima ajustável de todos os cards. Disposição, dimensões e máquina selecionada salvas por conta. Conteúdo cresce/reorganiza e os cards de recursos se empilham no celular.

Histórico de recursos e ping por máquina nas últimas 24h, até 1.440 amostras por minuto persistidas no diretório de dados. Uso médio, pico e recursos livres; disponibilidade observada ao ping, latência média ponderada/máxima e perda de pacotes. Três pacotes ICMP por minuto a partir do SIEM para máquinas cadastradas. O histórico começa após a instalação desta versão; faltas de coleta são indicadas como lacunas, não como disponibilidade. ICMP bloqueado não comprova falha do equipamento. O coletor deve fornecer métricas atuais; Proxmox com somente syslog terá dados de ping, sem CPU/RAM.

Indicador superior da VM Linux: CPU, RAM e filesystem do diretório de dados. Alerta a partir de 90%, recuperação abaixo de 85%, estado indisponível explícito. Central com visão das 20 threads de maior consumo observado, sem expor argumentos de comandos, popup e até 200 notificações recentes. Limpar reconhece os avisos pendentes apenas da conta atual e preserva o histórico. Novos avisos posteriores à limpeza permanecem pendentes.

Validação local: suíte Go, parsing de métricas Linux, regras críticas, autenticação/CSRF, persistência e isolamento de preferências/limpeza; compilação Linux amd64 e arm64. Prévia com dados ilustrativos. A coleta real da VM Debian e seus pings será conferida após a atualização.
