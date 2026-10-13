# Multipla Siem 1.2.26

## 1.2.26

Download de IPs críticos disponível também quando a consulta de histórico é parcial. O botão fica acima da lista, exporta exatamente os IPs exibidos e não repete a leitura do histórico. TXT com um IP por linha, sem cabeçalho, contagens ou nomes de dispositivos; preserva IPv4 e IPv6.

Consulta incompleta identificada no aviso, no botão e no nome ips-eventos-criticos-parcial.txt. A exportação não se apresenta como uma lista completa do período. URLs temporárias liberadas ao mudar o período ou fechar a janela. Limites de leitura do histórico e permissões de acesso preservados.

Corrige a política de reinício para permitir também a variante com outras sessões SSH abertas. Mantém bloqueadores de reinício e não autoriza desligamento, suspensão ou gerenciamento de serviços. Reinstale a política após atualizar, inclusive se já executou o comando anteriormente.

Reinício após migração: a política do sistema não faz parte do backup do SIEM. No VPS, instale polkitd e execute sudo /usr/local/bin/multipla-siem -enable-server-reboot para habilitar somente a operação de reinício da conta de serviço. Nenhuma permissão de shell ou sudo é concedida ao SIEM.

