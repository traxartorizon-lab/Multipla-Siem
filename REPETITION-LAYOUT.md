# Repetições e disposição manual

## Recebimentos repetidos

Um recebimento é uma entrada original aceita por syslog/CEF/SNMP, Wazuh ou webhook. Alertas derivados pelo analisador e pelas regras não incrementam novamente esse contador. Telemetria de recursos usa seu armazenamento limitado próprio, não o journal de eventos; auditoria, avisos internos de capacidade e isolamento direto não são suprimidos por esta regra.

A identidade usa cliente, dispositivo, IP remetente, IP de origem, formato, protocolo, detector, regra, nível e mensagem. Só o timestamp do cabeçalho syslog e o PID textual de processo são removidos. Portas, IPs, códigos de erro e demais valores continuam diferentes; isto favorece evitar fusões indevidas em vez de agrupar toda variação possível. O formato de timestamp/PID não reconhecido permanece literal.

O dia é UTC, como nos arquivos de eventos. Os primeiros19 recebimentos são anexados ao journal global. A20ª entrada ativa o grupo e sua janela contém os20 recebimentos. Daí em diante, cada novo recebimento substitui o mais antigo da janela; não é anexado ao journal nem à lista global ao vivo. As primeiras19 entradas já arquivadas não são apagadas ou reescritas: relatórios/exportações globais continuam apresentando o histórico global efetivamente guardado; exportar o grupo produz somente sua janela de até20 e pode repetir esses registros iniciais. A consulta global normal oculta o grupo ativo. A virada do dia reinicia a contagem/janela quando chega novo recebimento; sem repetição nova, o grupo automático do dia anterior deixa de ser exibido.

O botão compacto **Dispositivos com problema**, em **Eventos e alertas**, abre a lista sob demanda. Não há painel de problemas na visão geral. A janela permite ver/exportar os últimos20, consultar contadores/timestamps e voltar a exibir. Voltar a exibir suspende esse agrupamento automático até o fim do dia UTC. Ocultação manual por dias/permanente continua ativa; selecionar uma derivação usa seu recebimento pai quando disponível.

Limites:256 identidades mantidas no total,64 por cliente,20 recebimentos em memória por identidade. No disco são21 slots fixos por identidade (20 comprometidos e1 de preparação), mais metadados. A gravação do novo slot antecede o commit atômico dos metadados; reiniciar não revela um slot não comprometido. Só o novo recebimento e os metadados são escritos, não as20 mensagens antigas. O contador monotônico de slots não reinicia na mudança do dia.

Expiração segue `RetentionDays`, na manutenção e no startup. Ao esgotar a cota de grupos ou falhar sua persistência, o recebimento volta ao journal global, com aviso independente de capacidade. Logo, não há promessa de espaço fixo total do sistema: notificações, auditoria, fila de entrega, arquivos globais anteriores e fallback continuam sujeitos aos próprios limites. Corrupção de metadados/slots comprometidos impede iniciar com um contador aparentemente válido porém incompleto.

Detecção, notificações, encaminhamentos e isolamento continuam sendo avaliados. Alertas derivados preservam seus canais de segurança e não ocupam os20 slots de recebimentos. A janela não substitui evidência de retenção imutável externa.

Ensaio de desenvolvimento Windows:200 recebimentos de16KiB em7,19s,353.122 bytes retidos/22 arquivos para uma identidade. É medição sintética local de durabilidade/espaço, não dimensionamento de produção nem garantia de taxa sustentada; há2 commits com `fsync` por recebimento. Fazer ensaio no disco/VM alvo antes de dimensionar grandes taxas.

## Dashboard manual

PosiçõesX/Y em pixels relativos ao canvas, largura em pixels e altura são preferências da própria conta. Layouts anteriores são convertidos uma vez ao abrir; atualizar métricas não empacota, ordena ou movimenta os vizinhos. Conteúdo que cresce rola dentro do card. Em telas de até600px, a apresentação vira uma coluna legível; as coordenadas salvas do desktop são preservadas para o retorno.

Em **Organizar cards**, arrastar pelo cabeçalho oferece uma prévia livre, inclusive sobre áreas ocupadas, sem alterar a disposição persistida. Ao soltar, o card fica no local escolhido e somente conflitos são deslocados uma vez para evitar sobreposição. **Desfazer ajuste** restaura a disposição anterior quando houve deslocamento de vizinhos; para alinhamento simples restaura a geometria manual anterior ao arredondamento de 8px. O alinhamento continua opcional. Teclado e redimensionamento recusam colisões. Escape, cancelamento do ponteiro ou mudança de largura encerram a prévia sem gravá-la. Salvar persiste por conta.

**Restaurar posições originais** fica visível fora e dentro da edição. Recompõe as posições padrão sem excluir monitoramentos extras nem trocar os dispositivos selecionados. O resultado pode ser salvo ou cancelado antes de persistir.

A composição padrão usa gráfico principal largo no topo, indicadores compactos, recursos/postura alinhados e alertas abaixo. Layout anterior com colisões ou dimensões sem espaço útil é adaptado com aviso, preservando os dispositivos selecionados. Personalizações válidas são mantidas. A apresentação é projetada para a largura disponível, sem canvas horizontal; fora da edição isso não sobrescreve a preferência salva. Ao editar uma tela mais estreita, salvar confirma essa geometria; cancelar restaura a preferência anterior. Conteúdo longo mantém um corpo vertical com rolagem escura dentro do card e quebra de textos/tabelas, sem barras horizontais nem reorganização por atualização de métricas.

Fixture visual local com dados fictícios: `work/manual-dashboard-fixture/`, servida em loopback por HTTP, usa os mesmos arquivos dashboard.js/style.css. Seu localStorage é exclusivamente da fixture. Testes visuais no navegador não equivalem a testes na produção.


## Entrada syslog e limites de transporte

A leitura UDP agora é separada da ingestão/disco por uma fila fixa de256 mensagens de até16KiB (até4MiB de payload),64 posições por origem. Uma lista de remetentes cadastrados é publicada atomicamente quando a configuração muda e consultada antes da fila; o worker revalida o cadastro antes de ingerir. Não existe goroutine por datagrama. O limite de16KiB/truncamento já existia na ingestão anterior; mensagens maiores não representam evidência bruta completa.

Fila cheia e excesso de32 conexões TCP geram contagem/aviso em canal independente, com cardinalidade fixa e limite de mensagens no journal. Linux também solicita SO_RXQ_OVFL para observar perda no buffer UDP do kernel; se o recurso não estiver disponível, o journal declara a limitação. A contagem do kernel é cumulativa e não identifica o remetente culpado; não se atribui o descarte ao IP do datagrama subsequente. A manutenção incorpora os descartes ao contador do SIEM. Isto mitiga o bloqueio direto de ReadFrom pelo fsync, não transforma UDP em transporte confiável e não garante ausência de perdas sob saturação. Encerrar o processo pode deixar entradas voláteis da fila sem coleta; para evidência com confirmação, preferir TCP/TLS.

O menuM usa as áreas existentes. Contas fica disponível ao Superadmin e ao Administrativo global com grant de contas; nenhum grant transforma um Administrativo em Superadmin. Manutenção, reboot, update e terminal local exigem Superadmin no servidor. Terminal de equipamentos com grant continua separado. Nenhum reboot/update real é necessário para testar a navegação.
