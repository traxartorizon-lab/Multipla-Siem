# Multipla Siem 1.2.24

## 1.2.24

Corrige alocação excessiva ao reconstruir a janela dos eventos na inicialização e durante a coleta. O histórico continua sendo lido para recuperar os totais do dia, mas a janela de 2.000 eventos avança sem copiar todos os registros a cada linha. Preserva os eventos mais recentes, contagem diária e último horário por dispositivo. Testes de recuperação e benchmark adicionados.

Mantém todas as funcionalidades da 1.2.23, a verificação TLS, as assinaturas de atualização e a restauração automática se o painel não ficar disponível.

Consulta focada pelo botão Ver eventos das notificações e do popup de invasão. Pausa a atualização ao vivo e mantém paginação: eventos do mesmo tipo no dispositivo nas 24h até o gatilho; para o alerta global, falhas de senha do mesmo IP nos 60s do gatilho, entre dispositivos. Metadados compactos persistidos nas notificações novas; notificações antigas resolvidas pelo histórico quando disponível. Registro removido pela retenção ou consulta parcial é informado sem redirecionar ao fluxo ao vivo.
