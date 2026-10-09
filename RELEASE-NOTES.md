# Multipla Siem 1.2.23

## 1.2.23

Dashboard com arraste pelo cabeçalho e encaixe automático dos cards, preservando redimensionamento pelas bordas, preferências da conta e visualização móvel. Conteúdo mantém altura mínima e quebra de texto.

Gráfico de atividade lê os registros mais recentes primeiro, evitando que o limite de leitura do histórico consuma a consulta antes de chegar aos logs atuais.

Prévia dos IPs críticos no card e no popup, com download separado. Períodos rápidos usam o relógio do servidor. Versão exibida no painel acompanha a versão instalada.

Alerta global POSSIVEL TENTATIVA DE INVASAO após dez falhas de senha SSH do mesmo IP em menos de um minuto, inclusive entre dispositivos. Não conta novamente o registro Invalid user correspondente. Popup vermelho com sirene mediante habilitação de áudio no navegador, consulta aos eventos e controles para silenciar/fechar. Intervalo de um minuto entre avisos por IP; não aplica bloqueio automático.
