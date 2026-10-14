# Multipla Siem 1.2.34

## 1.2.34

Aplicativo Windows com bandeja, notificações por vínculo exclusivo de sete dias, DPAPI, escolha de saída de áudio e login Google em navegador externo. O servidor usa OAuth existente, prova PKCE, consentimento com código de comparação e confirmação de identidade; autorização de cinco minutos e uso único, sem copiar cookies do Chrome ou tokens Google. Corrige mensagens para distinguir painel conectado de notificações não vinculadas/servidor antigo.

Relatórios com logo e cabeçalho Multipla SIEM, título destacado, resumo em cartões, tabelas de alto contraste e marca d’água discreta para impressão legível.

Grupos Somente alertas, Administrativo e Superadmin com autorização no servidor. Contas legadas preservam acesso até atribuição explícita. Atualização assinada em Configurações exclusiva do Superadmin, com reautenticação local, CSRF, auditoria e unidade root fixa habilitada uma vez por administrador Linux. Sem terminal ou comandos arbitrários.

Clicar na contagem de críticos de um cliente pausa o fluxo ao vivo e consulta somente críticos daquele cliente nos últimos 30 minutos, com intervalo fixo e paginação. Retomar encerra o foco.

Testes locais: autenticação Google existente, consentimento/PKCE/uso único, revogação de vínculo, grupos e proteção de contas, filtro crítico antes da paginação e política polkit restrita. App compilado e autotestado no Windows. Nenhuma operação de update/reboot foi executada em produção. Pacote Windows portátil sem assinatura Authenticode; requer WebView2 Evergreen. Isolamento multiempresa, MFA e demais recomendações da avaliação continuam pendentes.

